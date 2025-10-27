from app.services.db import get_session_data, update_subscription_id, in_memory_db, update_deletion_task, get_deletion_task
from app.utils.logger import get_app_logger
from app.helpers.callback import send_notification_to_sink
from app.models.schemas import EventQosStatus, StatusInfo, QosStatus
import json
import httpx
import asyncio
from datetime import datetime, timezone
from app.utils.config import ASSESSIONWITHQOS_URL
"""
Transformation Functions for CAMARA QoD API to AsSessionWithQoS/NEF API.

"""


logger = get_app_logger()


async def schedule_qos_deletion(scs_as_id, QoS_sub_id, duration, session_id):
    """
    Schedule a deletion of QoS subscription after the specified duration.
    DELETE request is sent to the AsSessionWithQoS endpoint and CAMARA QoD.
    
    Args:
        scs_as_id: The x-correlator value (used as scsAsId)
        QoS_sub_id: The QoS subscription ID to delete
        duration: Time in seconds before deletion
        session_id: The session ID to delete from database
    """
    logger.debug(f"Scheduled QoS deletion for QoS NEF ID {QoS_sub_id} (QoD session {session_id}) in {duration} seconds")
    
    # Wait for the duration asynchronously
    await asyncio.sleep(duration)
    
    # Send delete request
    delete_endpoint = f"{ASSESSIONWITHQOS_URL}/{scs_as_id}/subscriptions/{QoS_sub_id}"
    
    try:
        logger.info(f"Sending scheduled DELETE to NEF/QoS: {delete_endpoint}")
        
        headers = {}
        if scs_as_id:
            headers["x-correlator"] = scs_as_id
        
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                delete_endpoint,
                headers=headers,
                timeout=10.0
            )
        
            if response.status_code in [200, 204]:
                logger.info(f"Successfully deleted QoS subscription {QoS_sub_id}")
            else:
                logger.warning(f"QoS deletion returned status {response.status_code}: {response.text}")
            
    except Exception as e:
        logger.error(f"Error deleting QoS subscription {QoS_sub_id}: {str(e)}")
    
    # Send callback notification about status change to UNAVAILABLE due to DURATION_EXPIRED
    await send_notification_to_sink(
        session_id=session_id,
        qos_status=EventQosStatus.UNAVAILABLE,
        status_info=StatusInfo.DURATION_EXPIRED
    )
    
    # Update session status to UNAVAILABLE with expiresAt as current time
    session_data = get_session_data(session_id)
    if session_data:
        session_info = session_data.get("session")
        if session_info:
            session_info.expiresAt = datetime.now(timezone.utc)
            session_info.statusInfo = StatusInfo.DURATION_EXPIRED
    
    # Delete the session from database after duration expiry
    store = in_memory_db()
    if session_id in store:
        del store[session_id]
        logger.debug(f"Session {session_id} deleted from database after duration expiry")
    else:
        logger.warning(f"Session {session_id} not found in database during scheduled deletion")


async def post_tf_to_qos(session_id):


     #NOTE : Fix in flow descriptions to include ports if provided, first i need to check documentation of AsSessionWithQoS api flow descriptions fields


    """
    POST request: Transformation function from CAMARA payload --> AsSessionWithQoS/NEF payload

    Args:
        session_id: The CAMARA session ID to transform and send
    Returns:
        The JSON payload sent to AsSessionWithQoS
    """
   

    logger.debug(f"Sending camara_session_id {session_id} to AsSessionWithQoS")
    session_data = get_session_data(session_id)
    
    if not session_data:
        logger.error(f"Session {session_id} not found in database")
        return
    
    # Extract the actual session info from the stored data
    session_info = session_data.get("session")
    x_correlator = session_data.get("x_correlator")
    
    if not session_info:
        logger.error(f"No session info found for session {session_id}")
        return
    
    # Extract required fields
    qos_profile = session_info.qosProfile.root if session_info.qosProfile else None
    
    # Get device IP (prefer ipv4, fallback to ipv6)
    device_ip = None
    if session_info.device:
        if session_info.device.ipv4Address:
            # Get publicAddress from DeviceIpv4Addr
            device_ip = str(session_info.device.ipv4Address.root.publicAddress.root)
        elif session_info.device.ipv6Address:
            device_ip = str(session_info.device.ipv6Address.root)
    
    # Get application server IP (prefer ipv4, fallback to ipv6)
    app_server_ip = None
    if session_info.applicationServer:
        if session_info.applicationServer.ipv4Address:
            app_server_ip = str(session_info.applicationServer.ipv4Address.root)
        elif session_info.applicationServer.ipv6Address:
            app_server_ip = str(session_info.applicationServer.ipv6Address.root)
    
    # Get ports if they exist
    device_ports_str = ""
    app_server_ports_str = ""
    
    # Process device ports
    if session_info.devicePorts:
        if session_info.devicePorts.ports:
            # Single ports: convert list to comma-separated string
            ports_list = [str(p.root) for p in session_info.devicePorts.ports]
            device_ports_str = f" {','.join(ports_list)}" if len(ports_list) == 1 else f" {','.join(ports_list)}"
        elif session_info.devicePorts.ranges:
            # Port ranges
            ranges_list = [f"{r.from_.root}-{r.to.root}" for r in session_info.devicePorts.ranges]
            device_ports_str = f" {','.join(ranges_list)}"
    
    # Process application server ports
    if session_info.applicationServerPorts:
        if session_info.applicationServerPorts.ports:
            # Single ports
            ports_list = [str(p.root) for p in session_info.applicationServerPorts.ports]
            app_server_ports_str = f" {','.join(ports_list)}" if len(ports_list) == 1 else f" {','.join(ports_list)}"
        elif session_info.applicationServerPorts.ranges:
            # Port ranges
            ranges_list = [f"{r.from_.root}-{r.to.root}" for r in session_info.applicationServerPorts.ranges]
            app_server_ports_str = f" {','.join(ranges_list)}"
    
    # Get notification destination (sink)
    notification_destination = str(session_info.sink) if session_info.sink else "https://example.com/callback"
    
    # Build the flow descriptions in the correct format (without ports for now)
    flow_descriptions = []
    if device_ip and app_server_ip:
        # Format: "permit out ip from <device_ip> to <app_server_ip>"
        # Format: "permit in ip from <app_server_ip> to <device_ip>"
        flow_descriptions = [
            f"permit out ip from {device_ip} to {app_server_ip}",
            f"permit in ip from {app_server_ip} to {device_ip}"
        ]
    
    # Construct the JSON payload
    qos_payload = {
        "flowInfo": [
            {
                "flowDescriptions": flow_descriptions,
                "flowId": 1
            }
        ],
        "notificationDestination": notification_destination,
        "qosReference": qos_profile,
        "supportedFeatures": "12",
        "ueIpv4Addr": device_ip
    }

    logger.debug(f"AsSessionWithQoS Payload: {json.dumps(qos_payload, indent=2)}")

    # Send the payload to the QoS system
    qos_endpoint = f"{ASSESSIONWITHQOS_URL}/{x_correlator}/subscriptions"
    
    try:
        logger.info(f"Sending POST to AsSessionWithQoS: {qos_endpoint}")
        
        headers = {
            "Content-Type": "application/json"
        }
        if x_correlator:
            headers["x-correlator"] = x_correlator
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                qos_endpoint,
                json=qos_payload,
                headers=headers,
                timeout=10.0
            )
        
            logger.debug(f"AsSessionWithQoS Response Status: {response.status_code}")
            
            if response.status_code == 201:


                try:
                    response_data = response.json()
                    QoS_sub_id = response_data.get("link", "").split("/")[-1]
                    
                    if not QoS_sub_id:
                        QoS_sub_id = response_data.get("subscriptionId")
                    
                    if QoS_sub_id:
                        logger.debug(f"QoS Subscription ID: {QoS_sub_id}")
                        
                        # Store the subscription ID in the database
                        update_subscription_id(session_id, QoS_sub_id)
                        
                        # Get duration and schedule delete
                        duration = session_info.duration
                        logger.debug(f"Scheduling QoS deletion after {duration} seconds")
                        
                        # Create a background task to delete the subscription after duration
                        task = asyncio.create_task(
                            schedule_qos_deletion(x_correlator, QoS_sub_id, duration, session_id)
                        )
                        
                        # Store the task reference so it can be cancelled if duration is extended
                        update_deletion_task(session_id, task)
                    else:
                        logger.warning("Could not extract QoS subscription ID from response")
                        
                except Exception as e:
                    logger.error(f"Error processing QoS response for auto-deletion: {str(e)}")
            else:
                logger.warning(f"QoS system returned status {response.status_code}: {response.text}")
        
            
    except Exception as e:
        logger.error(f"Error sending QoS payload: {str(e)}")
    
    return qos_payload

async def delete_tf_to_qos(session_id):
    """
    Delete QoS subscription from NEF/AsSessionWithQoS when CAMARA session is deleted.
    
    Args:
        session_id: The session ID to delete
    """
    logger.info(f"Deleting QoS subscription for session {session_id}")
    
    # Get session data to retrieve QoS_sub_id and x_correlator
    session_data = get_session_data(session_id)
    
    if not session_data:
        logger.warning(f"Session {session_id} not found in database")
        return
    
    QoS_sub_id = session_data.get("QoS_sub_id")
    x_correlator = session_data.get("x_correlator")
    
    if not QoS_sub_id:
        logger.info(f"No QoS subscription ID found for session {session_id}, skipping external deletion")
        return
    
    if not x_correlator:
        logger.warning(f"No x-correlator found for session {session_id}, cannot delete subscription")
        return
    
    # Send delete request to external QoS system
    delete_endpoint = f"{ASSESSIONWITHQOS_URL}/{x_correlator}/subscriptions/{QoS_sub_id}"
    
    try:
        logger.info(f"Sending DELETE to NEF: {delete_endpoint}")
        
        headers = {}
        if x_correlator:
            headers["x-correlator"] = x_correlator
        
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                delete_endpoint,
                headers=headers,
                timeout=10.0
            )
        
            if response.status_code in [200, 204]:
                logger.info(f"Successfully deleted QoS subscription {QoS_sub_id} from NEF")
            else:
                logger.warning(f"QoS/NEF deletion returned status {response.status_code}: {response.text}")
                
    except Exception as e:
        logger.error(f"Error deleting QoS subscription: {str(e)}")




