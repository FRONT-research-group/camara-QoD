from app.services.db import get_session_data, update_subscription_id
import json
import httpx
import asyncio


async def schedule_qos_deletion(scs_as_id, QoS_sub_id, duration):
    """
    Schedule a deletion of QoS subscription after the specified duration
    
    Args:
        scs_as_id: The x-correlator value (used as scsAsId)
        QoS_sub_id: The QoS subscription ID to delete
        duration: Time in seconds before deletion
    """
    print(f"TF: Scheduled deletion for subscription {QoS_sub_id} in {duration} seconds")
    
    # Wait for the duration asynchronously
    await asyncio.sleep(duration)
    
    # Send delete request
    delete_endpoint = f"http://10.220.2.73:8585/3gpp-as-session-with-qos/v1/{scs_as_id}/subscriptions/{QoS_sub_id}"
    
    try:
        print(f"TF: Sending DELETE request to {delete_endpoint}")
        
        headers = {}
        if scs_as_id:
            headers["x-correlator"] = scs_as_id
        
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                delete_endpoint,
                headers=headers,
                timeout=10.0
            )
        
            print(f"TF: DELETE Response Status: {response.status_code}")
            print(f"TF: DELETE Response: {response.text}")
            
            if response.status_code in [200, 204]:
                print(f"TF: Successfully deleted QoS subscription {QoS_sub_id}")
            else:
                print(f"TF: Warning - DELETE returned status: {response.status_code}")
            
    except Exception as e:
        print(f"TF: Error deleting QoS subscription: {str(e)}")


async def post_tf_to_qos(session_id):
    print(f"TF: Notifying QoS system about session {session_id}")
    session_data = get_session_data(session_id)
    
    if not session_data:
        print(f"TF: Session {session_id} not found in database")
        return
    
    # Extract the actual session info from the stored data
    session_info = session_data.get("session")
    x_correlator = session_data.get("x_correlator")
    
    if not session_info:
        print(f"TF: No session info found for session {session_id}")
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
    
    print(f"TF: QoS Payload:\n{json.dumps(qos_payload, indent=2)}")
    print(f"TF: X-Correlator - {x_correlator}")
    
    # Send the payload to the QoS system
    qos_endpoint = f"http://10.220.2.73:8585/3gpp-as-session-with-qos/v1/{x_correlator}/subscriptions"
    
    try:
        print(f"TF: Sending QoS payload to {qos_endpoint}")
        
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
        
            print(f"TF: QoS System Response Status: {response.status_code}")
            print(f"TF: QoS System Response: {response.text}")
            
            if response.status_code == 201:
                print(f"TF: Successfully sent QoS payload to system")
                
                # Extract subscriptionId from response
                try:
                    response_data = response.json()
                    QoS_sub_id = response_data.get("link", "").split("/")[-1]
                    
                    if not QoS_sub_id:
                        # Try to get subscriptionId directly from response
                        QoS_sub_id = response_data.get("subscriptionId")
                    
                    print(f"TF: QoS Subscription ID: {QoS_sub_id}")
                    
                    # Store the subscription ID in the database
                    update_subscription_id(session_id, QoS_sub_id)
                    print(f"TF: Stored QoS subscription ID for session {session_id}")
                    
                    # Get duration and schedule delete
                    duration = session_info.duration
                    print(f"TF: Session duration: {duration} seconds")
                    print(f"TF: Scheduling deletion after {duration} seconds")
                    
                    # Create a background task to delete the subscription after duration
                    if QoS_sub_id:
                        asyncio.create_task(
                            schedule_qos_deletion(x_correlator, QoS_sub_id, duration)
                        )
                    else:
                        print(f"TF: Warning - Could not extract QoS subscription ID from response")
                        
                except Exception as e:
                    print(f"TF: Error processing response for auto-deletion: {str(e)}")
            else:
                print(f"TF: Warning - QoS system returned non-success status: {response.status_code}")
        
            
    except Exception as e:
        print(f"TF: Error sending QoS payload: {str(e)}")
    
    return qos_payload

async def delete_tf_to_qos(session_id):
    """
    Delete QoS subscription from the external system
    
    Args:
        session_id: The session ID to delete
    """
    print(f"TF: Deleting QoS subscription for session {session_id}")
    
    # Get session data to retrieve QoS_sub_id and x_correlator
    session_data = get_session_data(session_id)
    
    if not session_data:
        print(f"TF: Session {session_id} not found in database")
        return
    
    QoS_sub_id = session_data.get("QoS_sub_id")
    x_correlator = session_data.get("x_correlator")
    
    if not QoS_sub_id:
        print(f"TF: No QoS subscription ID found for session {session_id}, skipping external deletion")
        return
    
    if not x_correlator:
        print(f"TF: No x-correlator found for session {session_id}, cannot delete subscription")
        return
    
    # Send delete request to external QoS system
    delete_endpoint = f"http://10.220.2.73:8585/3gpp-as-session-with-qos/v1/{x_correlator}/subscriptions/{QoS_sub_id}"
    
    try:
        print(f"TF: Sending DELETE request to {delete_endpoint}")
        
        headers = {}
        if x_correlator:
            headers["x-correlator"] = x_correlator
        
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                delete_endpoint,
                headers=headers,
                timeout=10.0
            )
        
            print(f"TF: DELETE Response Status: {response.status_code}")
            print(f"TF: DELETE Response: {response.text}")
            
            if response.status_code in [200, 204]:
                print(f"TF: Successfully deleted QoS subscription {QoS_sub_id}")
            else:
                print(f"TF: Warning - DELETE returned status: {response.status_code}")
                
    except Exception as e:
        print(f"TF: Error deleting QoS subscription: {str(e)}")