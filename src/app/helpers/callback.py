"""
Callback notification handler for QoS session events.
Sends notifications to the sink URL.
"""

import httpx
import uuid
from datetime import datetime, timezone
from app.utils.logger import get_app_logger
from app.models.schemas import EventQosStatusChanged, Data, EventQosStatus, StatusInfo, Type, Specversion, Datacontenttype, SessionId
from app.services.db import get_session_data

logger = get_app_logger()


async def send_notification_to_sink(
    session_id: str,
    qos_status: EventQosStatus,
    status_info: StatusInfo,
    x_correlator: str = None
):
    """
    Send a CloudEvent notification to the sink URL when QoS status changes.
    Gets session data from database to retrieve sink URL and other information.
    
    Args:
        session_id: The session ID that experienced the status change
        qos_status: The new QoS status (AVAILABLE or UNAVAILABLE)
        status_info: The reason for the status change (DURATION_EXPIRED, NETWORK_TERMINATED, DELETE_REQUESTED)
        x_correlator: Optional correlation ID for tracking
    """
    
    session_data = get_session_data(session_id)
    
    if not session_data:
        logger.warning(f"Session {session_id} not found in database, cannot send notification")
        return
    
    session_info = session_data.get("session")
    if not session_info:
        logger.warning(f"No session info found for session {session_id}")
        return
    
    if not session_info.sink:
        logger.info(f"No sink URL configured for session {session_id}, skipping notification")
        return
    
    sink_url = str(session_info.sink)
    
    if not x_correlator:
        x_correlator = session_data.get("x_correlator")
    
    try:
        cloud_event = EventQosStatusChanged(
            id=str(uuid.uuid4()),
            source=f"https://qod-api.example.com/sessions/{session_id}",
            type=Type.org_camaraproject_quality_on_demand_v1_qos_status_changed,
            specversion=Specversion.field_1_0,
            datacontenttype=Datacontenttype.application_json,
            time=datetime.now(timezone.utc),
            data=Data(
                sessionId=SessionId(root=session_id),
                qosStatus=qos_status,
                statusInfo=status_info
            )
        )
        
        headers = {
            "Content-Type": "application/cloudevents+json",
            "ce-id": cloud_event.id,
            "ce-source": cloud_event.source,
            "ce-type": cloud_event.type.value,
            "ce-specversion": cloud_event.specversion.value,
        }
        
        if x_correlator:
            headers["x-correlator"] = x_correlator
        
        logger.info(f"Sending QoS status notification to {sink_url} for session {session_id}")
        logger.debug(f"CloudEvent: {cloud_event.model_dump_json(indent=2)}")
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                sink_url,
                json=cloud_event.model_dump(mode="json"),
                headers=headers,
                timeout=10.0
            )
            
            if response.status_code in [200, 201, 202, 204]:
                logger.info(f"Successfully sent notification to {sink_url}")
            else:
                logger.warning(f"Notification endpoint returned status {response.status_code}: {response.text}")
                
    except httpx.RequestError as e:
        logger.error(f"Failed to send notification to {sink_url}: {str(e)}")
    except Exception as e:
        logger.error(f"Error creating/sending CloudEvent notification: {str(e)}")

