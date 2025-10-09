from fastapi import APIRouter, HTTPException, Header, status
from fastapi.responses import JSONResponse
from typing import Optional
import uuid
from datetime import datetime, timezone
import sys
import os
from app.utils.logger import get_app_logger
from app.models.schemas import CreateSession, SessionInfo, QosStatus, SessionId, XCorrelator



logger = get_app_logger()

router = APIRouter()

# In-memory storage for sessions (in production, use a database)
sessions_store = {}


@router.post(
    "/sessions",
    response_model=SessionInfo,
    status_code=status.HTTP_201_CREATED,
    summary="Creates a new session",
    description="""
    Create QoS Session to manage latency/throughput priorities

    If the qosStatus in the API response is "AVAILABLE" and a notification callback is provided the API consumer will receive in addition to the response a
    `QOS_STATUS_CHANGED` event notification with `qosStatus` as `AVAILABLE`.

    If the `qosStatus` in the API response is `REQUESTED`, the client will receive either
    - a `QOS_STATUS_CHANGED` event notification with `qosStatus` as `AVAILABLE` after the network notifies that it has created the requested session, or
    - a `QOS_STATUS_CHANGED` event notification with `qosStatus` as `UNAVAILABLE` and `statusInfo` as `NETWORK_TERMINATED` after the network notifies that it has failed to provide the requested session.

    A `QOS_STATUS_CHANGED` event notification with `qosStatus` as `UNAVAILABLE` will also be send if the network terminates the session before the requested duration expired

    **NOTES:**
    - In case of a `QOS_STATUS_CHANGED` event with `qosStatus` as `UNAVAILABLE` and `statusInfo` as `NETWORK_TERMINATED` the resources of the QoS session are not directly released, but will get deleted automatically at earliest 360 seconds after the event.

      This behavior allows API consumers which are not receiving notification events but are polling to get the session information with the `qosStatus` `UNAVAILABLE` and `statusInfo` `NETWORK_TERMINATED`. Before a API consumer can attempt to create a new QoD session for the same device and flow period they must release the session resources with an explicit `delete` operation if not yet automatically deleted.
    - The access token may be either 2-legged or 3-legged. See "Identifying the device from the access token" for further information
      - When the API is invoked using a two-legged access token, the subject will be identified from the optional `device` object, which therefore MUST be provided.
      - When a three-legged access token is used however, this optional identifier MUST NOT be provided, as the subject will be uniquely identified from the access token.
    """
)
async def create_session(
    session_request: CreateSession,
    x_correlator: Optional[str] = Header(None, description="Correlation id for the different services")
):
    """
    Create a new QoS session
    
    Args:
        session_request: The session creation request
        x_correlator: Optional correlation ID header
        
    Returns:
        SessionInfo: The created session information
        
    Raises:
        HTTPException: Various HTTP errors based on validation failures
    """
    
    # Validate x-correlator if provided
    validated_correlator = validate_x_correlator(x_correlator)
    
    try:
        # Validate required fields
        if not session_request.applicationServer.get('ipv4Address') and not session_request.applicationServer.get('ipv6Address'):
            raise HTTPException(
                status_code=400,
                detail="Application server must have at least one IP address (IPv4 or IPv6)"
            )
        
        # Validate QoS profile (basic validation)
        valid_qos_profiles = ["QOS_E", "QOS_S", "QOS_M", "QOS_L", "voice", "video", "gaming"]
        qos_profile_str = session_request.qosProfile
        if qos_profile_str not in valid_qos_profiles:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid qosProfile. Must be one of: {valid_qos_profiles}"
            )
        
        # Generate a unique session ID
        session_id = str(uuid.uuid4())
        
        # For this example implementation, we'll set status to AVAILABLE immediately
        # In a real implementation, this might be REQUESTED initially
        current_time = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(
            current_time.timestamp() + session_request.duration,
            tz=timezone.utc
        )
        
        # Create session info response
        session_info = SessionInfo(
            sessionId=session_id,
            device=session_request.device,
            applicationServer=session_request.applicationServer,
            devicePorts=session_request.devicePorts,
            applicationServerPorts=session_request.applicationServerPorts,
            qosProfile=session_request.qosProfile,
            sink=session_request.sink,
            sinkCredential=session_request.sinkCredential,
            duration=session_request.duration,
            startedAt=current_time,
            expiresAt=expires_at,
            qosStatus=QosStatus.AVAILABLE,
            statusInfo=None
        )
        
        # Store the session (in production, save to database)
        sessions_store[session_id] = session_info
        
        # Set response headers
        headers = {}
        if validated_correlator:
            headers["x-correlator"] = validated_correlator
            
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=session_info.model_dump(mode="json"),
            headers=headers
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Handle other errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error occurred while creating session: {str(e)}"
        ) 

@router.get("/sessions", summary="List all sessions")
async def list_sessions():
    """List all active sessions"""
    return {"sessions": list(sessions_store.values()), "count": len(sessions_store)}


@router.get("/sessions/{sessions_id}")
async def get_session(sessions_id: str):
    """Get a specific session by ID"""
    if sessions_id not in sessions_store:
        raise HTTPException(status_code=404, detail="Session not found")
    return sessions_store[sessions_id]


@router.delete("/sessions/{sessions_id}")
async def delete_session(sessions_id: str):
    """Delete a specific session by ID"""
    if sessions_id not in sessions_store:
        raise HTTPException(status_code=404, detail="Session not found")
    
    deleted_session = sessions_store.pop(sessions_id)
    return {"message": f"Session {sessions_id} deleted successfully", "session": deleted_session}