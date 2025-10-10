from fastapi import HTTPException, Header, Depends, status
from fastapi.responses import JSONResponse
from typing import Optional
import uuid
from datetime import datetime, timezone
from app.utils.logger import get_app_logger
from app.models.schemas import CreateSession, SessionInfo, QosStatus, SessionId, XCorrelator
from app.services.db import in_memory_db

logger = get_app_logger()

def validate_x_correlator(x_correlator: Optional[str]) -> Optional[str]:
    """Validate x-correlator header using the XCorrelator Pydantic model"""
    if x_correlator:
        try:
            validated = XCorrelator.model_validate(x_correlator)
            return validated.root
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid x-correlator format: {str(e)}"
            )
    return x_correlator

async def create_session(
    session_request,
    x_correlator,
    store
):
    """
    Create a new QoS session with required fields validation
    
    Args:
        session_request: The session creation request with required fields
        x_correlator: Optional correlation ID header
        store: In-memory database dependency
        
    Returns:
        SessionInfo: The created session information
        
    Raises:
        HTTPException: Various HTTP errors based on validation failures
    """
    try:
        # Validate x-correlator if provided
        validated_correlator = validate_x_correlator(x_correlator)
        logger.info(f"Creating new QoS session with correlator: {validated_correlator}")
        
        # Validate required fields
        # ApplicationServer validation (must have at least one IP address)
        if not session_request.applicationServer.ipv4Address and not session_request.applicationServer.ipv6Address:
            raise HTTPException(
                status_code=400,
                detail="ApplicationServer must have at least one IP address (ipv4Address or ipv6Address)"
            )
        
        # QosProfile validation (handled by Pydantic model)
        logger.info(f"Requested QoS profile: {session_request.qosProfile.root}")
        
        # Duration validation (handled by Pydantic model - minimum 1)
        logger.info(f"Requested duration: {session_request.duration} seconds")
        
        # Generate a unique session ID
        session_uuid = uuid.uuid4()
        session_id = SessionId.model_validate(session_uuid)
        
        # For this implementation, set status to AVAILABLE immediately
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
        
        # Store the session
        store[str(session_id.root)] = session_info
        logger.info(f"Session created with ID: {session_id.root}")
        
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
        logger.error(f"Error creating session: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error occurred while creating session: {str(e)}"
        )
    