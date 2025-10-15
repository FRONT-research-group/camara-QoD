from fastapi import HTTPException, Header, Depends, status
from fastapi.responses import JSONResponse
from typing import Optional
import uuid
from app.utils.logger import get_app_logger
from app.models.schemas import SessionInfo, QosStatus, SessionId, XCorrelator
from app.services.db import store_session_with_correlator, get_session_data, verify_session_access, in_memory_db
from app.helpers.error_responses import create_error_response
from app.helpers.TF import post_tf_to_qos, delete_tf_to_qos
logger = get_app_logger()


def validate_x_correlator(x_correlator: Optional[str]) -> Optional[str]:
    """Validate x-correlator header using the XCorrelator Pydantic model"""
    if x_correlator:
        try:
            validated = XCorrelator.model_validate(x_correlator)
            return validated.root
        except Exception as e:
            raise create_error_response(
                400,
                "INVALID_ARGUMENT",
                "Client specified an invalid argument, request body or query param."
            )
    return x_correlator

async def create_session(
    session_request,
    x_correlator,
    store = Depends(in_memory_db)
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
            raise create_error_response(
                400,
                "INVALID_ARGUMENT",
                "ApplicationServer must have at least one IP address (ipv4Address or ipv6Address)"
            )
        
        # Check for potential QoS profile availability
        if hasattr(session_request, 'qosProfile') and session_request.qosProfile.root in ["UNAVAILABLE_PROFILE"]:
            raise create_error_response(
                422,
                "QUALITY_ON_DEMAND.QOS_PROFILE_NOT_APPLICABLE",
                "The requested QoS Profile is currently not available for session creation."
            )
        
        # Duration range validation for QoS profile
        if session_request.duration > 3600:  # Example: 6 minutes minutes
            raise create_error_response(
                400,
                "QUALITY_ON_DEMAND.DURATION_OUT_OF_RANGE",
                "The requested duration is out of the allowed range for the specific QoS profile"
            )
        
        # QosProfile validation (handled by Pydantic model)
        logger.info(f"Requested QoS profile: {session_request.qosProfile.root}")
        
        # Duration validation (handled by Pydantic model - minimum 1)
        logger.info(f"Requested duration: {session_request.duration} seconds")
        
        # Check for existing sessions with same device (session conflict)
        if session_request.device:
            # This is a simplified check - in a real implementation you'd check the database
            # for existing active sessions for the same device
            existing_sessions = [s for s in store.values() if 
                               s.get('session') and 
                               s['session'].device and 
                               session_request.device and
                               s['session'].device == session_request.device and
                               s['session'].qosStatus == QosStatus.AVAILABLE]
            
            if existing_sessions:
                logger.warning(f"Session conflict detected for device: {session_request.device}")
                raise create_error_response(
                    409,
                    "CONFLICT",
                    "Conflict with an existing session for the same device."
                )
        
        # Generate a unique session ID
        session_uuid = uuid.uuid4()
        session_id = SessionId.model_validate(session_uuid)
        

        
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
            qosStatus=QosStatus.AVAILABLE,
            statusInfo=None
        )
        
        # Store the session with its x-correlator
        store_session_with_correlator(str(session_id.root), session_info, validated_correlator)
        logger.info(f"Session created with ID: {session_id.root} and correlator: {validated_correlator}")
        
        # Set response headers
        headers = {}
        if validated_correlator:
            headers["x-correlator"] = validated_correlator

        #NOTE testing the TF fucntions 
        await post_tf_to_qos(str(session_id.root))

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


async def get_session_info(
    session_id: str,
    x_correlator: Optional[str] = None,
    store = Depends(in_memory_db)
) -> SessionInfo:
    """
    Get QoS session information by session ID
    
    Args:
        session_id: The session ID to retrieve
        x_correlator: Optional correlation ID header
        store: In-memory database dependency
        
    Returns:
        SessionInfo: The session information
        
    Raises:
        HTTPException: Various HTTP errors based on validation failures
    """
    try:
        # Validate x-correlator if provided
        validated_correlator = validate_x_correlator(x_correlator)
        logger.info(f"Retrieving QoS session {session_id} with correlator: {validated_correlator}")
        
        # Get session data (includes correlator info)
        session_data = get_session_data(session_id)
        if not session_data:
            logger.warning(f"Session {session_id} not found")
            raise create_error_response(
                404,
                "NOT_FOUND",
                f"Session with ID '{session_id}' not found"
            )
        
        # Cross-check x-correlator if provided
        if validated_correlator:
            if verify_session_access(session_id, validated_correlator) == False:
                stored_correlator = session_data.get("x_correlator", "none")
                logger.warning(f"Access denied: Session {session_id} x-correlator mismatch. Provided: {validated_correlator}, Expected: {stored_correlator}")
                #NOTE fix this error not correct
                raise create_error_response(
                    403,
                    "PERMISSION_DENIED",
                    "Access denied: Session was created with a different x-correlator"
                )
            else:
                logger.info(f"x-correlator verification successful for session {session_id}")
        
        # Get the actual session info
        session_info = session_data.get("session")
        
        logger.info(f"Session {session_id} retrieved successfully")
        
        # Validate session data integrity
        if not isinstance(session_info, SessionInfo):
            logger.error(f"Invalid session data type for session {session_id}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Invalid session data found"
            )
        
        return session_info
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error retrieving session {session_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error occurred while retrieving session: {str(e)}"
        )


async def delete_session(
    session_id: str,
    x_correlator: Optional[str] = None
) -> dict:
    """
    Delete QoS session by session ID with x-correlator validation
    
    Args:
        session_id: The session ID to delete
        x_correlator: Optional correlation ID header for validation
        
    Returns:
        dict: Confirmation message with deleted session info
        
    Raises:
        HTTPException: Various HTTP errors based on validation failures
    """
    try:
        # Validate x-correlator if provided
        validated_correlator = validate_x_correlator(x_correlator)
        logger.info(f"Deleting QoS session {session_id} with correlator: {validated_correlator}")
        
        # Get session data (includes correlator info)
        session_data = get_session_data(session_id)
        if not session_data:
            logger.warning(f"Session {session_id} not found for deletion")
            raise create_error_response(
                404,
                "NOT_FOUND",
                f"Session with ID '{session_id}' not found"
            )
        
        # Cross-check x-correlator if provided (same logic as GET)
        if validated_correlator:
            if not verify_session_access(session_id, validated_correlator):
                stored_correlator = session_data.get("x_correlator", "none")
                logger.warning(f"Delete access denied: Session {session_id} x-correlator mismatch. Provided: {validated_correlator}, Expected: {stored_correlator}")
                raise create_error_response(
                    403,
                    "PERMISSION_DENIED",
                    "Access denied: Session was created with a different x-correlator"
                )
            else:
                logger.info(f"x-correlator verification successful for session {session_id} deletion")
        
        # Get the session info before deletion
        # session_info = session_data.get("session")
        stored_correlator = session_data.get("x_correlator")
        
        # Delete from external QoS system first
        await delete_tf_to_qos(session_id)
        
        # Delete the session from database
        store = in_memory_db()
        if session_id in store:
            del store[session_id]
            logger.info(f"Session {session_id} deleted successfully")
        else:
            logger.error(f"Session {session_id} not found in store during deletion")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session with ID '{session_id}' not found in store"
            )
        
        # Return confirmation with session details
        return {
            "message": f"Session {session_id} deleted successfully",
        }
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error deleting session {session_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error occurred while deleting session: {str(e)}"
        )


