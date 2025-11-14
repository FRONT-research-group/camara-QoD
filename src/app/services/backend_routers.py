from fastapi import HTTPException, Header, Depends, status
from fastapi.responses import JSONResponse
from typing import Optional
import uuid
import asyncio
from datetime import datetime, timezone, timedelta
from app.utils.logger import get_app_logger
from app.models.schemas import SessionInfo, QosStatus, SessionId, XCorrelator, ExtendSessionDuration, RetrieveSessionsInput,RetrieveSessionsInput,RetrieveSessionsOutput
from app.services.db import store_session_with_correlator, get_session_data, verify_session_access, in_memory_db, get_deletion_task, update_deletion_task
from app.helpers.error_responses import create_error_response
from app.helpers.TF import post_tf_to_qos, delete_tf_to_qos, schedule_qos_deletion
from app.helpers.callback import send_notification_to_sink
from app.models.schemas import EventQosStatus, StatusInfo



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
    session_request ,
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
        logger.debug(f"Creating new QoS session with correlator: {validated_correlator}")
        logger.debug(f"Session request payload: {session_request}")
        from app.services.db import DB
        import json
        try:
            db_json = {k: {**v, "session": v["session"].model_dump() if hasattr(v["session"], "model_dump") else v["session"]} for k, v in DB.items()}
            logger.debug(f"DB state after request: {json.dumps(db_json, indent=2, default=str)}")
        except Exception:
            logger.debug(f"DB state after request: {DB}")
        
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
        
        logger.debug(f"Requested QoS profile: {session_request.qosProfile.root}")
        
        logger.debug(f"Requested duration: {session_request.duration} seconds")
        
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
        
        session_uuid = uuid.uuid4()
        session_id = SessionId.model_validate(session_uuid)
        
        started_at = datetime.now(timezone.utc)
        expires_at = started_at + timedelta(seconds=session_request.duration)
        
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
            statusInfo=None,
            startedAt=started_at,
            expiresAt=expires_at
        )
        
        store_session_with_correlator(str(session_id.root), session_info, validated_correlator)
        logger.info(f"Session created with ID: {session_id.root} and correlator: {validated_correlator}")
        
        # Set response headers
        headers = {}
        if validated_correlator:
            headers["x-correlator"] = validated_correlator


        #NOTE Calling the TF function to create the session in AsSessionWithQoS
        _, qos_status_code = await post_tf_to_qos(str(session_id.root))
        
        # Check if QoS system returned 404 or other error
        if qos_status_code and qos_status_code == 404:
            logger.warning(f"QoS system returned 404 for session {session_id.root}, sending NETWORK_TERMINATED notification")
            
            # Send callback notification with UNAVAILABLE status and NETWORK_TERMINATED info
            await send_notification_to_sink(
                session_id=str(session_id.root),
                qos_status=EventQosStatus.UNAVAILABLE,
                status_info=StatusInfo.NETWORK_TERMINATED
            )
        elif qos_status_code and qos_status_code >= 400:
            logger.error(f"QoS system returned error {qos_status_code} for session {session_id.root}")
            
            # Send callback notification with UNAVAILABLE status and NETWORK_TERMINATED info
            await send_notification_to_sink(
                session_id=str(session_id.root),
                qos_status=EventQosStatus.UNAVAILABLE,
                status_info=StatusInfo.NETWORK_TERMINATED
            )
        else:
            # Send callback notification for successful session creation with AVAILABLE status
            await send_notification_to_sink(
                session_id=str(session_id.root),
                qos_status=EventQosStatus.AVAILABLE,
                status_info=None
            )

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=session_info.model_dump(mode="json", exclude_none=True),
            headers=headers
        )
        

    except HTTPException:
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
        logger.debug(f"Session info request for session_id={session_id}, correlator={validated_correlator}")
        
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
        
        session_info = session_data.get("session")
        
        logger.debug(f"Session {session_id} retrieved successfully")
        
        # Validate session data integrity
        if not isinstance(session_info, SessionInfo):
            logger.error(f"Invalid session data type for session {session_id}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Invalid session data found"
            )
        
        return session_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving session {session_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error occurred while retrieving session: {str(e)}"
        )


async def delete_session(
    session_id: str,
    x_correlator: Optional[str] = None,
    store = Depends(in_memory_db)
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
        from app.services.db import DB
        import json
        try:
            db_json = {k: {**v, "session": v["session"].model_dump() if hasattr(v["session"], "model_dump") else v["session"]} for k, v in DB.items()}
            logger.debug(f"DB state after request: {json.dumps(db_json, indent=2, default=str)}")
        except Exception:
            logger.debug(f"DB state after request: {DB}")

        
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
        
        session_info = session_data.get("session")
        stored_correlator = session_data.get("x_correlator")
        
        # Update session status to UNAVAILABLE with DELETE_REQUESTED
        if session_info:
            session_info.qosStatus = QosStatus.UNAVAILABLE
            session_info.statusInfo = StatusInfo.DELETE_REQUESTED
        
        #NOTE calling the TF function to delete the session in AsSessionWithQoS
        await delete_tf_to_qos(session_id)
        
        # Send callback notification BEFORE deleting from database (so callback can retrieve session data)
        await send_notification_to_sink(
            session_id=session_id,
            qos_status=EventQosStatus.UNAVAILABLE,
            status_info=StatusInfo.DELETE_REQUESTED
        )
        
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
        
        return {
            "message": f"Session {session_id} deleted successfully",
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting session {session_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error occurred while deleting session: {str(e)}"
        )

async def extend_duration(
    sessions_id: str,
    extend_request: ExtendSessionDuration,
    x_correlator: Optional[str] = None,
    store = Depends(in_memory_db)
):
    """
    Extend the duration of an existing QoS session by its ID
    
    Args:
        sessions_id: The session ID to extend
        extend_request: The request body with requestedAdditionalDuration
        x_correlator: Optional correlation ID header for validation
        
    Returns:
        SessionInfo: The updated session information with extended duration
    """
    try:
        # Validate x-correlator if provided
        validated_correlator = validate_x_correlator(x_correlator)
        logger.info(f"Extending duration for QoS session {sessions_id} with correlator: {validated_correlator}")
        from app.services.db import DB
        import json
        try:
            db_json = {k: {**v, "session": v["session"].model_dump() if hasattr(v["session"], "model_dump") else v["session"]} for k, v in DB.items()}
            logger.debug(f"DB state after request: {json.dumps(db_json, indent=2, default=str)}")
        except Exception:
            logger.debug(f"DB state after request: {DB}")
        
        # Get session data (includes correlator info)
        session_data = get_session_data(sessions_id)
        if not session_data:
            logger.warning(f"Session {sessions_id} not found for duration extension")
            raise create_error_response(
                404,
                "NOT_FOUND",
                f"Session with ID '{sessions_id}' not found"
            )
        
        # Cross-check x-correlator if provided
        if validated_correlator:
            if not verify_session_access(sessions_id, validated_correlator):
                stored_correlator = session_data.get("x_correlator", "none")
                logger.warning(f"Extend access denied: Session {sessions_id} x-correlator mismatch. Provided: {validated_correlator}, Expected: {stored_correlator}")
                raise create_error_response(
                    403,
                    "PERMISSION_DENIED",
                    "Access denied: Session was created with a different x-correlator"
                )
            else:
                logger.info(f"x-correlator verification successful for session {sessions_id} duration extension")
        
        # Get the session info
        session_info = session_data.get("session")
        
        if not session_info:
            logger.error(f"No session info found for session {sessions_id}")
            raise create_error_response(
                500,
                "INTERNAL",
                "Session data is corrupted"
            )
        
        # Validate that session is AVAILABLE
        if session_info.qosStatus != QosStatus.AVAILABLE:
            logger.warning(f"Cannot extend session {sessions_id} with status {session_info.qosStatus}")
            raise create_error_response(
                400,
                "INVALID_ARGUMENT",
                f"Session must be in AVAILABLE status to extend duration. Current status: {session_info.qosStatus}"
            )
        
        additional_duration = extend_request.requestedAdditionalDuration
        
        new_duration = session_info.duration + additional_duration
        
        max_duration = 3600
        if new_duration > max_duration:
            logger.warning(f"Requested total duration {new_duration} exceeds maximum {max_duration}")
            raise create_error_response(
                400,
                "QUALITY_ON_DEMAND.DURATION_OUT_OF_RANGE",
                f"The extended duration would exceed the maximum allowed duration of {max_duration} seconds"
            )
        
        session_info.duration = new_duration
        if session_info.startedAt:
            # Recalculate expiresAt based on startedAt + new total duration
            session_info.expiresAt = session_info.startedAt + timedelta(seconds=new_duration)
            logger.debug(f"Updated expiresAt to {session_info.expiresAt.isoformat()}")
        
        # Update the session in the database
        store = in_memory_db()
        if sessions_id in store:
            store[sessions_id]["session"] = session_info
            logger.debug(f"Session {sessions_id} duration extended by {additional_duration} seconds to {new_duration} seconds total")
        else:
            logger.error(f"Session {sessions_id} not found in store during duration extension")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session with ID '{sessions_id}' not found in store"
            )
        
        # Reschedule the automatic deletion: cancel old task and create new one with new total duration
        session_data = get_session_data(sessions_id)
        if session_data:
            existing_task = get_deletion_task(sessions_id)
            if existing_task and not existing_task.done():
                existing_task.cancel()
                logger.debug(f"Cancelled existing deletion task for session {sessions_id}")
            
            QoS_sub_id = session_data.get("QoS_sub_id")
            x_correlator = session_data.get("x_correlator")
            
            if QoS_sub_id:
                # Create new background task with the new total duration
                new_task = asyncio.create_task(
                    schedule_qos_deletion(x_correlator, QoS_sub_id, new_duration, sessions_id)
                )
                
                update_deletion_task(sessions_id, new_task)
                logger.debug(f"New deletion task scheduled for session {sessions_id} in {new_duration} seconds")
            else:
                logger.warning(f"No QoS subscription ID found for session {sessions_id}, cannot reschedule deletion")
        
        return session_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error extending duration for session {sessions_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error occurred while extending session duration: {str(e)}"
        )
    
async def retrieve_backend_sessions(
    x_correlator: Optional[str] = None,
    request_model: RetrieveSessionsInput = None,
    store = Depends(in_memory_db)
):
    """
    Retrieve QoS sessions for a given device
    
    Args:
        x_correlator: Optional correlation ID header for validation
        request_model: The request body containing device information to filter sessions
        store: In-memory database dependency (can be replaced with real DB in future)
        
    Returns:
        RetrieveSessionsOutput: List of sessions matching the device criteria (empty array if no sessions match)
    """
    try:
        # Validate x-correlator if provided
        validated_correlator = validate_x_correlator(x_correlator)
        logger.info(f"Retrieving QoS sessions with correlator: {validated_correlator}")
        
        # Get all sessions from the database
        retrieved_sessions = []
        
        # If no device specified, return all sessions (or empty array)
        if not request_model or not request_model.device:
            logger.debug("No device specified, returning all sessions")
            for session_id, session_data in store.items():
                session_info = session_data.get("session")
                if session_info:
                    retrieved_sessions.append(session_info)
        else:
            device_filter = request_model.device
            logger.info(f"Filtering sessions by device: {device_filter}")
            
            for session_id, session_data in store.items():
                session_info = session_data.get("session")
                if not session_info or not session_info.device:
                    continue
                
                # Check if device matches any of the provided identifiers
                match = False
                
                # Check phone number
                if device_filter.phoneNumber and session_info.device.phoneNumber:
                    if device_filter.phoneNumber.root == session_info.device.phoneNumber.root:
                        match = True
                
                # Check network access identifier
                if device_filter.networkAccessIdentifier and session_info.device.networkAccessIdentifier:
                    if device_filter.networkAccessIdentifier.root == session_info.device.networkAccessIdentifier.root:
                        match = True
                
                # Check IPv4 address
                if device_filter.ipv4Address and session_info.device.ipv4Address:
                    if device_filter.ipv4Address.root.publicAddress.root == session_info.device.ipv4Address.root.publicAddress.root:
                        match = True
                
                # Check IPv6 address
                if device_filter.ipv6Address and session_info.device.ipv6Address:
                    if device_filter.ipv6Address.root == session_info.device.ipv6Address.root:
                        match = True
                
                if match:
                    retrieved_sessions.append(session_info)
        
        logger.info(f"Successfully retrieved {len(retrieved_sessions)} sessions")
        return retrieved_sessions
        
    except Exception as e:
        logger.error(f"Error retrieving sessions: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error occurred while retrieving sessions: {str(e)}"
        )