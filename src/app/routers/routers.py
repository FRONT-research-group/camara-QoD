from fastapi import APIRouter, HTTPException, Header, Response, Request, Depends, status
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
import uuid
from datetime import datetime, timezone
from pydantic import ValidationError
from app.utils.logger import get_app_logger
from app.models.schemas import CreateSession, SessionInfo, QosStatus, SessionId, XCorrelator, ExtendSessionDuration
from app.services.db import in_memory_db
from app.services.backend_routers import create_session, get_session_info, delete_session, extend_duration
from app.helpers.response_examples import (
    CREATE_SESSION_ERROR_RESPONSES, 
    GET_SESSION_ERROR_RESPONSES, 
    DELETE_SESSION_ERROR_RESPONSES,
    SUCCESS_RESPONSES,
    COMMON_ERROR_RESPONSES
)

logger = get_app_logger()

router = APIRouter()


#NOTE check if in the parameters the x_correlator is required or not


@router.post(
    "/sessions",
    response_model=SessionInfo,
    status_code=status.HTTP_201_CREATED,
    summary="Creates a new session",
    description="""
    Create QoS Session to manage latency/throughput priorities.
    
    **MINIMAL REQUIRED EXAMPLE:**
    {
      "applicationServer": {
        "ipv4Address": "192.168.1.100"
      },
      "qosProfile": "QOS_L",
      "duration": 3600
    }
    
    Required fields:
    - applicationServer: Must have at least one IP address (IPv4 or IPv6)
    - qosProfile: QoS profile name (e.g., QOS_L, QOS_S, QOS_M, QOS_E, voice)
    - duration: Session duration in seconds (minimum 1)
    
    Optional fields:
    - device: Device information
    - devicePorts: Ports used by the device
    - applicationServerPorts: Ports on the application server
    - sink: Notification callback URL
    - sinkCredential: Authentication for notifications
    """,
    responses={
        201: SUCCESS_RESPONSES["CREATE_SESSION_201"],
        **CREATE_SESSION_ERROR_RESPONSES
    }
)
async def backend_create_session(
    session_request: CreateSession,
    x_correlator: Optional[str] = Header('b4333c46-49c0-4f62-80d7-f0ef930f1c46', description="Correlation id for the different services"),
    store: dict = Depends(in_memory_db)
):
    return await create_session(session_request, x_correlator, store)


@router.get(
    "/sessions/{session_id}", 
    response_model=SessionInfo,
    summary="Get QoS session by ID",
    status_code=status.HTTP_200_OK,
    description="Retrieve a specific QoS session by its ID with optional x-correlator",
    responses={
        200: SUCCESS_RESPONSES["GET_SESSION_200"],
        **GET_SESSION_ERROR_RESPONSES
    }
)
async def get_session(
    session_id: str, 
    x_correlator: Optional[str] = Header(None, description="Correlation id for the different services"),
    store: dict = Depends(in_memory_db)
):
    """Get a specific QoS session by ID"""
    return await get_session_info(session_id, x_correlator, store)




@router.delete(
    "/sessions/{session_id}",
    summary="Delete QoS session by ID",
    description="Delete a specific QoS session by its ID with optional x-correlator validation",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        204: SUCCESS_RESPONSES["DELETE_SESSION_204"],
        **DELETE_SESSION_ERROR_RESPONSES
    }
)
async def delete_session_endpoint(
    session_id: str, 
    x_correlator: Optional[str] = Header(None, description="Correlation id for the different services"),
):
    """Delete a specific QoS session by ID with x-correlator validation"""
    return await delete_session(session_id, x_correlator)


@router.post(
    "/sessions/{sessions_id}/extend",
    response_model=SessionInfo,
    summary="Extend QoS session duration",
    description="Extend the duration of an existing QoS session by its ID",
    status_code=status.HTTP_200_OK,
    responses={**COMMON_ERROR_RESPONSES}
    
    )
async def extend_session_duration(
    sessions_id: str,
    extend_request: ExtendSessionDuration,
    x_correlator: Optional[str] = Header(None, description="Correlation id for the different services"),
    store: dict = Depends(in_memory_db)
):
    """Extend the duration of an existing QoS session by its ID"""
    return await extend_duration(sessions_id, extend_request, x_correlator)