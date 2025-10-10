from fastapi import APIRouter, HTTPException, Header, Response, Request, Depends, status
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
import uuid
from datetime import datetime, timezone
from pydantic import ValidationError
from app.utils.logger import get_app_logger
from app.models.schemas import CreateSession, SessionInfo, QosStatus, SessionId, XCorrelator
from app.services.db import in_memory_db
from app.services.backend_routers import create_session 

logger = get_app_logger()

router = APIRouter()


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
)
async def backend_create_session(
    session_request: CreateSession,
    x_correlator: Optional[str] = Header('b4333c46-49c0-4f62-80d7-f0ef930f1c46', description="Correlation id for the different services"),
    store: dict = Depends(in_memory_db)
):
    return await create_session(session_request, x_correlator, store)

                                    








@router.get("/sessions", summary="List all sessions")
async def list_sessions(store: dict = Depends(in_memory_db)):
    """List all active sessions"""
    return {"sessions": list(store.values()), "count": len(store)}


@router.get("/sessions/{session_id}", response_model=SessionInfo)
async def get_session(session_id: str, store: dict = Depends(in_memory_db)):
    """Get a specific session by ID"""
    if session_id not in store:
        raise HTTPException(status_code=404, detail="Session not found")
    return store[session_id]


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: str, store: dict = Depends(in_memory_db)):
    """Delete a specific session by ID"""
    if session_id not in store:
        raise HTTPException(status_code=404, detail="Session not found")
    
    deleted_session = store.pop(session_id)
    logger.info(f"Session {session_id} deleted successfully")
    return {"message": f"Session {session_id} deleted successfully", "session": deleted_session}