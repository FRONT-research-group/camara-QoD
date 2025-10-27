from app.utils.logger import get_app_logger
import json
"""In-memory Database for storing, but could be replaced with persistent storage"""
logger = get_app_logger()


DB = {}

def in_memory_db():
    return DB

def store_session_with_correlator(session_id: str, session_info, x_correlator: str = None, QoS_sub_id: str = None, deletion_task = None):
    """Store session with its x-correlator, QoS_sub_id, and deletion task for cross-checking"""
    DB[session_id] = {
        "session": session_info,
        "x_correlator": x_correlator,
        "QoS_sub_id": QoS_sub_id,
        "deletion_task": deletion_task
    }
    try:
        # Convert session_info to dict
        db_json = {k: {**v, "session": v["session"].model_dump() if hasattr(v["session"], "model_dump") else v["session"]} for k, v in DB.items()}
        logger.debug(f"DB after store_session_with_correlator: {json.dumps(db_json, indent=2, default=str)}")
    except Exception:
        logger.debug(f"DB after store_session_with_correlator: {DB}")

def get_session_data(session_id: str):
    """Get session data including x-correlator"""
    return DB.get(session_id, {})

def update_subscription_id(session_id: str, QoS_sub_id: str):
    """Update the QoS subscription ID for a session"""
    if session_id in DB:
        DB[session_id]["QoS_sub_id"] = QoS_sub_id

def update_deletion_task(session_id: str, deletion_task):
    """Update the deletion task reference for a session"""
    if session_id in DB:
        DB[session_id]["deletion_task"] = deletion_task
        try:
            db_json = {k: {**v, "session": v["session"].model_dump() if hasattr(v["session"], "model_dump") else v["session"]} for k, v in DB.items()}
            logger.debug(f"DB after update_deletion_task: {json.dumps(db_json, indent=2, default=str)}")
        except Exception:
            logger.debug(f"DB after update_deletion_task: {DB}")

def get_deletion_task(session_id: str):
    """Get the deletion task for a session"""
    session_data = DB.get(session_id, {})
    return session_data.get("deletion_task")

def verify_session_access(session_id: str, x_correlator: str = None) -> bool:
    """Verify if the provided x-correlator matches the one used to create the session"""
    session_data = get_session_data(session_id)
    if not session_data:
        return False
    
    stored_correlator = session_data.get("x_correlator")
    
    # If no correlator was stored or provided, allow access
    if not stored_correlator or not x_correlator:
        return True
    
    # Check if correlators match
    return stored_correlator == x_correlator