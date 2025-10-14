

DB = {}

def in_memory_db():
    return DB

def store_session_with_correlator(session_id: str, session_info, x_correlator: str = None):
    """Store session with its x-correlator for cross-checking"""
    DB[session_id] = {
        "session": session_info,
        "x_correlator": x_correlator
    }

def get_session_data(session_id: str):
    """Get session data including x-correlator"""
    return DB.get(session_id, {})

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