from fastapi import HTTPException
from app.models.schemas import ErrorInfo


def create_error_response(status_code: int, error_code: str, message: str) -> HTTPException:
    """Create standardized error response using ErrorInfo format"""
    error_detail = ErrorInfo(
        status=status_code,
        code=error_code,
        message=message
    )
    return HTTPException(
        status_code=status_code,
        detail=error_detail.model_dump()
    )
