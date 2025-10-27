"""
Response examples for FastAPI endpoints based on OpenAPI specification.
This module contains all the standardized error response examples used across endpoints.
"""

from app.models.schemas import ErrorInfo

# Common error response examples that can be reused across endpoints
COMMON_ERROR_RESPONSES = {
    400: {
        "model": ErrorInfo,
        "description": "Bad Request",
        "content": {
            "application/json": {
                "examples": {
                    "GENERIC_400_INVALID_ARGUMENT": {
                        "summary": "Invalid Argument",
                        "description": "Invalid Argument. Generic Syntax Exception",
                        "value": {"status": 400, "code": "INVALID_ARGUMENT", "message": "Client specified an invalid argument, request body or query param."}
                    },
                    "GENERIC_400_OUT_OF_RANGE": {
                        "summary": "Out of Range", 
                        "description": "Out of Range. Specific Syntax Exception used when a given field has a pre-defined range or a invalid filter criteria combination is requested",
                        "value": {"status": 400, "code": "OUT_OF_RANGE", "message": "Client specified an invalid range."}
                    }
                }
            }
        }
    },
    401: {
        "model": ErrorInfo,
        "description": "Unauthorized",
        "content": {
            "application/json": {
                "examples": {
                    "GENERIC_401_UNAUTHENTICATED": {
                        "summary": "Unauthenticated",
                        "description": "Request cannot be authenticated and a new authentication is required",
                        "value": {"status": 401, "code": "UNAUTHENTICATED", "message": "Request not authenticated due to missing, invalid, or expired credentials. A new authentication is required."}
                    }
                }
            }
        }
    },
    403: {
        "model": ErrorInfo,
        "description": "Forbidden",
        "content": {
            "application/json": {
                "examples": {
                    "GENERIC_403_PERMISSION_DENIED": {
                        "summary": "Permission Denied",
                        "description": "Permission denied. OAuth2 token access does not have the required scope or when the user fails operational security",
                        "value": {"status": 403, "code": "PERMISSION_DENIED", "message": "Client does not have sufficient permissions to perform this action."}
                    },
                    "X_CORRELATOR_MISMATCH": {
                        "summary": "X-Correlator Mismatch",
                        "description": "Access denied due to x-correlator mismatch",
                        "value": {"status": 403, "code": "PERMISSION_DENIED", "message": "Access denied: Session was created with a different x-correlator"}
                    }
                }
            }
        }
    },
    404: {
        "model": ErrorInfo,
        "description": "Not Found",
        "content": {
            "application/json": {
                "examples": {
                    "GENERIC_404_NOT_FOUND": {
                        "summary": "Resource Not Found",
                        "description": "Resource is not found",
                        "value": {"status": 404, "code": "NOT_FOUND", "message": "The specified resource is not found."}
                    }
                }
            }
        }
    },
    410: {
        "model": ErrorInfo,
        "description": "Gone",
        "content": {
            "application/json": {
                "examples": {
                    "GENERIC_410_GONE": {
                        "summary": "Resource Gone",
                        "description": "Use in notifications flow to allow API Consumer to indicate that its callback is no longer available",
                        "value": {"status": 410, "code": "GONE", "message": "Access to the target resource is no longer available."}
                    }
                }
            }
        }
    },
    429: {
        "model": ErrorInfo,
        "description": "Too Many Requests",
        "content": {
            "application/json": {
                "examples": {
                    "GENERIC_429_QUOTA_EXCEEDED": {
                        "summary": "Quota Exceeded",
                        "description": "Request is rejected due to exceeding a business quota limit",
                        "value": {"status": 429, "code": "QUOTA_EXCEEDED", "message": "Out of resource quota."}
                    },
                    "GENERIC_429_TOO_MANY_REQUESTS": {
                        "summary": "Too Many Requests",
                        "description": "Access to the API has been temporarily blocked due to rate or spike arrest limits being reached",
                        "value": {"status": 429, "code": "TOO_MANY_REQUESTS", "message": "Rate limit reached."}
                    }
                }
            }
        }
    }
}

# POST /sessions specific error responses
CREATE_SESSION_ERROR_RESPONSES = {
    **COMMON_ERROR_RESPONSES,
    400: {
        "model": ErrorInfo,
        "description": "Bad Request",
        "content": {
            "application/json": {
                "examples": {
                    **COMMON_ERROR_RESPONSES[400]["content"]["application/json"]["examples"],
                    "DurationOutOfRangeForQoSProfile": {
                        "summary": "Duration Out of Range for QoS Profile",
                        "description": "The requested duration is out of the allowed range for the specific QoS profile",
                        "value": {"status": 400, "code": "QUALITY_ON_DEMAND.DURATION_OUT_OF_RANGE", "message": "The requested duration is out of the allowed range for the specific QoS profile"}
                    },
                    "GENERIC_400_INVALID_CREDENTIAL": {
                        "summary": "Invalid Credential",
                        "value": {"status": 400, "code": "INVALID_CREDENTIAL", "message": "Only Access token is supported"}
                    },
                    "GENERIC_400_INVALID_TOKEN": {
                        "summary": "Invalid Token",
                        "value": {"status": 400, "code": "INVALID_TOKEN", "message": "Only bearer token is supported"}
                    },
                    "GENERIC_400_INVALID_SINK": {
                        "summary": "Invalid Sink",
                        "description": "Invalid sink value",
                        "value": {"status": 400, "code": "INVALID_SINK", "message": "sink not valid for the specified protocol"}
                    }
                }
            }
        }
    },
    404: {
        "model": ErrorInfo,
        "description": "Not Found",
        "content": {
            "application/json": {
                "examples": {
                    **COMMON_ERROR_RESPONSES[404]["content"]["application/json"]["examples"],
                    "GENERIC_404_DEVICE_NOT_FOUND": {
                        "summary": "Device Not Found",
                        "description": "Device identifier not found",
                        "value": {"status": 404, "code": "IDENTIFIER_NOT_FOUND", "message": "Device identifier not found."}
                    }
                }
            }
        }
    },
    409: {
        "model": ErrorInfo,
        "description": "Conflict",
        "content": {
            "application/json": {
                "examples": {
                    "SessionInConflict": {
                        "summary": "Session Conflict",
                        "value": {"status": 409, "code": "CONFLICT", "message": "Conflict with an existing session for the same device."}
                    }
                }
            }
        }
    },
    422: {
        "model": ErrorInfo,
        "description": "Unprocessable Content",
        "content": {
            "application/json": {
                "examples": {
                    "GENERIC_422_SERVICE_NOT_APPLICABLE": {
                        "summary": "Service Not Applicable",
                        "description": "Service not applicable for the provided identifier",
                        "value": {"status": 422, "code": "SERVICE_NOT_APPLICABLE", "message": "The service is not available for the provided identifier."}
                    },
                    "GENERIC_422_MISSING_IDENTIFIER": {
                        "summary": "Missing Identifier",
                        "description": "An identifier is not included in the request and the device or phone number identification cannot be derived from the access token",
                        "value": {"status": 422, "code": "MISSING_IDENTIFIER", "message": "The device cannot be identified."}
                    },
                    "GENERIC_422_UNSUPPORTED_IDENTIFIER": {
                        "summary": "Unsupported Identifier",
                        "description": "None of the provided identifiers is supported by the implementation",
                        "value": {"status": 422, "code": "UNSUPPORTED_IDENTIFIER", "message": "The identifier provided is not supported."}
                    },
                    "GENERIC_422_UNNECESSARY_IDENTIFIER": {
                        "summary": "Unnecessary Identifier",
                        "description": "An explicit identifier is provided when a device or phone number has already been identified from the access token",
                        "value": {"status": 422, "code": "UNNECESSARY_IDENTIFIER", "message": "The device is already identified by the access token."}
                    },
                    "QUALITY_ON_DEMAND_422_QOS_PROFILE_NOT_APPLICABLE": {
                        "summary": "QoS Profile Not Applicable",
                        "description": "The requested QoS Profile exists but cannot be used to create a session.",
                        "value": {"status": 422, "code": "QUALITY_ON_DEMAND.QOS_PROFILE_NOT_APPLICABLE", "message": "The requested QoS Profile is currently not available for session creation."}
                    }
                }
            }
        }
    }
}

# GET /sessions/{session_id} specific error responses
GET_SESSION_ERROR_RESPONSES = {
    **COMMON_ERROR_RESPONSES,
    404: {
        "model": ErrorInfo,
        "description": "Not Found",
        "content": {
            "application/json": {
                "examples": {
                    **COMMON_ERROR_RESPONSES[404]["content"]["application/json"]["examples"],
                    "SESSION_NOT_FOUND": {
                        "summary": "Session Not Found",
                        "description": "Session with the provided ID was not found",
                        "value": {"status": 404, "code": "NOT_FOUND", "message": "Session with ID 'invalid-id' not found"}
                    }
                }
            }
        }
    }
}

# DELETE /sessions/{session_id} specific error responses  
DELETE_SESSION_ERROR_RESPONSES = {
    **COMMON_ERROR_RESPONSES,
    404: {
        "model": ErrorInfo,
        "description": "Not Found",
        "content": {
            "application/json": {
                "examples": {
                    **COMMON_ERROR_RESPONSES[404]["content"]["application/json"]["examples"],
                    "SESSION_NOT_FOUND": {
                        "summary": "Session Not Found",
                        "description": "Session with the provided ID was not found",
                        "value": {"status": 404, "code": "NOT_FOUND", "message": "Session with ID 'invalid-id' not found"}
                    }
                }
            }
        }
    }
}

# Success response examples
SUCCESS_RESPONSES = {
    "CREATE_SESSION_201": {
        "description": "Session created successfully",
        "content": {
            "application/json": {
                "example": {
                    "sessionId": "qs15-h556-rt89-1298",
                    "device": None,
                    "applicationServer": {
                        "ipv4Address": "192.168.1.0/24"
                    },
                    "sink": "https://application-server.com/notifications",
                    "qosProfile": "QOS_L",
                    "duration": 3600,
                    "qosStatus": "AVAILABLE"
                }
            }
        }
    },
    "GET_SESSION_200": {
        "description": "Session retrieved successfully",
        "content": {
            "application/json": {
                "example": {
                    "sessionId": "qs15-h556-rt89-1298",
                    "device": None,
                    "applicationServer": {
                        "ipv4Address": "192.168.1.100"
                    },
                    "qosProfile": "QOS_L",
                    "duration": 3600,
                    "startedAt": "2025-10-14T10:30:00Z",
                    "expiresAt": "2025-10-14T11:30:00Z",
                    "qosStatus": "AVAILABLE"
                }
            }
        }
    },
    "DELETE_SESSION_204": {
        "description": "Session deleted successfully",
        "status_code": 204
    }
}