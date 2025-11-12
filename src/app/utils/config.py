import os


ASSESSIONWITHQOS_URL = os.getenv("ASSESSIONWITHQOS_URL", "http://localhost:8001/3gpp-as-session-with-qos/v1")

LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG") # Set default to INFO or you can change to DEBUG to see more detailed logs