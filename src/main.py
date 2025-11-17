'''
    Run this with:
      uvicorn main:_app --host 0.0.0.0 --port 8001 --reload or python3 main.py
'''
from app.utils.logger import get_app_logger
from app import _app
from app.utils.config import LOG_LEVEL,ASSESSIONWITHQOS_URL

logger = get_app_logger()

logger.info('*** Quality-on-Demand **')
logger.info(f"QoS_NEF_URL: {ASSESSIONWITHQOS_URL}")
logger.info(f"Log Level set to: {LOG_LEVEL}")



if __name__ == "__main__":
  import uvicorn
  uvicorn.run(_app, host="0.0.0.0", port=8002)
