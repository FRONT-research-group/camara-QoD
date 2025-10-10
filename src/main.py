'''
    Run this with:
      uvicorn main:_app --host 0.0.0.0 --port 8000 --reload or python3 main.py
'''
from app.utils.logger import get_app_logger
from app import _app

logger = get_app_logger()

logger.info('*** Quality-on-Demand **')



if __name__ == "__main__":
  import uvicorn
  uvicorn.run(_app, host="0.0.0.0", port=8001)
