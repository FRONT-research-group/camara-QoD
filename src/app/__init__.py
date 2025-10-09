'''
Docstring
'''
from fastapi import FastAPI
from app.routers import routers

# FastAPI object customization
FASTAPI_TITLE = "Quality On Demand API"
FASTAPI_DESCRIPTION = "QoD API"
FASTAPI_VERSION = "0.109.0"
FASTAPI_OPEN_API_URL = "/"
FASTAPI_DOCS_URL = "/docs"

_app = FastAPI(title=FASTAPI_TITLE,
              description=FASTAPI_DESCRIPTION,
              version=FASTAPI_VERSION,
              docs_url=FASTAPI_DOCS_URL,
              openapi_url=FASTAPI_OPEN_API_URL)

_app.include_router(routers.router, prefix="/quality-on-demand/v1")