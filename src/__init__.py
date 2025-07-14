from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .lambda_ import app as lambda_app
from .s3 import app as s3_app
from .iam import app as iam_app

def create_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(lambda_app)
    app.include_router(s3_app)
    app.include_router(iam_app)
    return app