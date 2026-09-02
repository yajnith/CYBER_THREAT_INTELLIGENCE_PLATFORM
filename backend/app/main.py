from fastapi import FastAPI  # type: ignore[reportMissingImports]
from fastapi.middleware.cors import CORSMiddleware  # type: ignore[reportMissingImports]
from app.database.database import engine
from app.database.database import Base
import app.database.models

from app.api.iocs import router as ioc_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="CTIP API",
    description=(
        "AI-Powered Cyber Threat Intelligence Platform for threat "
        "collection, correlation, risk analysis and proactive cyber defense."
    ),
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ioc_router)


@app.get("/")
def root():
    return {
        "project": "CTIP",
        "full_name": "AI-Powered Cyber Threat Intelligence Platform",
        "version": "0.2.0",
        "status": "running",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }