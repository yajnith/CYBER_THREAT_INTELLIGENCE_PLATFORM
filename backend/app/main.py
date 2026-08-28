from fastapi import FastAPI
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