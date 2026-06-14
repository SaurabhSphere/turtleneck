"""
Turtleneck Phishing Detection API
==================================
FastAPI application entry point.  All route handlers live in routers.py;
business logic lives in services.py.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import engine, Base
from .routers import router

# Create database tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Turtleneck Phishing Detection API",
    description="REST API for real-time phishing and suspected domain classification using XGBoost.",
    version="2.0.0",
)

# CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://turtleneckai.netlify.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "Turtleneck Phishing Detection API is running!"}


# Mount all /api/* routes
app.include_router(router)
