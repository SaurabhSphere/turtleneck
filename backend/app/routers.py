"""
API Router
==========
All REST endpoints for the Turtleneck Phishing Detection API.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from .database import get_db
from .schemas import (
    DomainPredictRequest,
    DomainPredictResponse,
    BatchPredictRequest,
    BatchPredictResponse,
    StatsResponse,
)
from . import services

router = APIRouter(prefix="/api")


@router.post("/predict", response_model=DomainPredictResponse)
def predict(request: DomainPredictRequest, db: Session = Depends(get_db)):
    """Classify a single domain as phishing or legitimate."""
    domain = request.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain name cannot be empty")

    try:
        return services.run_single_prediction(domain, db)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")


@router.post("/predict/batch", response_model=BatchPredictResponse)
def predict_batch(request: BatchPredictRequest, db: Session = Depends(get_db)):
    """Classify a batch of domains in a single request."""
    if not request.domains:
        raise HTTPException(status_code=400, detail="Domain list cannot be empty")

    try:
        predictions = services.run_batch_prediction(request.domains, db)
        return BatchPredictResponse(predictions=predictions)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Batch processing error: {str(e)}")


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    """Return aggregate scan statistics."""
    try:
        stats = services.get_aggregate_stats(db)
        return StatsResponse(**stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stats error: {str(e)}")


@router.get("/history", response_model=List[DomainPredictResponse])
def get_history(limit: int = 50, db: Session = Depends(get_db)):
    """Return the most recent scan log entries."""
    try:
        return services.get_scan_history(db, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"History error: {str(e)}")
