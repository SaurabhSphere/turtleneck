"""
API Router
==========
All REST endpoints for the Turtleneck Phishing Detection API.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List

from .database import get_db
from .schemas import (
    DomainPredictRequest,
    DomainPredictResponse,
    BatchPredictRequest,
    BatchPredictResponse,
    StatsResponse,
    ReportMistakeRequest,
    GenericMessageResponse,
)
from . import services
from .train import run_training
from .features import is_valid_url_or_domain

router = APIRouter(prefix="/api")


@router.post("/predict", response_model=DomainPredictResponse)
def predict(request: DomainPredictRequest, db: Session = Depends(get_db)):
    """Classify a single domain as phishing or legitimate."""
    domain = request.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain name cannot be empty")
    if not is_valid_url_or_domain(domain):
        raise HTTPException(status_code=400, detail="Please enter a valid URL or domain.")

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

    valid_domains = [d for d in request.domains if is_valid_url_or_domain(d)]
    if not valid_domains:
        raise HTTPException(status_code=400, detail="Domain list must contain at least one valid URL or domain.")

    try:
        predictions = services.run_batch_prediction(valid_domains, db)
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


@router.post("/report", response_model=GenericMessageResponse)
def report_mistake(request: ReportMistakeRequest, db: Session = Depends(get_db)):
    """Report a misclassified domain to be used for future model retraining."""
    if not request.domain.strip() or request.corrected_label not in ["legitimate", "phishing"]:
        raise HTTPException(status_code=400, detail="Invalid domain or label.")
    
    try:
        services.save_reported_mistake(request.domain, request.corrected_label, db)
        return GenericMessageResponse(message=f"Successfully flagged {request.domain} as {request.corrected_label} for Active Learning.")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to save report: {str(e)}")


@router.post("/retrain", response_model=GenericMessageResponse)
def trigger_retrain(background_tasks: BackgroundTasks):
    """Trigger the XGBoost active learning pipeline in the background."""
    background_tasks.add_task(run_training)
    return GenericMessageResponse(message="Model retraining initiated in the background. This will take a few minutes.")
