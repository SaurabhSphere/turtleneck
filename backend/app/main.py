from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List
from datetime import datetime
from collections import Counter

from .database import engine, Base, get_db
from .models import DomainScan
from .schemas import (
    DomainPredictRequest,
    DomainPredictResponse,
    BatchPredictRequest,
    BatchPredictResponse,
    StatsResponse
)
from .inference import predict_domain

# Create database tables if they do not exist
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Turtleneck Phishing Detection API",
    description="REST API for real-time phishing and suspected domain classification using XGBoost.",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Turtleneck Phishing Detection API is running!"}

@app.post("/api/predict", response_model=DomainPredictResponse)
def predict(request: DomainPredictRequest, db: Session = Depends(get_db)):
    domain = request.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain name cannot be empty")
    
    try:
        # Run ML Inference
        result = predict_domain(domain)
        
        # Save to database
        db_scan = DomainScan(
            domain=result["domain"],
            label=result["label"],
            confidence=result["confidence"],
            features_json=result["features"]
        )
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)
        
        return DomainPredictResponse(
            domain=result["domain"],
            label=result["label"],
            confidence=result["confidence"],
            timestamp=db_scan.timestamp,
            features=result["features"],
            additional_indicators=result["additional_indicators"]
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Inference/Database error: {str(e)}")

@app.post("/api/predict/batch", response_model=BatchPredictResponse)
def predict_batch(request: BatchPredictRequest, db: Session = Depends(get_db)):
    if not request.domains:
        raise HTTPException(status_code=400, detail="Domain list cannot be empty")
    
    predictions = []
    try:
        db_scans = []
        for domain in request.domains:
            domain = domain.strip()
            if not domain:
                continue
            
            result = predict_domain(domain)
            db_scan = DomainScan(
                domain=result["domain"],
                label=result["label"],
                confidence=result["confidence"],
                features_json=result["features"]
            )
            db_scans.append(db_scan)
            
            # Prepare response item
            predictions.append(
                DomainPredictResponse(
                    domain=result["domain"],
                    label=result["label"],
                    confidence=result["confidence"],
                    timestamp=datetime.utcnow(),  # Will be updated by DB commit time
                    features=result["features"],
                    additional_indicators=result["additional_indicators"]
                )
            )
        
        # Bulk save
        if db_scans:
            db.add_all(db_scans)
            db.commit()
            
            # Align timestamps with DB records
            for idx, scan in enumerate(db_scans):
                db.refresh(scan)
                predictions[idx].timestamp = scan.timestamp
                
        return BatchPredictResponse(predictions=predictions)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Batch processing error: {str(e)}")

@app.get("/api/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    try:
        # Total scanned count
        total = db.query(DomainScan).count()
        
        # Label counts
        labels_query = db.query(DomainScan.label, func.count(DomainScan.id)).group_by(DomainScan.label).all()
        label_counts = {label: count for label, count in labels_query}
        
        # Ensure default labels are present
        if "legitimate" not in label_counts:
            label_counts["legitimate"] = 0
        if "phishing" not in label_counts:
            label_counts["phishing"] = 0
            
        # Top risky TLDs (based on domains labeled as phishing)
        phishing_scans = db.query(DomainScan.domain).filter(DomainScan.label == "phishing").all()
        
        tld_counter = Counter()
        for (domain,) in phishing_scans:
            parts = domain.split('.')
            if len(parts) > 1:
                tld = parts[-1].lower()
                tld_counter[tld] += 1
        
        top_risky_tlds = [
            {"tld": tld, "count": count}
            for tld, count in tld_counter.most_common(5)
        ]
        
        return StatsResponse(
            total_scanned=total,
            label_counts=label_counts,
            top_risky_tlds=top_risky_tlds
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database aggregation error: {str(e)}")

@app.get("/api/history", response_model=List[DomainPredictResponse])
def get_history(limit: int = 50, db: Session = Depends(get_db)):
    try:
        scans = db.query(DomainScan).order_by(DomainScan.timestamp.desc()).limit(limit).all()
        history = []
        for scan in scans:
            # Reconstruct extra indicators from domain name for response compatibility
            from .features import get_additional_indicators
            extra = get_additional_indicators(scan.domain)
            
            history.append(
                DomainPredictResponse(
                    domain=scan.domain,
                    label=scan.label,
                    confidence=scan.confidence,
                    timestamp=scan.timestamp,
                    features=scan.features_json,
                    additional_indicators=extra
                )
            )
        return history
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database history retrieval error: {str(e)}")
