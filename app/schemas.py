from pydantic import BaseModel, Field
from typing import List, Dict, Any
from datetime import datetime

class DomainPredictRequest(BaseModel):
    domain: str = Field(..., example="example-login.tk")

class DomainPredictResponse(BaseModel):
    domain: str
    label: str
    confidence: float
    timestamp: datetime
    features: Dict[str, Any]
    additional_indicators: Dict[str, Any]

    class Config:
        from_attributes = True

class BatchPredictRequest(BaseModel):
    domains: List[str] = Field(..., example=["google.com", "example-login.tk"])

class BatchPredictResponse(BaseModel):
    predictions: List[DomainPredictResponse]

class StatsResponse(BaseModel):
    total_scanned: int
    label_counts: Dict[str, int]
    top_risky_tlds: List[Dict[str, Any]]
