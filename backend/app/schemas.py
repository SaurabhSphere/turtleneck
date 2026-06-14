from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any
from datetime import datetime


class DomainPredictRequest(BaseModel):
    domain: str = Field(..., examples=["example-login.tk"])


class DomainPredictResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    domain: str
    label: str
    confidence: float
    timestamp: datetime
    features: Dict[str, Any]
    additional_indicators: Dict[str, Any]


class BatchPredictRequest(BaseModel):
    domains: List[str] = Field(..., examples=[["google.com", "example-login.tk"]])


class BatchPredictResponse(BaseModel):
    predictions: List[DomainPredictResponse]


class StatsResponse(BaseModel):
    total_scanned: int
    label_counts: Dict[str, int]
    top_risky_tlds: List[Dict[str, Any]]


class ReportMistakeRequest(BaseModel):
    domain: str = Field(..., examples=["example.com"])
    corrected_label: str = Field(..., examples=["legitimate", "phishing"])


class GenericMessageResponse(BaseModel):
    message: str
