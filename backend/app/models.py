from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from datetime import datetime
from .database import Base

class DomainScan(Base):
    __tablename__ = "domain_scans"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, nullable=False, index=True)
    label = Column(String, nullable=False)  # "legitimate" or "phishing"
    confidence = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    features_json = Column(JSON, nullable=False)
