"""
Service Layer
=============
Business logic for domain prediction, separated from HTTP routing.
"""

from datetime import datetime, timezone
from collections import Counter
from sqlalchemy.orm import Session
from sqlalchemy import func

from .models import DomainScan
from .inference import predict_domain
from .features import get_additional_indicators
from .schemas import DomainPredictResponse


def run_single_prediction(domain: str, db: Session) -> DomainPredictResponse:
    """Run inference on one domain, save to DB, and return response."""
    result = predict_domain(domain)

    db_scan = DomainScan(
        domain=result["domain"],
        label=result["label"],
        confidence=result["confidence"],
        features_json=result["features"],
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
        additional_indicators=result["additional_indicators"],
    )


def run_batch_prediction(domains: list[str], db: Session) -> list[DomainPredictResponse]:
    """Run inference on multiple domains, bulk-save to DB, and return responses."""
    predictions: list[DomainPredictResponse] = []
    db_scans: list[DomainScan] = []

    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue

        result = predict_domain(domain)
        db_scan = DomainScan(
            domain=result["domain"],
            label=result["label"],
            confidence=result["confidence"],
            features_json=result["features"],
        )
        db_scans.append(db_scan)

        predictions.append(
            DomainPredictResponse(
                domain=result["domain"],
                label=result["label"],
                confidence=result["confidence"],
                timestamp=datetime.now(timezone.utc),
                features=result["features"],
                additional_indicators=result["additional_indicators"],
            )
        )

    if db_scans:
        db.add_all(db_scans)
        db.commit()
        for idx, scan in enumerate(db_scans):
            db.refresh(scan)
            predictions[idx].timestamp = scan.timestamp

    return predictions


def get_aggregate_stats(db: Session) -> dict:
    """Compute aggregate statistics from the scan history."""
    total = db.query(DomainScan).count()

    labels_query = (
        db.query(DomainScan.label, func.count(DomainScan.id))
        .group_by(DomainScan.label)
        .all()
    )
    label_counts = {label: count for label, count in labels_query}
    label_counts.setdefault("legitimate", 0)
    label_counts.setdefault("phishing", 0)

    # Top risky TLDs from phishing predictions
    phishing_scans = (
        db.query(DomainScan.domain)
        .filter(DomainScan.label == "phishing")
        .all()
    )
    tld_counter: Counter = Counter()
    for (domain,) in phishing_scans:
        parts = domain.split(".")
        if len(parts) > 1:
            tld_counter[parts[-1].lower()] += 1

    top_risky_tlds = [
        {"tld": tld, "count": count}
        for tld, count in tld_counter.most_common(5)
    ]

    return {
        "total_scanned": total,
        "label_counts": label_counts,
        "top_risky_tlds": top_risky_tlds,
    }


def get_scan_history(db: Session, limit: int = 50) -> list[DomainPredictResponse]:
    """Retrieve the most recent scan records from the database."""
    scans = (
        db.query(DomainScan)
        .order_by(DomainScan.timestamp.desc())
        .limit(limit)
        .all()
    )

    history: list[DomainPredictResponse] = []
    for scan in scans:
        extra = get_additional_indicators(scan.domain)
        history.append(
            DomainPredictResponse(
                domain=scan.domain,
                label=scan.label,
                confidence=scan.confidence,
                timestamp=scan.timestamp,
                features=scan.features_json,
                additional_indicators=extra,
            )
        )
    return history
