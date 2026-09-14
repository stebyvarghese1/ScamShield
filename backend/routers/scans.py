"""Scan History Management Router (In-Memory / No Database)"""
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from backend.models import ScanHistoryItem
from backend.storage import (
    get_scan_history,
    get_scan_by_id,
    delete_scan_by_id,
    clear_scan_history
)

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])

@router.get("", response_model=List[ScanHistoryItem])
def list_scans(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    scan_type: Optional[str] = None
):
    """Fetch paginated scan history from in-memory session"""
    records = get_scan_history(limit=limit, offset=offset, scan_type=scan_type)

    items = []
    for r in records:
        created_dt = r.get("created_at")
        formatted_date = created_dt.strftime("%b %d, %Y %H:%M") if created_dt else "Just now"
        items.append(ScanHistoryItem(
            id=r["id"],
            scan_type=r["scan_type"],
            input_snippet=r["input_snippet"],
            risk_score=r["risk_score"],
            risk_level=r["risk_level"],
            category=r["category"],
            created_at=formatted_date,
            findings_count=len(r.get("findings", []))
        ))
    return items

@router.get("/{scan_id}")
def get_scan_details(scan_id: int):
    """Fetch detailed findings for a previous scan from in-memory session"""
    record = get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")

    created_dt = record.get("created_at")
    return {
        "id": record["id"],
        "scan_type": record["scan_type"],
        "input_snippet": record["input_snippet"],
        "risk_score": record["risk_score"],
        "risk_level": record["risk_level"],
        "category": record["category"],
        "confidence": record["confidence"],
        "recommendation": record["recommendation"],
        "created_at": created_dt.isoformat() if created_dt else None,
        "findings": record.get("findings", [])
    }

@router.delete("/{scan_id}")
def delete_scan(scan_id: int):
    """Delete a single scan record from in-memory session"""
    deleted = delete_scan_by_id(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan record not found")
    return {"message": "Scan record deleted successfully", "id": scan_id}

@router.delete("")
def clear_all_scans():
    """Clears all scan history from in-memory session for complete user privacy"""
    deleted_count = clear_scan_history()
    return {"message": "All scan history cleared", "deleted_count": deleted_count}
