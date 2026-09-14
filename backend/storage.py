"""In-Memory Storage for Scan History and Security Stats (No Database Required)"""
import threading
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

_lock = threading.Lock()
_scan_history: List[Dict[str, Any]] = []
_next_scan_id: int = 1

def add_scan_record(
    scan_type: str,
    snippet: str,
    result: Dict[str, Any],
    privacy_mode: bool = False
) -> Optional[Dict[str, Any]]:
    """Adds a scan to in-memory session history if privacy mode is disabled"""
    global _next_scan_id
    if privacy_mode:
        return None

    with _lock:
        rec = {
            "id": _next_scan_id,
            "scan_type": scan_type,
            "input_snippet": snippet[:250],
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "category": result["category"],
            "confidence": result.get("confidence", 0.9),
            "findings": result.get("findings", []),
            "recommendation": result.get("recommendation", ""),
            "created_at": datetime.now(timezone.utc)
        }
        _next_scan_id += 1
        _scan_history.insert(0, rec)
        # Cap memory to latest 500 scans
        if len(_scan_history) > 500:
            _scan_history.pop()
        return rec

def get_scan_history(limit: int = 50, offset: int = 0, scan_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves paginated scan history from memory"""
    with _lock:
        items = _scan_history
        if scan_type:
            items = [r for r in items if r["scan_type"] == scan_type.upper()]
        return items[offset:offset + limit]

def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Fetches a specific scan record by ID"""
    with _lock:
        for r in _scan_history:
            if r["id"] == scan_id:
                return r
        return None

def delete_scan_by_id(scan_id: int) -> bool:
    """Deletes a specific scan record from memory"""
    global _scan_history
    with _lock:
        initial_len = len(_scan_history)
        _scan_history = [r for r in _scan_history if r["id"] != scan_id]
        return len(_scan_history) < initial_len

def clear_scan_history() -> int:
    """Clears all scan history from memory"""
    global _scan_history
    with _lock:
        count = len(_scan_history)
        _scan_history = []
        return count

def get_stats() -> Dict[str, Any]:
    """Calculates threat statistics from in-memory scans"""
    from collections import Counter
    with _lock:
        records = list(_scan_history)

    total = len(records)
    if total == 0:
        return {
            "total_scans": 0,
            "high_risk_count": 0,
            "suspicious_count": 0,
            "safe_count": 0,
            "avg_risk_score": 0.0,
            "top_categories": {}
        }

    high_count = sum(1 for r in records if r["risk_level"] == "HIGH")
    suspicious_count = sum(1 for r in records if r["risk_level"] == "SUSPICIOUS")
    safe_count = sum(1 for r in records if r["risk_level"] == "SAFE")
    avg_score = sum(r["risk_score"] for r in records) / total

    category_counts = Counter(r["category"] for r in records if r["category"] != "SAFE")
    top_cats = dict(category_counts.most_common(5))

    return {
        "total_scans": total,
        "high_risk_count": high_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "avg_risk_score": round(avg_score, 1),
        "top_categories": top_cats
    }
