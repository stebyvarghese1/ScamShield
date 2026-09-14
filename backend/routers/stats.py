"""Security Statistics & Metrics Router (In-Memory / No Database)"""
from fastapi import APIRouter
from backend.models import StatsResponse
from backend.storage import get_stats

router = APIRouter(prefix="/api/v1/stats", tags=["Stats"])

@router.get("", response_model=StatsResponse)
def get_security_stats():
    """Fetch dashboard statistics and aggregate threat counts from in-memory session"""
    return get_stats()
