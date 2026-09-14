"""Education & Interactive Training Router"""
from typing import List, Dict, Any
from fastapi import APIRouter
from backend.engines.education_engine import get_education_tips, get_interactive_scenarios

router = APIRouter(prefix="/api/v1/education", tags=["Education"])

@router.get("/tips")
def list_tips() -> List[Dict[str, Any]]:
    """Fetch cybersecurity guidance and prevention rules"""
    return get_education_tips()

@router.get("/scenarios")
def list_scenarios() -> List[Dict[str, Any]]:
    """Fetch interactive 'Spot the Scam' challenges"""
    return get_interactive_scenarios()
