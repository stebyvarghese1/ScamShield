"""Pydantic Request & Response Schemas for ScamShield (Stateless / In-Memory)"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

# ==========================================
# Pydantic Schemas
# ==========================================

class FindingItem(BaseModel):
    type: str = Field(..., description="Unique code for the finding")
    title: str = Field(..., description="Human readable summary")
    severity: str = Field(..., description="high, medium, low, info")
    description: str = Field(..., description="Clear explanation of why it was flagged")
    educational_note: Optional[str] = Field(None, description="Guidance on what this tactic means")

class AnalysisResponse(BaseModel):
    risk_score: int = Field(..., ge=0, le=100, description="Risk score from 0 to 100")
    risk_level: str = Field(..., description="SAFE, SUSPICIOUS, HIGH")
    category: str = Field(..., description="Scam taxonomy classification")
    confidence: float = Field(..., ge=0.0, le=1.0)
    findings: List[FindingItem] = Field(default_factory=list)
    recommendation: str = Field(..., description="Direct, actionable guidance")
    educational_tip: Optional[str] = None
    analyzed_target: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

class URLAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, description="URL or domain to analyze")
    privacy_mode: bool = Field(False, description="If true, do not store scan in history")

class MessageAnalyzeRequest(BaseModel):
    message: str = Field(..., min_length=1, description="Text message or SMS to inspect")
    privacy_mode: bool = Field(False, description="If true, do not store scan in history")

class EmailAnalyzeRequest(BaseModel):
    sender: Optional[str] = Field(None, description="Sender email or From header")
    reply_to: Optional[str] = Field(None, description="Reply-to header if available")
    subject: Optional[str] = Field(None, description="Email subject line")
    body: Optional[str] = Field(None, description="Email text body")
    raw_email: Optional[str] = Field(None, description="Pasted raw email headers/body")
    privacy_mode: bool = Field(False, description="If true, do not store scan in history")

class QRAnalyzeRequest(BaseModel):
    payload: str = Field(..., min_length=1, description="Decoded QR text or destination URL")
    privacy_mode: bool = Field(False, description="If true, do not store scan in history")

class ImageAnalyzeRequest(BaseModel):
    extracted_text: Optional[str] = Field(None, description="OCR text extracted from image")
    image_name: Optional[str] = Field(None, description="Filename or descriptor")
    privacy_mode: bool = Field(False, description="If true, do not store scan in history")

class ScanHistoryItem(BaseModel):
    id: int
    scan_type: str
    input_snippet: str
    risk_score: int
    risk_level: str
    category: str
    created_at: str
    findings_count: int

class StatsResponse(BaseModel):
    total_scans: int
    high_risk_count: int
    suspicious_count: int
    safe_count: int
    avg_risk_score: float
    top_categories: Dict[str, int]
