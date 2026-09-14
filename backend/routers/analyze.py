"""API Endpoints for Threat Analysis (In-Memory / No Database)"""
from typing import Optional
from fastapi import APIRouter, UploadFile, File, Form
from backend.models import (
    URLAnalyzeRequest,
    MessageAnalyzeRequest,
    EmailAnalyzeRequest,
    QRAnalyzeRequest,
    ImageAnalyzeRequest,
    AnalysisResponse
)
from backend.storage import add_scan_record
from backend.engines.url_scanner import analyze_url
from backend.engines.message_scanner import analyze_message
from backend.engines.email_analyzer import analyze_email
from backend.engines.qr_scanner import analyze_qr_payload
from backend.engines.image_analyzer import analyze_screenshot_text, inspect_image_file
from backend.engines.risk_engine import evaluate_risk

router = APIRouter(prefix="/api/v1/analyze", tags=["Analyze"])

@router.post("/url", response_model=AnalysisResponse)
def analyze_url_endpoint(req: URLAnalyzeRequest):
    """Analyze a suspicious URL or domain"""
    url_data = analyze_url(req.url)
    res = evaluate_risk(
        base_score=url_data["score_penalty"],
        findings=url_data["findings"],
        context_text=req.url
    )
    res["analyzed_target"] = req.url
    res["details"] = {
        "hostname": url_data.get("hostname"),
        "entropy": url_data.get("entropy"),
        "threat_intel": url_data.get("threat_intel")
    }
    add_scan_record("URL", req.url, res, req.privacy_mode)
    return res

@router.post("/message", response_model=AnalysisResponse)
def analyze_message_endpoint(req: MessageAnalyzeRequest):
    """Analyze an SMS, WhatsApp, or Telegram message"""
    msg_data = analyze_message(req.message)
    res = evaluate_risk(
        base_score=msg_data["score_penalty"],
        findings=msg_data["findings"],
        context_text=req.message
    )
    snippet = req.message[:100] + ("..." if len(req.message) > 100 else "")
    res["analyzed_target"] = snippet
    res["details"] = {
        "extracted_links": msg_data.get("extracted_links", []),
        "length": msg_data.get("raw_length", 0)
    }
    add_scan_record("MESSAGE", snippet, res, req.privacy_mode)
    return res

@router.post("/email", response_model=AnalysisResponse)
def analyze_email_endpoint(req: EmailAnalyzeRequest):
    """Analyze email headers, sender address, and content"""
    eml_data = analyze_email(
        raw_email=req.raw_email,
        sender=req.sender,
        reply_to=req.reply_to,
        subject=req.subject,
        body=req.body
    )
    target_snippet = f"From: {eml_data.get('sender_email') or 'Unknown'} | Subj: {req.subject or 'No Subject'}"
    res = evaluate_risk(
        base_score=eml_data["score_penalty"],
        findings=eml_data["findings"],
        context_text=f"{req.subject or ''} {req.body or ''} {eml_data.get('display_name') or ''}"
    )
    res["analyzed_target"] = target_snippet
    res["details"] = {
        "sender_email": eml_data.get("sender_email"),
        "display_name": eml_data.get("display_name"),
        "reply_to": eml_data.get("reply_to")
    }
    add_scan_record("EMAIL", target_snippet, res, req.privacy_mode)
    return res

@router.post("/qr", response_model=AnalysisResponse)
def analyze_qr_endpoint(req: QRAnalyzeRequest):
    """Analyze decoded QR code payload or destination"""
    qr_data = analyze_qr_payload(req.payload)
    res = evaluate_risk(
        base_score=qr_data["score_penalty"],
        findings=qr_data["findings"],
        context_text=req.payload
    )
    res["analyzed_target"] = f"QR [{qr_data['payload_type']}]: {req.payload[:60]}"
    res["details"] = {
        "payload_type": qr_data.get("payload_type")
    }
    add_scan_record("QR", res["analyzed_target"], res, req.privacy_mode)
    return res

@router.post("/image", response_model=AnalysisResponse)
def analyze_image_endpoint(req: ImageAnalyzeRequest):
    """Analyze screenshot text and contextual visual patterns"""
    text = req.extracted_text or ""
    img_data = analyze_screenshot_text(text)
    res = evaluate_risk(
        base_score=img_data["score_penalty"],
        findings=img_data["findings"],
        context_text=text
    )
    target_snippet = f"Screenshot: {req.image_name or 'Uploaded Image'} ({len(text)} chars extracted)"
    res["analyzed_target"] = target_snippet
    res["details"] = {
        "screenshot_type": img_data.get("screenshot_type")
    }
    add_scan_record("SCREENSHOT", target_snippet, res, req.privacy_mode)
    return res

@router.post("/upload-image", response_model=AnalysisResponse)
async def upload_and_analyze_image(
    file: UploadFile = File(...),
    extracted_text: Optional[str] = Form(None),
    privacy_mode: Optional[bool] = Form(False)
):
    """Endpoint supporting multipart image uploads"""
    content = await file.read()
    image_meta = inspect_image_file(content)
    
    text = (extracted_text or "").strip()
    img_data = analyze_screenshot_text(text, image_meta)
    
    res = evaluate_risk(
        base_score=img_data["score_penalty"],
        findings=img_data["findings"],
        context_text=text
    )
    target_snippet = f"Image: {file.filename} ({image_meta.get('width', 0)}x{image_meta.get('height', 0)})"
    res["analyzed_target"] = target_snippet
    res["details"] = {
        "filename": file.filename,
        "image_meta": image_meta,
        "screenshot_type": img_data.get("screenshot_type")
    }
    add_scan_record("SCREENSHOT", target_snippet, res, bool(privacy_mode))
    return res
