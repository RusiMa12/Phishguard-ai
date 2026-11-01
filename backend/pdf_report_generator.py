"""
pdf_report_generator.py
-----------------------
Pure-Python SOC Forensic Dossier & Threat Assessment PDF Generator for PhishGuard AI.
Zero external dependencies (no reportlab required) - generates standard PDF 1.4.
Designed for automated export via Telegram Bot and Web API.
"""

import os
import sys
import time
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional


class PDFCanvas:
    """A lightweight, zero-dependency PDF 1.4 canvas and stream builder."""

    def __init__(self, width: float = 595.28, height: float = 841.89):
        self.width = width
        self.height = height
        self.stream: List[str] = []

    def set_fill_rgb(self, r: float, g: float, b: float):
        self.stream.append(f"{r:.3f} {g:.3f} {b:.3f} rg")

    def set_stroke_rgb(self, r: float, g: float, b: float):
        self.stream.append(f"{r:.3f} {g:.3f} {b:.3f} RG")

    def rect(self, x: float, y: float, w: float, h: float, fill: bool = True, stroke: bool = False, stroke_w: float = 1.0):
        cmds = ["q"]
        if stroke:
            cmds.append(f"{stroke_w:.2f} w")
        cmds.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re")
        if fill and stroke:
            cmds.append("B")
        elif fill:
            cmds.append("f")
        elif stroke:
            cmds.append("S")
        cmds.append("Q")
        self.stream.append(" ".join(cmds))

    def line(self, x1: float, y1: float, x2: float, y2: float, stroke_w: float = 1.0):
        cmd = f"q {stroke_w:.2f} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S Q"
        self.stream.append(cmd)

    def text(self, s: str, x: float, y: float, font: str = "/F1", size: float = 10.0, r: float = 0.0, g: float = 0.0, b: float = 0.0):
        # Escape string for PDF literal
        # Replace non-ascii chars to safe representation
        clean = ""
        for ch in str(s):
            code = ord(ch)
            if code == 92:  # \
                clean += "\\\\"
            elif code == 40:  # (
                clean += "\\("
            elif code == 41:  # )
                clean += "\\)"
            elif 32 <= code <= 126:
                clean += ch
            elif ch == "—" or ch == "–":
                clean += "-"
            elif ch == "“" or ch == "”" or ch == "\"":
                clean += "'"
            elif ch == "‘" or ch == "’":
                clean += "'"
            elif ch == "•":
                clean += "*"
            else:
                clean += "?"

        cmd = f"q {r:.3f} {g:.3f} {b:.3f} rg BT {font} {size:.2f} Tf 1 0 0 1 {x:.2f} {y:.2f} Tm ({clean}) Tj ET Q"
        self.stream.append(cmd)

    def build_pdf_bytes(self) -> bytes:
        content = "\n".join(self.stream).encode("latin-1", "replace")
        
        objects = [
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
            b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
            f"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.width:.2f} {self.height:.2f}] /Resources << /Font << /F1 4 0 R /F2 5 0 R /F3 6 0 R >> >> /Contents 7 0 R >> endobj\n".encode("latin-1"),
            b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
            b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> endobj\n",
            b"6 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Courier >> endobj\n",
            f"7 0 obj << /Length {len(content)} >> stream\n".encode("latin-1") + content + b"\nendstream\nendobj\n"
        ]

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for obj in objects:
            offsets.append(len(out))
            out.extend(obj)
        
        xref_pos = len(out)
        out.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("latin-1"))
        for off in offsets[1:]:
            out.extend(f"{off:010d} 00000 n \n".encode("latin-1"))
        
        out.extend(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("latin-1"))
        return bytes(out)


def generate_soc_pdf_report(
    scan_type: str,
    target_data: Dict[str, Any],
    output_path: Optional[str] = None
) -> bytes:
    """
    Generates a full-featured single-page SOC Forensic Dossier PDF for a scan.
    
    :param scan_type: 'URL', 'EXE', or 'APK'
    :param target_data: The output dictionary from the analyzer
    :param output_path: Optional file path to save the PDF
    :return: PDF document bytes
    """
    canvas = PDFCanvas(595.28, 841.89)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_id = f"PG-SOC-{hashlib.md5(f'{now_str}_{scan_type}'.encode()).hexdigest()[:8].upper()}"

    # Extract common fields
    risk_score = target_data.get("risk_score") or target_data.get("final_score") or 0
    risk_level = (target_data.get("risk_level") or "UNKNOWN").upper()
    classification = target_data.get("classification") or "Unknown"

    # Color themes based on Risk Level
    # RGB tuples (0.0 to 1.0)
    if risk_level in ("CRITICAL", "HIGH"):
        badge_bg = (0.78, 0.15, 0.15)      # Deep Red
        badge_border = (0.95, 0.25, 0.25)
        gauge_color = (0.90, 0.20, 0.20)
    elif risk_level == "MEDIUM":
        badge_bg = (0.85, 0.55, 0.10)      # Amber / Orange
        badge_border = (0.95, 0.65, 0.15)
        gauge_color = (0.90, 0.60, 0.15)
    else:
        badge_bg = (0.12, 0.62, 0.35)      # Forest Green / Safe
        badge_border = (0.20, 0.75, 0.45)
        gauge_color = (0.15, 0.70, 0.40)

    # 1. Background Canvas Setup
    canvas.set_fill_rgb(0.96, 0.97, 0.98)
    canvas.rect(0, 0, 595.28, 841.89, fill=True, stroke=False)

    # 2. Top Header Bar (Dark Navy SOC Banner)
    canvas.set_fill_rgb(0.06, 0.10, 0.18)
    canvas.rect(25, 755, 545.28, 65, fill=True, stroke=False)
    
    # Accent cyan line under header
    canvas.set_stroke_rgb(0.15, 0.65, 0.95)
    canvas.line(25, 755, 570.28, 755, stroke_w=2.5)

    # Header Texts
    canvas.text("PHISHGUARD AI  |  CYBERSECURITY SOC LABS", 42, 795, font="/F2", size=14, r=0.95, g=0.98, b=1.0)
    canvas.text("AUTONOMOUS THREAT INTELLIGENCE & FORENSIC DOSSIER", 42, 778, font="/F1", size=8.5, r=0.55, g=0.75, b=0.95)
    canvas.text(f"REPORT ID: {report_id}", 415, 797, font="/F3", size=8.5, r=0.85, g=0.90, b=0.95)
    canvas.text(f"GENERATED: {now_str} (Tashkent)", 360, 778, font="/F1", size=7.5, r=0.65, g=0.75, b=0.85)

    # 3. Target Metadata Card (Top left)
    canvas.set_fill_rgb(1.0, 1.0, 1.0)
    canvas.set_stroke_rgb(0.85, 0.88, 0.92)
    canvas.rect(25, 655, 365, 88, fill=True, stroke=True, stroke_w=1.0)

    # Target card title
    canvas.text("INCIDENT ARTIFACT / TARGET DETAILS", 37, 726, font="/F2", size=9, r=0.20, g=0.25, b=0.35)
    canvas.set_stroke_rgb(0.88, 0.90, 0.94)
    canvas.line(37, 720, 375, 720, stroke_w=0.8)

    # Details rows based on scan_type
    if scan_type.upper() == "URL":
        target_name = target_data.get("url") or "Unknown URL"
        if len(target_name) > 48:
            target_name = target_name[:45] + "..."
        hostname = (target_data.get("features") or {}).get("hostname") or "N/A"
        ml_prob = target_data.get("ml_probability")
        ml_txt = f"{ml_prob * 100:.1f}%" if ml_prob is not None else "Model Baseline (70%)"

        canvas.text("Artifact Type:", 37, 704, font="/F2", size=8, r=0.40, g=0.45, b=0.55)
        canvas.text("Web URL / Hyperlink", 115, 704, font="/F1", size=8, r=0.10, g=0.15, b=0.25)
        canvas.text("Target URL:", 37, 688, font="/F2", size=8, r=0.40, g=0.45, b=0.55)
        canvas.text(target_name, 115, 688, font="/F3", size=7.5, r=0.10, g=0.35, b=0.75)
        canvas.text("Target Host:", 37, 672, font="/F2", size=8, r=0.40, g=0.45, b=0.55)
        canvas.text(f"{hostname}  |  ML Phish Prob: {ml_txt}", 115, 672, font="/F1", size=7.5, r=0.20, g=0.25, b=0.35)

    elif scan_type.upper() == "EXE":
        target_name = target_data.get("filename") or "sample.exe"
        sha256 = target_data.get("sha256") or "N/A"
        size_kb = (target_data.get("file_size_bytes") or 0) / 1024

        canvas.text("Artifact Type:", 37, 704, font="/F2", size=8, r=0.40, g=0.45, b=0.55)
        canvas.text("Portable Executable (PE32 / Windows EXE)", 115, 704, font="/F1", size=8, r=0.10, g=0.15, b=0.25)
        canvas.text("Binary File:", 37, 688, font="/F2", size=8, r=0.40, g=0.45, b=0.55)
        canvas.text(f"{target_name} ({size_kb:.1f} KB)", 115, 688, font="/F3", size=7.5, r=0.10, g=0.35, b=0.75)
        canvas.text("SHA-256 Hash:", 37, 672, font="/F2", size=8, r=0.40, g=0.45, b=0.55)
        canvas.text(sha256[:44] + "...", 115, 672, font="/F3", size=7, r=0.25, g=0.30, b=0.40)

    else:  # APK
        target_name = target_data.get("filename") or "app.apk"
        pkg_name = target_data.get("package_name") or "Unknown Package"
        sha256 = target_data.get("sha256") or "N/A"
        size_mb = (target_data.get("file_size_bytes") or 0) / (1024 * 1024)

        canvas.text("Artifact Type:", 37, 704, font="/F2", size=8, r=0.40, g=0.45, b=0.55)
        canvas.text("Android Application Package (APK)", 115, 704, font="/F1", size=8, r=0.10, g=0.15, b=0.25)
        canvas.text("Package ID:", 37, 688, font="/F2", size=8, r=0.40, g=0.45, b=0.55)
        canvas.text(f"{pkg_name} ({size_mb:.1f} MB)", 115, 688, font="/F3", size=7.5, r=0.10, g=0.35, b=0.75)
        canvas.text("SHA-256 Hash:", 37, 672, font="/F2", size=8, r=0.40, g=0.45, b=0.55)
        canvas.text(sha256[:44] + "...", 115, 672, font="/F3", size=7, r=0.25, g=0.30, b=0.40)

    # 4. Threat Score Gauge Box (Top right)
    canvas.set_fill_rgb(1.0, 1.0, 1.0)
    canvas.set_stroke_rgb(0.85, 0.88, 0.92)
    canvas.rect(400, 655, 170.28, 88, fill=True, stroke=True, stroke_w=1.0)

    # Threat Score Badge Banner
    canvas.set_fill_rgb(badge_bg[0], badge_bg[1], badge_bg[2])
    canvas.rect(400, 719, 170.28, 24, fill=True, stroke=False)
    canvas.text("SOC THREAT LEVEL", 435, 727, font="/F2", size=9, r=1.0, g=1.0, b=1.0)

    # Score Big Digits
    canvas.text(f"{int(risk_score)}", 430, 682, font="/F2", size=32, r=gauge_color[0], g=gauge_color[1], b=gauge_color[2])
    canvas.text("/ 100", 478, 686, font="/F1", size=11, r=0.50, g=0.55, b=0.60)
    
    # Verdict Label
    canvas.text(f"{risk_level} - {classification.upper()}", 412, 664, font="/F2", size=8, r=gauge_color[0], g=gauge_color[1], b=gauge_color[2])

    # 5. Multi-Layer Detection Summary Table
    canvas.set_fill_rgb(1.0, 1.0, 1.0)
    canvas.set_stroke_rgb(0.85, 0.88, 0.92)
    canvas.rect(25, 570, 545.28, 72, fill=True, stroke=True, stroke_w=1.0)

    canvas.text("MULTI-VECTOR HYBRID ENGINE VERIFICATION", 37, 627, font="/F2", size=9, r=0.20, g=0.25, b=0.35)
    canvas.set_stroke_rgb(0.88, 0.90, 0.94)
    canvas.line(37, 621, 560, 621, stroke_w=0.8)

    # 3 verification columns: Rule-based Heuristics | ML Classifier | VirusTotal Threat Intel
    # Column 1: Static / Rule Heuristics
    rule_score = target_data.get("rule_score") or target_data.get("static_risk_score") or 0
    canvas.text("1. Heuristic Forensics:", 37, 604, font="/F2", size=8, r=0.35, g=0.40, b=0.50)
    canvas.text(f"Score: {rule_score}/100", 37, 588, font="/F1", size=8, r=0.10, g=0.15, b=0.20)

    # Column 2: Machine Learning
    ml_verdict = target_data.get("ml_classification") or "Active"
    ml_prob = target_data.get("ml_probability")
    ml_score_text = f"{ml_prob * 100:.1f}% Probability" if ml_prob is not None else "Ensemble Mode"
    canvas.text("2. Machine Learning Model:", 210, 604, font="/F2", size=8, r=0.35, g=0.40, b=0.50)
    canvas.text(f"{ml_verdict} ({ml_score_text})", 210, 588, font="/F1", size=8, r=0.10, g=0.15, b=0.20)

    # Column 3: VirusTotal Intelligence
    vt_data = target_data.get("virustotal") or {}
    vt_status = vt_data.get("status") or "not_found"
    vt_mal = vt_data.get("malicious_count", 0)
    vt_total = vt_data.get("total_engines", 0)
    if vt_status == "ok" and vt_total > 0:
        vt_txt = f"{vt_mal} / {vt_total} Engines Flagged"
    elif vt_status == "not_configured":
        vt_txt = "Local Engine Active (No VT Key)"
    else:
        vt_txt = "Clean / Zero Prior Flags"

    canvas.text("3. Threat Intel (VirusTotal):", 390, 604, font="/F2", size=8, r=0.35, g=0.40, b=0.50)
    canvas.text(vt_txt, 390, 588, font="/F1", size=8, r=0.10, g=0.15, b=0.20)

    # 6. Explainable AI (XAI) & Attribution Box
    canvas.set_fill_rgb(1.0, 1.0, 1.0)
    canvas.set_stroke_rgb(0.85, 0.88, 0.92)
    canvas.rect(25, 420, 545.28, 138, fill=True, stroke=True, stroke_w=1.0)

    canvas.text("EXPLAINABLE AI (XAI) & MITRE ATT&CK FORENSIC BREAKDOWN", 37, 542, font="/F2", size=9, r=0.20, g=0.25, b=0.35)
    canvas.text("Transparent feature attribution showing exactly which indicators determined the verdict", 37, 531, font="/F1", size=7.5, r=0.50, g=0.55, b=0.65)
    canvas.set_stroke_rgb(0.88, 0.90, 0.94)
    canvas.line(37, 524, 560, 524, stroke_w=0.8)

    # Gather Indicators and Reasons
    indicators = target_data.get("reasons") or target_data.get("indicators") or []
    xai_data = target_data.get("xai_analysis") or []
    if isinstance(xai_data, dict):
        top_features = xai_data.get("top_contributing_features") or []
    elif isinstance(xai_data, list):
        top_features = xai_data
    else:
        top_features = []

    y_pos = 508
    if not indicators and not top_features:
        canvas.text("- No anomalous patterns detected. All inspected features reside within baseline parameters.", 45, y_pos, font="/F1", size=8, r=0.15, g=0.55, b=0.25)
    else:
        # Show up to 4 key indicators / XAI factors
        shown = 0
        if top_features:
            for feat in top_features[:4]:
                feat_name = feat.get("name_en") or feat.get("description") or feat.get("feature") or "Heuristic"
                reason_desc = feat.get("reason_en") or feat.get("description") or feat.get("value_display") or feat_name
                pct = feat.get("impact_pct")
                if pct is not None:
                    impact = f"+{pct}%" if feat.get("direction") == "RISK" else f"-{pct}%"
                else:
                    weight = feat.get("weight") or feat.get("contribution") or 0.0
                    impact = f"+{weight * 100:.0f}%" if weight > 0 else f"{weight * 100:.0f}%"

                is_risk = feat.get("direction", "RISK") == "RISK"
                canvas.text(
                    f"* [{impact}] {feat_name}: {reason_desc}"[:105],
                    45, y_pos,
                    font="/F2" if is_risk else "/F1",
                    size=7.5,
                    r=0.75 if is_risk else 0.15,
                    g=0.15 if is_risk else 0.55,
                    b=0.15 if is_risk else 0.25
                )
                y_pos -= 16
                shown += 1

        for ind in indicators:
            if shown >= 5:
                break
            # Skip if duplicate or already covered
            if any(str(ind).lower() in str(f.get("name_en", "")).lower() for f in top_features):
                continue
            canvas.text(f"* {str(ind)}"[:105], 45, y_pos, font="/F1", size=7.5, r=0.25, g=0.30, b=0.40)
            y_pos -= 16
            shown += 1

    # 7. Positive Safety Signals & Integrity Verification
    canvas.set_fill_rgb(1.0, 1.0, 1.0)
    canvas.set_stroke_rgb(0.85, 0.88, 0.92)
    canvas.rect(25, 290, 545.28, 118, fill=True, stroke=True, stroke_w=1.0)

    canvas.text("DEFENSIVE SIGNALS & REPUTATION BASELINE", 37, 393, font="/F2", size=9, r=0.20, g=0.25, b=0.35)
    canvas.set_stroke_rgb(0.88, 0.90, 0.94)
    canvas.line(37, 386, 560, 386, stroke_w=0.8)

    pos_signals = target_data.get("positive_signals") or []
    y_pos = 370
    if pos_signals:
        for sig in pos_signals[:4]:
            canvas.text(f"+ [BENIGN] {str(sig)[:90]}", 45, y_pos, font="/F1", size=7.5, r=0.12, g=0.50, b=0.25)
            y_pos -= 16
    else:
        canvas.text("- Standard system parameters; no additional high-trust reputation anchors found.", 45, y_pos, font="/F1", size=7.5, r=0.45, g=0.50, b=0.55)

    # 8. SOC Analyst Containment Recommendations
    canvas.set_fill_rgb(1.0, 1.0, 1.0)
    canvas.set_stroke_rgb(0.85, 0.88, 0.92)
    canvas.rect(25, 120, 545.28, 158, fill=True, stroke=True, stroke_w=1.0)

    canvas.text("RECOMMENDED MITIGATION & INCIDENT RESPONSE PLAYBOOK", 37, 263, font="/F2", size=9, r=0.20, g=0.25, b=0.35)
    canvas.set_stroke_rgb(0.88, 0.90, 0.94)
    canvas.line(37, 256, 560, 256, stroke_w=0.8)

    recs = target_data.get("recommendations") or [
        "Continue exercising standard cyber hygiene.",
        "Ensure enterprise endpoint detection and response (EDR) is active."
    ]
    y_pos = 240
    for rec in recs[:5]:
        canvas.text(f"> {rec}", 45, y_pos, font="/F1", size=8, r=0.15, g=0.20, b=0.30)
        y_pos -= 16

    canvas.set_stroke_rgb(0.90, 0.92, 0.95)
    canvas.line(45, 160, 550, 160, stroke_w=0.8)

    # Legal / Academic disclaimer inside box
    canvas.text("CERTIFICATION: Generated automatically by PhishGuard AI Unified Detection System.", 45, 142, font="/F2", size=7.5, r=0.30, g=0.35, b=0.45)
    canvas.text("Designed for thesis research, enterprise SOC triage, and real-time defensive operations.", 45, 128, font="/F1", size=7, r=0.50, g=0.55, b=0.60)

    # 9. Bottom Footer & Verification Seal
    canvas.set_stroke_rgb(0.80, 0.83, 0.88)
    canvas.line(25, 65, 570.28, 65, stroke_w=1.0)

    canvas.text("PHISHGUARD AI v2.4", 25, 50, font="/F2", size=8, r=0.20, g=0.25, b=0.35)
    canvas.text("Certified Static PE/APK Reverse Engineering & Gradient Boosted URL Threat Intelligence", 25, 38, font="/F1", size=7, r=0.50, g=0.55, b=0.60)
    canvas.text("Confidential SOC Incident Report | Page 1 of 1", 390, 50, font="/F1", size=7.5, r=0.45, g=0.50, b=0.55)

    pdf_bytes = canvas.build_pdf_bytes()

    if output_path:
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes


if __name__ == "__main__":
    # Test generation with sample mock data
    mock_url_data = {
        "url": "https://secure-login.paypal-verification.com/login.php?token=x8921a",
        "risk_score": 88,
        "risk_level": "CRITICAL",
        "classification": "Phishing",
        "rule_score": 82,
        "ml_probability": 0.94,
        "ml_classification": "Phishing",
        "features": {"hostname": "secure-login.paypal-verification.com"},
        "reasons": [
            "Punycode/Spoofed PayPal brand keyword in subdomain",
            "Suspicious hyphenation count in domain (> 2 hyphens)",
            "High token entropy in query parameters"
        ],
        "positive_signals": ["Valid HTTPS structure present"],
        "recommendations": [
            "Do not enter any personal credentials or banking passwords.",
            "Block this domain at firewall / DNS perimeter immediately.",
            "Report the spoofing link to CERT-UZ and brand abuse channels."
        ],
        "virustotal": {"status": "ok", "malicious_count": 14, "total_engines": 72},
        "xai_analysis": {
            "top_contributing_features": [
                {"feature": "brand_in_subdomain", "description": "PayPal keyword impersonation", "weight": 0.38},
                {"feature": "hyphen_count", "description": "Excessive hyphens (spoofing indicator)", "weight": 0.22},
                {"feature": "url_length", "description": "Unusually long authentication path", "weight": 0.15}
            ]
        }
    }

    test_file = "test_soc_report.pdf"
    generate_soc_pdf_report("URL", mock_url_data, test_file)
    print(f"Generated test PDF: {test_file} ({os.path.getsize(test_file)} bytes)")
