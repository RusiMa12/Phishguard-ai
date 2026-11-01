"""
telegram_bot.py
---------------
PhishGuard AI — Telegram SOC (Security Operations Center) Bot.
Allows real-time cyber threat detection directly from mobile devices or Telegram desktop:
  - Suspicious URL & Phishing Link Detection
  - Windows Executable (.exe) Static PE Analysis & Entropy Detection
  - Android Application (.apk) Manifest & Dangerous Permission Analysis
  - Explainable AI (XAI) Attribution & MITRE ATT&CK Mapping
  - Instant Official PDF Forensic Report Dispatch

Zero external bot framework dependencies (uses standard 'requests').
"""

import os
import sys
import time
import io
import re
import argparse
import logging
import warnings
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

# Suppress minor scikit-learn feature name mismatch warnings
warnings.filterwarnings("ignore", category=UserWarning)

# Ensure backend root is in sys.path for direct module imports
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Ensure UTF-8 output on Windows console
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from dotenv import load_dotenv
load_dotenv(BACKEND_DIR / ".env")

import requests

# Local Security Engines
from database import init_db, record_scan, get_dashboard_stats
from url_features import extract_features
from risk_engine import calculate_risk, combine_with_ml, score_to_level
from ml_url_model import predict_probability as predict_url_probability
from exe_analyzer import (
    parse_pe, compute_hashes as compute_exe_hashes, calculate_static_risk,
    combine_static_and_ml, InvalidExecutableError, MAX_FILE_SIZE as MAX_EXE_SIZE,
)
from ml_exe_model import predict_probability as predict_exe_probability
from apk_analyzer import (
    parse_apk, compute_hashes as compute_apk_hashes, calculate_static_risk as calculate_apk_static_risk,
    InvalidApkError, MAX_FILE_SIZE as MAX_APK_SIZE,
)
from services import virustotal
from risk_fusion import fuse_scores, combine_final
from xai_explainer import explain_url_decision, explain_exe_decision, explain_apk_decision
from pdf_report_generator import generate_soc_pdf_report

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("PhishGuardTelegramBot")

# Maximum file size Telegram Bot API allows downloading (20 MB)
TELEGRAM_MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024


class PhishGuardTelegramBot:
    def __init__(self, token: str):
        self.token = token.strip()
        self.api_base = f"https://api.telegram.org/bot{self.token}"
        self.file_base = f"https://api.telegram.org/file/bot{self.token}"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "PhishGuard-AI-SOC-Bot/2.4"})
        self.bot_info: Optional[Dict[str, Any]] = None

    def test_connection(self) -> bool:
        """Verifies bot token with getMe."""
        try:
            resp = self.session.get(f"{self.api_base}/getMe", timeout=10)
            data = resp.json()
            if data.get("ok"):
                self.bot_info = data["result"]
                return True
            else:
                logger.error(f"Telegram API Error: {data.get('description')}")
                return False
        except Exception as e:
            logger.error(f"Connection error to Telegram API: {e}")
            return False

    def send_chat_action(self, chat_id: int, action: str = "typing"):
        try:
            self.session.post(f"{self.api_base}/sendChatAction", data={"chat_id": chat_id, "action": action}, timeout=5)
        except Exception:
            pass

    def send_message(self, chat_id: int, text: str, reply_to_message_id: Optional[int] = None) -> Optional[int]:
        try:
            payload = {
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }
            if reply_to_message_id:
                payload["reply_to_message_id"] = reply_to_message_id

            resp = self.session.post(f"{self.api_base}/sendMessage", data=payload, timeout=15)
            data = resp.json()
            if data.get("ok"):
                return data["result"]["message_id"]
            else:
                # If HTML parsing fails, fallback to plain text
                payload.pop("parse_mode", None)
                resp = self.session.post(f"{self.api_base}/sendMessage", data=payload, timeout=15)
                return resp.json().get("result", {}).get("message_id")
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return None

    def send_document(
        self, chat_id: int, file_bytes: bytes, filename: str, caption: str = "", reply_to_message_id: Optional[int] = None
    ) -> bool:
        try:
            self.send_chat_action(chat_id, "upload_document")
            data = {
                "chat_id": chat_id,
                "caption": caption,
                "parse_mode": "HTML",
            }
            if reply_to_message_id:
                data["reply_to_message_id"] = reply_to_message_id

            files = {
                "document": (filename, io.BytesIO(file_bytes), "application/pdf")
            }
            resp = self.session.post(f"{self.api_base}/sendDocument", data=data, files=files, timeout=30)
            return resp.json().get("ok", False)
        except Exception as e:
            logger.error(f"Failed to send document: {e}")
            return False

    def download_file_bytes(self, file_id: str) -> Optional[bytes]:
        try:
            resp = self.session.get(f"{self.api_base}/getFile", params={"file_id": file_id}, timeout=10)
            data = resp.json()
            if not data.get("ok"):
                logger.error(f"getFile failed: {data.get('description')}")
                return None

            file_path = data["result"]["file_path"]
            file_url = f"{self.file_base}/{file_path}"
            dl_resp = self.session.get(file_url, timeout=45)
            if dl_resp.status_code == 200:
                return dl_resp.content
            return None
        except Exception as e:
            logger.error(f"Download file exception: {e}")
            return None

    # -------------------------------------------------------------
    # Threat Analysis Routines
    # -------------------------------------------------------------

    def analyze_url(self, raw_url: str) -> Tuple[str, bytes]:
        """Runs URL multi-vector analysis and generates response text + PDF."""
        url = raw_url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        features = extract_features(url)
        rule_result = calculate_risk(features)
        ml_probability = predict_url_probability(features)
        local = combine_with_ml(rule_result, ml_probability, features["hostname"])

        vt_result = virustotal.lookup_url(url)
        fused = fuse_scores(
            local["final_score"], local["reasons"], local["positive_signals"], vt_result, subject="URL"
        )
        final_score = fused["final_score"]
        risk_level, classification = score_to_level(final_score)

        if risk_level in ("HIGH", "CRITICAL"):
            recs = [
                "Ushbu havolaga aslo kirmang va ma'lumot kiritmang!",
                "Agar havola Telegram/SMS orqali kelgan bo'lsa, xabarni o'chiring va xabar jo'natuvchini bloklang.",
                "Tashkilotingiz xavfsizlik xizmati (SOC)ga ushbu fishing domenni bloklashni tavsiya eting."
            ]
        elif risk_level == "MEDIUM":
            recs = [
                "Ehtiyotkorlik bilan kiring - domen yangi yoki shubhali belgilarga ega.",
                "Parol yoki bank karta ma'lumotlarini kiritishdan saqlaning."
            ]
        else:
            recs = [
                "Aniq fishing belgilari topilmadi. Lekin umumiy kiber-gigiyena qoidalariga amal qiling."
            ]

        # Log into unified database
        record_scan(
            scan_type="URL",
            target=features["hostname"] or url,
            risk_score=final_score,
            risk_level=risk_level,
            classification=classification,
        )

        xai = explain_url_decision(features, rule_result["risk_score"], local.get("ml_probability"))

        data_bundle = {
            "url": url,
            "risk_score": final_score,
            "risk_level": risk_level,
            "classification": classification,
            "rule_score": rule_result["risk_score"],
            "ml_probability": local.get("ml_probability"),
            "ml_classification": local.get("ml_classification"),
            "features": features,
            "reasons": fused["reasons"],
            "positive_signals": fused["positive_signals"],
            "recommendations": recs,
            "virustotal": vt_result,
            "xai_analysis": xai,
        }

        # Build PDF
        pdf_bytes = generate_soc_pdf_report("URL", data_bundle)

        # Build Telegram Message
        level_icons = {
            "CRITICAL": "🚨 KRITIK XAVF",
            "HIGH": "⚠️ YUQORI XAVF",
            "MEDIUM": "🟡 O'RTA XAVF",
            "LOW": "🟢 XAVFSIZ",
            "VERY_LOW": "🟢 BUTKUL XAVFSIZ",
        }
        icon_badge = level_icons.get(risk_level, "🔍 TEKSHIRILDI")

        ml_txt = f"{local['ml_probability'] * 100:.1f}%" if local.get("ml_probability") is not None else "Ensemble"
        
        msg_lines = [
            f"🛡️ <b>PHISHGUARD AI — SOC TEKSHIRUV NATIJASI</b>",
            f"━━━━━━━━━━━━━━━━━━━━━━",
            f"🎯 <b>Nishon:</b> <code>{features['hostname'] or url}</code>",
            f"📊 <b>Xavf Darajasi:</b> <b>{final_score} / 100</b> [{icon_badge}]",
            f"🏷️ <b>Xulosa:</b> <b>{classification}</b>",
            "",
            f"🧠 <b>Sun'iy Intellekt va Tahlil (XAI):</b>",
            f"• ML Neyrotarmoq ehtimoli: <b>{ml_txt}</b>",
            f"• Statik qoidalar balli: <b>{rule_result['risk_score']}/100</b>",
        ]

        if fused["reasons"]:
            msg_lines.append("")
            msg_lines.append("⚠️ <b>Aniqlangan xavf omillari (IoC):</b>")
            for r in fused["reasons"][:4]:
                msg_lines.append(f" • {r}")

        if fused["positive_signals"]:
            msg_lines.append("")
            msg_lines.append("✅ <b>Himoya signallari:</b>")
            for s in fused["positive_signals"][:2]:
                msg_lines.append(f" • {s}")

        msg_lines.append("")
        msg_lines.append(f"💡 <b>Tavsiya:</b> {recs[0]}")
        msg_lines.append("━━━━━━━━━━━━━━━━━━━━━━")
        msg_lines.append("📄 <i>Rasmiy SOC Ekspertiza Hisoboti (PDF) quyida yuklanmoqda...</i>")

        return "\n".join(msg_lines), pdf_bytes

    def analyze_exe(self, content: bytes, filename: str) -> Tuple[str, bytes]:
        """Runs Windows PE file static reverse engineering and generates response + PDF."""
        pe_info = parse_pe(content)
        hashes = compute_exe_hashes(content)
        static_result = calculate_static_risk(pe_info)
        ml_prob = predict_exe_probability(len(content), pe_info)
        local_combined = combine_static_and_ml(static_result, ml_prob)
        vt_result = virustotal.lookup_hash(hashes["sha256"])
        fusion = combine_final(local_combined, vt_result)
        xai = explain_exe_decision(pe_info, static_result["static_risk_score"])

        # Log to unified DB
        record_scan(
            scan_type="EXE",
            target=filename,
            risk_score=fusion["final_score"],
            risk_level=fusion["risk_level"],
            classification=fusion["classification"],
        )

        data_bundle = {
            "filename": filename,
            "file_size_bytes": len(content),
            "sha256": hashes["sha256"],
            "sha1": hashes["sha1"],
            "md5": hashes["md5"],
            "final_score": fusion["final_score"],
            "risk_level": fusion["risk_level"],
            "classification": fusion["classification"],
            "rule_score": static_result["static_risk_score"],
            "ml_probability": ml_prob,
            "ml_classification": fusion["classification"],
            "indicators": fusion["reasons"],
            "positive_signals": fusion["positive_signals"],
            "recommendations": fusion["recommendations"],
            "virustotal": vt_result,
            "xai_analysis": xai,
        }

        pdf_bytes = generate_soc_pdf_report("EXE", data_bundle)

        level_icons = {
            "CRITICAL": "🚨 KRITIK ZARARLI (MALICIOUS)",
            "HIGH": "⚠️ XAVFLI (TROJAN/MALWARE)",
            "MEDIUM": "🟡 SHUBHALI (SUSPICIOUS)",
            "LOW": "🟢 XAVFSIZ (BENIGN)",
            "VERY_LOW": "🟢 ISHONCHLI FAYL",
        }
        icon_badge = level_icons.get(fusion["risk_level"], "🔍 TAHLIL QILINDI")

        msg_lines = [
            f"🛡️ <b>PHISHGUARD AI — EXE STATIK TAHLIL</b>",
            f"━━━━━━━━━━━━━━━━━━━━━━",
            f"💾 <b>Fayl:</b> <code>{filename}</code> ({len(content)//1024} KB)",
            f"📊 <b>Xavf Balli:</b> <b>{fusion['final_score']} / 100</b> [{icon_badge}]",
            f"🏷️ <b>Tasnif:</b> <b>{fusion['classification']}</b>",
            "",
            f"⚙️ <b>PE Binariy Anatomiyasi:</b>",
            f"• Mashina turi: <code>{pe_info['machine_type']}</code>",
            f"• Bo'limlar soni: <b>{pe_info['number_of_sections']}</b>",
            f"• Raqamli imzo: {'✅ Mavjud' if pe_info['has_digital_signature'] else '❌ Mavjud emas'}",
            f"• Xavfli Windows API importlari: <b>{len(pe_info['suspicious_imports'])} ta</b>",
            f"• SHA-256: <code>{hashes['sha256'][:24]}...</code>",
        ]

        if fusion["reasons"]:
            msg_lines.append("")
            msg_lines.append("⚠️ <b>Forensic Anomaliyalar:</b>")
            for ind in fusion["reasons"][:4]:
                msg_lines.append(f" • {ind}")

        msg_lines.append("")
        msg_lines.append(f"💡 <b>Tavsiya:</b> {fusion['recommendations'][0] if fusion['recommendations'] else 'Ehtiyotkorlik bilan ishga tushiring.'}")
        msg_lines.append("━━━━━━━━━━━━━━━━━━━━━━")
        msg_lines.append("📄 <i>Rasmiy PE SOC Ekspertiza Hisoboti (PDF) yuborilmoqda...</i>")

        return "\n".join(msg_lines), pdf_bytes

    def analyze_apk(self, content: bytes, filename: str) -> Tuple[str, bytes]:
        """Runs Android APK static manifest reverse engineering and generates response + PDF."""
        apk_info = parse_apk(content, filename)
        hashes = compute_apk_hashes(content)
        static_result = calculate_apk_static_risk(apk_info)
        vt_result = virustotal.lookup_hash(hashes["sha256"])
        fused = fuse_scores(
            static_result["static_risk_score"], static_result["indicators"], static_result["positive_signals"],
            vt_result, subject="APK"
        )
        final_score = fused["final_score"]
        risk_level, classification_label = score_to_level(final_score)
        classification = "MALICIOUS" if risk_level in ("HIGH", "CRITICAL") else ("SUSPICIOUS" if risk_level == "MEDIUM" else "BENIGN")

        if risk_level in ("HIGH", "CRITICAL"):
            recs = [
                "Ushbu ilovani aslo smartfoningizga o'rnatmang!",
                "Agar o'rnatilgan bo'lsa, zudlik bilan o'chirib tashlang va bank ilovalari parollarini yangilang.",
                "Ilovalarni faqat rasmiy Google Play do'konidan yuklang."
            ]
        elif risk_level == "MEDIUM":
            recs = [
                "Ehtiyot bo'ling: ilova keragidan ortiq shubhali ruxsatnomalar so'ramoqda.",
                "O'rnatishdan oldin dasturchi manbasini tekshiring."
            ]
        else:
            recs = ["Ilova tahlilida ochiq xavfli indikatorlar topilmadi."]

        record_scan(
            scan_type="APK",
            target=f"{apk_info['package_name']} ({filename})",
            risk_score=final_score,
            risk_level=risk_level,
            classification=classification,
        )

        xai = explain_apk_decision(apk_info, static_result["static_risk_score"])

        data_bundle = {
            "filename": filename,
            "package_name": apk_info.get("package_name"),
            "file_size_bytes": len(content),
            "sha256": hashes["sha256"],
            "sha1": hashes["sha1"],
            "md5": hashes["md5"],
            "final_score": final_score,
            "risk_level": risk_level,
            "classification": classification,
            "rule_score": static_result["static_risk_score"],
            "indicators": fused["reasons"],
            "positive_signals": fused["positive_signals"],
            "recommendations": recs,
            "virustotal": vt_result,
            "xai_analysis": xai,
        }

        pdf_bytes = generate_soc_pdf_report("APK", data_bundle)

        level_icons = {
            "CRITICAL": "🚨 KRITIK ZARARLI APK",
            "HIGH": "⚠️ XAVFLI APK (TROJAN/SPYWARE)",
            "MEDIUM": "🟡 SHUBHALI APK",
            "LOW": "🟢 XAVFSIZ ILOVA",
            "VERY_LOW": "🟢 ISHONCHLI ILOVA",
        }
        icon_badge = level_icons.get(risk_level, "🔍 TAHLIL QILINDI")

        msg_lines = [
            f"🛡️ <b>PHISHGUARD AI — ANDROID APK TAHLIL</b>",
            f"━━━━━━━━━━━━━━━━━━━━━━",
            f"📱 <b>Paket:</b> <code>{apk_info.get('package_name', 'Unknown')}</code>",
            f"📦 <b>Fayl:</b> <code>{filename}</code> ({len(content)//(1024*1024):.1f} MB)",
            f"📊 <b>Xavf Balli:</b> <b>{final_score} / 100</b> [{icon_badge}]",
            f"🏷️ <b>Tasnif:</b> <b>{classification}</b>",
            "",
            f"🔍 <b>Android Manifest Tahlili:</b>",
            f"• Ilova nomi: <b>{apk_info.get('app_name', 'Noma\'lum')}</b>",
            f"• Jami ruxsatnomalar (Permissions): <b>{len(apk_info.get('permissions', []))} ta</b>",
            f"• Xavfli ruxsatnomalar: <b>{len(apk_info.get('dangerous_permissions', []))} ta</b>",
        ]

        if apk_info.get("dangerous_permissions"):
            msg_lines.append("")
            msg_lines.append("⚡ <b>Xavfli Ruxsatlar:</b>")
            for perm in apk_info["dangerous_permissions"][:4]:
                perm_short = perm.split(".")[-1]
                msg_lines.append(f" • <code>{perm_short}</code>")

        if fused["reasons"]:
            msg_lines.append("")
            msg_lines.append("⚠️ <b>Aniqlangan Anomaliyalar:</b>")
            for r in fused["reasons"][:3]:
                msg_lines.append(f" • {r}")

        msg_lines.append("")
        msg_lines.append(f"💡 <b>Tavsiya:</b> {recs[0]}")
        msg_lines.append("━━━━━━━━━━━━━━━━━━━━━━")
        msg_lines.append("📄 <i>Rasmiy APK SOC Ekspertiza Hisoboti (PDF) yuborilmoqda...</i>")

        return "\n".join(msg_lines), pdf_bytes

    # -------------------------------------------------------------
    # Message Routing & Handling
    # -------------------------------------------------------------

    def handle_message(self, message: Dict[str, Any]):
        chat_id = message["chat"]["id"]
        msg_id = message.get("message_id")
        text = (message.get("text") or "").strip()

        # 1. Commands
        if text.startswith("/start") or text.startswith("/help"):
            welcome = (
                "🛡️ <b>PhishGuard AI — Kiberxavfsizlik SOC Tahlilchi Boti</b>\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                "Ushbu bot sun'iy intellekt va statik tahlil yordamida fishing havolalari, "
                "zararli Windows dasturlari (.exe) va xavfli Android ilovalari (.apk)ni "
                "real vaqtda aniqlaydi.\n\n"
                "<b>Qanday foydalanish mumkin?</b>\n"
                "1️⃣ <b>Havolani tekshirish:</b> Shubhali URL manzilni to'g'ridan-to'g'ri chatga yuboring (masalan: <code>https://pay-security.com</code>)\n"
                "2️⃣ <b>.exe faylni tekshirish:</b> Shubhali Windows dasturini fayl sifatida yuboring\n"
                "3️⃣ <b>.apk ilovani tekshirish:</b> Android ilovasi o'rnatish faylini yuboring\n\n"
                "📑 <i>Har bir tahlil yakunida rasmiy <b>PDF Ekspertiza Hisoboti</b> yuklab beriladi!</i>\n"
                "📊 Tizim statistikasini ko'rish uchun: /stats buyrug'ini yuboring."
            )
            self.send_message(chat_id, welcome, reply_to_message_id=msg_id)
            return

        if text.startswith("/stats"):
            stats = get_dashboard_stats()
            stats_msg = (
                "📊 <b>PHISHGUARD AI — SOC STATISTIKASI</b>\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                f"🔢 Jami tekshiruvlar: <b>{stats['total_scans']} ta</b>\n"
                f"🔗 URL tekshiruvlari: <b>{stats['url_scans']} ta</b>\n"
                f"💾 EXE fayllar: <b>{stats['exe_scans']} ta</b>\n"
                f"📱 APK ilovalar: <b>{stats['apk_scans']} ta</b>\n"
                f"🚨 Aniqlangan tahdidlar: <b>{stats['threats_detected']} ta</b>\n"
                f"📉 O'rtacha xavf darajasi: <b>{stats['average_risk']} / 100</b>\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                "🌐 <i>Web-interfeys: http://127.0.0.1:8000</i>"
            )
            self.send_message(chat_id, stats_msg, reply_to_message_id=msg_id)
            return

        # 2. Document Attachments (.exe, .apk)
        document = message.get("document")
        if document:
            filename = document.get("file_name", "unknown_file")
            file_id = document.get("file_id")
            file_size = document.get("file_size", 0)
            ext = Path(filename).suffix.lower()

            if ext not in (".exe", ".apk"):
                self.send_message(
                    chat_id,
                    f"⚠️ <b>Qo'llab-quvvatlanmaydigan format:</b> <code>{ext}</code>\n"
                    "PhishGuard AI hozirda faqat <b>.exe</b> (Windows dasturlari), "
                    "<b>.apk</b> (Android ilovalari) va <b>URL havolalarni</b> tahlil qiladi.",
                    reply_to_message_id=msg_id
                )
                return

            if file_size > TELEGRAM_MAX_DOWNLOAD_BYTES:
                self.send_message(
                    chat_id,
                    f"⚠️ <b>Fayl hajmi juda katta:</b> {file_size // (1024*1024)} MB.\n"
                    "Telegram Bot API cheklovi tufayli bot faqat 20 MB gacha bo'lgan fayllarni qabul qiladi. "
                    "Kattaroq fayllar (50 MB gacha) uchun Web-interfeysimizdan foydalaning: http://127.0.0.1:8000",
                    reply_to_message_id=msg_id
                )
                return

            self.send_chat_action(chat_id, "upload_document")
            self.send_message(chat_id, f"⏳ <b>{filename}</b> qabul qilindi. Statik PE/APK dekompilyatsiyasi va tahlil ketmoqda...", reply_to_message_id=msg_id)

            content = self.download_file_bytes(file_id)
            if not content:
                self.send_message(chat_id, "❌ Faylni Telegram serverlaridan yuklab olishda xatolik yuz berdi.", reply_to_message_id=msg_id)
                return

            try:
                if ext == ".exe":
                    resp_text, pdf_bytes = self.analyze_exe(content, filename)
                    doc_name = f"PhishGuard_SOC_Report_{Path(filename).stem}.pdf"
                else:
                    resp_text, pdf_bytes = self.analyze_apk(content, filename)
                    doc_name = f"PhishGuard_SOC_Report_{Path(filename).stem}.pdf"

                self.send_message(chat_id, resp_text, reply_to_message_id=msg_id)
                self.send_document(chat_id, pdf_bytes, doc_name, caption=f"📄 Rasmiy SOC Ekspertiza Hisoboti: {filename}")
            except (InvalidExecutableError, InvalidApkError) as e:
                self.send_message(chat_id, f"⚠️ <b>Fayl formati xatosi:</b> {str(e)}", reply_to_message_id=msg_id)
            except Exception as e:
                logger.exception(f"File analysis error: {e}")
                self.send_message(chat_id, f"❌ Tahlil jarayonida xatolik yuz berdi: {str(e)}", reply_to_message_id=msg_id)
            return

        # 3. Text containing URL
        if text:
            # Look for URL pattern
            url_pattern = r"(https?://[^\s]+|[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:/[^\s]*)?)"
            match = re.search(url_pattern, text)
            if match:
                target_url = match.group(0)
                self.send_chat_action(chat_id, "typing")
                try:
                    resp_text, pdf_bytes = self.analyze_url(target_url)
                    self.send_message(chat_id, resp_text, reply_to_message_id=msg_id)
                    domain_slug = re.sub(r"[^a-zA-Z0-9]", "_", target_url[:30])
                    doc_name = f"PhishGuard_SOC_Report_{domain_slug}.pdf"
                    self.send_document(chat_id, pdf_bytes, doc_name, caption=f"📄 Rasmiy SOC Ekspertiza Hisoboti: {target_url[:35]}")
                except Exception as e:
                    logger.exception(f"URL analysis error: {e}")
                    self.send_message(chat_id, f"❌ Havolani tekshirishda xatolik yuz berdi: {str(e)}", reply_to_message_id=msg_id)
            else:
                self.send_message(
                    chat_id,
                    "❓ <b>Tushunarsiz xabar formati.</b>\n\n"
                    "Iltimos, tekshirish uchun shubhali <b>havola (URL)</b> yozing yoki "
                    "<b>.exe</b> / <b>.apk</b> fayl yuklang.\n"
                    "Masalan: <code>https://kun.uz</code> yoki <code>click-online-uzcard.net</code>",
                    reply_to_message_id=msg_id
                )

    # -------------------------------------------------------------
    # Polling Loop
    # -------------------------------------------------------------

    def run_polling(self):
        """Main long-polling loop."""
        if not self.test_connection():
            logger.error("❌ Telegram botga ulanib bo'lmadi! Iltimos, Bot Tokenni tekshiring.")
            return

        username = self.bot_info.get("username", "UnknownBot")
        first_name = self.bot_info.get("first_name", "Bot")
        init_db()

        print("\n" + "=" * 65)
        print(f" 🛡️  PHISHGUARD AI — TELEGRAM SOC BOT ISHGA TUSHDI")
        print("=" * 65)
        print(f" 🤖 Bot: @{username} ({first_name})")
        print(f" 📡 Holat: Real-time Long-polling faol")
        print(f" 💾 SQLite bazasi: Ulanish muvaffaqiyatli")
        print(f" 📑 Avtomatik PDF ekspertiza hisoboti: Faol")
        print("=" * 65)
        print(" To'xtatish uchun: Ctrl + C bosing.\n")

        offset = 0
        while True:
            try:
                params = {"offset": offset, "timeout": 25}
                resp = self.session.get(f"{self.api_base}/getUpdates", params=params, timeout=35)
                data = resp.json()

                if not data.get("ok"):
                    time.sleep(3)
                    continue

                updates = data.get("result", [])
                for update in updates:
                    offset = max(offset, update["update_id"] + 1)
                    if "message" in update:
                        self.handle_message(update["message"])

            except requests.exceptions.RequestException as e:
                logger.warning(f"Network warning (retrying in 5s): {e}")
                time.sleep(5)
            except KeyboardInterrupt:
                print("\n🛑 Telegram SOC Bot to'xtatildi.")
                break
            except Exception as e:
                logger.error(f"Unexpected loop exception: {e}")
                time.sleep(2)


def prompt_and_save_token() -> str:
    print("\n" + "=" * 65)
    print(" 🤖 PHISHGUARD AI — TELEGRAM SOC BOT SOZLAMASI")
    print("=" * 65)
    print(" Telegram bot yaratish uchun 30 soniya kifoya:")
    print(" 1. Telegramda @BotFather ni oching.")
    print(" 2. /newbot buyrug'ini yuboring va botingizga nom bering.")
    print(" 3. BotFather bergan HTTP API tokenni nusxalang.")
    print("=" * 65)

    token = input("\n👉 Telegram Bot Tokenni kiriting: ").strip()
    if token:
        env_path = BACKEND_DIR / ".env"
        env_content = ""
        if env_path.exists():
            with open(env_path, "r", encoding="utf-8") as f:
                env_content = f.read()

        if "TELEGRAM_BOT_TOKEN=" in env_content:
            # Replace
            new_lines = []
            for line in env_content.splitlines():
                if line.startswith("TELEGRAM_BOT_TOKEN="):
                    new_lines.append(f"TELEGRAM_BOT_TOKEN={token}")
                else:
                    new_lines.append(line)
            env_content = "\n".join(new_lines) + "\n"
        else:
            env_content = env_content.rstrip() + f"\nTELEGRAM_BOT_TOKEN={token}\n"

        with open(env_path, "w", encoding="utf-8") as f:
            f.write(env_content)
        print("✅ Token 'backend/.env' fayliga muvaffaqiyatli saqlandi!\n")

    return token


def main():
    parser = argparse.ArgumentParser(description="PhishGuard AI Telegram SOC Bot")
    parser.add_argument("--token", type=str, help="Telegram Bot Token from @BotFather")
    args = parser.parse_args()

    token = args.token or os.getenv("TELEGRAM_BOT_TOKEN")
    if not token or token == "YOUR_TELEGRAM_BOT_TOKEN_HERE":
        token = prompt_and_save_token()

    if not token:
        print("❌ Token kiritilmadi. Dastur to'xtatildi.")
        sys.exit(1)

    bot = PhishGuardTelegramBot(token)
    bot.run_polling()


if __name__ == "__main__":
    main()
