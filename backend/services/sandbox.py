"""
services/sandbox.py
-------------------
PhishGuard AI — Dinamik Tahlil va Xatti-harakatlar (Behavioral / Sandbox Analysis) Moduli.

Xususiyatlari:
  1) CAPE / Cuckoo Sandbox API Integratsiyasi:
     - Agar SANDBOX_API_URL va SANDBOX_API_TOKEN sozlangan bo'lsa, fayllarni avtomatik
       izolyatsiya qilingan qumloqqa (sandbox VM) jo'natadi va real vaqt hisobotini oladi.
  2) Evristik Xatti-harakatlarni Modellashtirish (Behavioral Reconstruction Engine):
     - Agar tashqi sandbox ulanmagan bo'lsa, PE va APK fayl tuzilmasi, shubhali API zanjirlari
       va MITRE ATT&CK qoliplari asosida dasturning dinamik xatti-harakatlarini
       (Process tree, Registry persistence, Network C2, File tampering) rekonstruksiya qiladi.
"""

import os
import io
import time
from typing import Dict, Any, List, Optional
import requests

SANDBOX_API_URL = os.environ.get("SANDBOX_API_URL", "").rstrip("/")
SANDBOX_API_TOKEN = os.environ.get("SANDBOX_API_TOKEN", "")
SANDBOX_TIMEOUT = int(os.environ.get("SANDBOX_TIMEOUT", "15"))


def is_remote_sandbox_available() -> bool:
    """Tashqi CAPE/Cuckoo Sandbox API mavjudligini tekshiradi."""
    return bool(SANDBOX_API_URL)


def submit_to_remote_sandbox(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Faylni tashqi CAPE yoki Cuckoo Sandbox REST API ga yuborish.
    """
    if not SANDBOX_API_URL:
        return {"status": "not_configured", "detail": "SANDBOX_API_URL sozlanmagan."}

    headers = {}
    if SANDBOX_API_TOKEN:
        headers["Authorization"] = f"Bearer {SANDBOX_API_TOKEN}"

    try:
        files = {"file": (filename, io.BytesIO(file_bytes))}
        response = requests.post(
            f"{SANDBOX_API_URL}/api/v1/tasks/create/file/",
            files=files,
            headers=headers,
            timeout=SANDBOX_TIMEOUT,
        )
        if response.status_code in (200, 201):
            data = response.json()
            task_id = data.get("task_id") or data.get("id")
            return {
                "status": "submitted",
                "task_id": task_id,
                "sandbox_type": "CAPE/Cuckoo",
                "message": "Fayl tahlil uchun dinamik Sandbox muhitiga muvaffaqiyatli topshirildi.",
            }
        return {"status": "error", "detail": f"Sandbox server xatolik qaytardi: {response.status_code}"}
    except Exception as exc:
        return {"status": "unavailable", "detail": f"Sandbox serveriga ulanib bo'lmadi: {str(exc)}"}


def reconstruct_behavioral_profile(
    target_type: str,
    target_name: str,
    suspicious_indicators: List[str],
    raw_details: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Dinamik xatti-harakatlar profilini tahlil qilish va modellashtirish.
    SOC tahlilchilari uchun dastur ishga tushsa tizimda nimalar sodir bo'lishini ko'rsatadi.
    """
    target_type = target_type.lower()
    process_tree = []
    registry_actions = []
    filesystem_actions = []
    network_actions = []
    mitre_behaviors = []
    threat_severity = "LOW"
    severity_score = 10

    if target_type == "pe" or target_type == "exe":
        suspicious_apis = set(raw_details.get("suspicious_imports", []))
        sections = raw_details.get("sections", [])
        has_wx = any(s.get("is_writable") and s.get("is_executable") for s in sections)

        # 1. Process Injection & Hollowing
        if {"VirtualAllocEx", "WriteProcessMemory"}.intersection(suspicious_apis):
            severity_score += 35
            process_tree.append({
                "parent": target_name,
                "child": "svchost.exe (Injected)",
                "action": "Process Injection / Memory Modification",
                "technique": "T1055.002",
                "severity": "CRITICAL"
            })
            mitre_behaviors.append({
                "technique": "T1055",
                "name": "Process Injection",
                "tactics": "Privilege Escalation / Defense Evasion",
                "risk": "Yuqori xavf: Boshqa tizim jarayonlari xotirasiga zararli kod joylaydi."
            })

        if {"WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW"}.intersection(suspicious_apis):
            severity_score += 20
            process_tree.append({
                "parent": target_name,
                "child": "cmd.exe / powershell.exe",
                "action": "Spawn Hidden Child Process",
                "technique": "T1059.001",
                "severity": "HIGH"
            })

        # 2. Registry Persistence
        if {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA"}.intersection(suspicious_apis):
            severity_score += 25
            registry_actions.append({
                "hive": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value": target_name,
                "action": "Auto-Start Persistence qo'shish",
                "technique": "T1547.001"
            })
            mitre_behaviors.append({
                "technique": "T1547",
                "name": "Boot or Logon Autostart Execution",
                "tactics": "Persistence",
                "risk": "Tizim har gal qayta yoqilganda avtomatik ishga tushish mexanizmi."
            })

        # 3. Network & C2 Traffic
        if {"URLDownloadToFileA", "InternetOpenA", "WinHttpOpen", "connect", "WSAStartup"}.intersection(suspicious_apis):
            severity_score += 25
            network_actions.append({
                "protocol": "HTTP/HTTPS / TCP Socket",
                "type": "C2 Callback & Stager Retrieval",
                "technique": "T1071.001",
                "description": "Tashqi server bilan maxfiy ulanish o'rnatish va qo'shimcha troyan yuklash."
            })

        # 4. Anti-Debugging & Evasion
        if {"IsDebuggerPresent", "CheckRemoteDebuggerPresent"}.intersection(suspicious_apis) or has_wx:
            severity_score += 15
            mitre_behaviors.append({
                "technique": "T1497",
                "name": "Virtualization/Sandbox Evasion",
                "tactics": "Defense Evasion",
                "risk": "Antivirus qumloqlari va tahlil vositalarini aniqlab, faoliyatini to'xtatishga urinish."
            })

        filesystem_actions.append({
            "path": "%TEMP%\\" + target_name,
            "action": "Vaqtinchalik papkada yashirin fayl nusxasini yaratish",
            "type": "DROP"
        })

    elif target_type == "apk":
        permissions = raw_details.get("permissions", [])
        has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in permissions
        has_accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions
        has_sms = any("SMS" in p for p in permissions)

        if has_overlay and has_accessibility:
            severity_score += 50
            mitre_behaviors.append({
                "technique": "T1417",
                "name": "Input Capture via Accessibility",
                "tactics": "Credential Access",
                "risk": "Bank va to'lov ilovalari ustiga soxta oyna (Overlay) chiqarish va PIN-kodlarni o'g'irlash."
            })
            process_tree.append({
                "parent": "Android OS",
                "child": target_name,
                "action": "Overlay Hijacking & Keystroke Logging",
                "severity": "CRITICAL"
            })

        if has_sms:
            severity_score += 30
            mitre_behaviors.append({
                "technique": "T1412",
                "name": "Capture SMS Messages",
                "tactics": "Credential Access / 2FA Bypass",
                "risk": "Keluvchi SMS xabarlari va bir martalik bank tasdiqlash kodlarini (OTP) o'g'irlash."
            })
            network_actions.append({
                "protocol": "Telegram Bot API / HTTPS",
                "type": "Exfiltrate SMS & Banking OTP",
                "description": "O'g'irlangan SMS kodlarni kiber-jinoyatchining Telegram botiga uzatish."
            })

    # Yakuniy xatti-harakat xavfi
    severity_score = min(max(severity_score, 0), 100)
    if severity_score >= 80:
        threat_severity = "CRITICAL"
    elif severity_score >= 60:
        threat_severity = "HIGH"
    elif severity_score >= 40:
        threat_severity = "MEDIUM"
    else:
        threat_severity = "LOW"

    return {
        "status": "completed",
        "mode": "simulated_reconstruction",
        "target_name": target_name,
        "target_type": target_type.upper(),
        "behavioral_severity": threat_severity,
        "behavioral_score": severity_score,
        "process_tree": process_tree,
        "registry_actions": registry_actions,
        "filesystem_actions": filesystem_actions,
        "network_actions": network_actions,
        "mitre_behaviors": mitre_behaviors,
        "remote_sandbox_configured": is_remote_sandbox_available(),
    }
