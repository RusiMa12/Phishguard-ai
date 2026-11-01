"""
yara_generator.py
-----------------
PhishGuard AI — Forensic Threat Intelligence Engine.
Skanerlangan fishing havolalari, Windows PE va Android APK troyanlari uchun
xalqaro standartdagi YARA qoidalarini (YARA 4.x) avtomatik shakllantirish moduli.
"""

from typing import Dict, Any, List
import re
from datetime import datetime, timezone


def sanitize_rule_name(name: str) -> str:
    """YARA qoidasi nomini tozalab, mos identifikator shakliga keltiradi."""
    clean = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    clean = re.sub(r'_+', '_', clean).strip('_')
    if not clean or clean[0].isdigit():
        clean = "PhishGuard_" + clean
    return clean[:45]


def generate_yara_rule(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Skanerlash natijalari asosida to'liq YARA qoidasini generatsiya qiladi.
    Turlar: 'url', 'pe', 'apk'
    """
    scan_type = data.get("type", "pe").lower()
    target_name = data.get("target_name", "Unknown_Threat")
    threat_level = data.get("threat_level", "HIGH").upper()
    risk_score = data.get("risk_score", 85)
    sha256 = data.get("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    reasons = data.get("reasons", [])
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    date_short = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    clean_target = sanitize_rule_name(target_name)
    rule_name = f"PhishGuard_{scan_type.upper()}_{clean_target}_{threat_level}"

    # Determine MITRE tactics
    if scan_type == "url":
        mitre = "T1566.002 (Phishing: Spearphishing Link), T1204.001 (User Execution)"
        category = "PHISHING_URL_INFRASTRUCTURE"
    elif scan_type == "apk":
        mitre = "T1475 (Access Token Theft), T1417 (Input Capture), T1437 (Standard Application Layer Protocol)"
        category = "ANDROID_BANKER_DROPPER"
    else:
        mitre = "T1055 (Process Injection), T1027 (Obfuscated Files or Information), T1566.001 (Spearphishing Attachment)"
        category = "WINDOWS_TROJAN_BACKDOOR"

    lines = []
    lines.append("/*")
    lines.append("   ==========================================================================")
    lines.append("   PhishGuard AI — Forensic Threat Intelligence YARA Rule (v9.0)")
    lines.append(f"   Target: {target_name}")
    lines.append(f"   Generated: {now_str}")
    lines.append(f"   Classification: {category}")
    lines.append("   TLP Classification: TLP:AMBER | Incident Response Team Only")
    lines.append(f"   MITRE ATT&CK: {mitre}")
    lines.append("   ==========================================================================")
    lines.append("*/")
    lines.append("")

    if scan_type == "pe":
        lines.append('import "pe"')
        lines.append("")

    lines.append(f"rule {rule_name}")
    lines.append("{")
    lines.append("    meta:")
    lines.append(f'        description = "Automated forensic detection for {category.lower().replace("_", " ")}"')
    lines.append('        author = "PhishGuard AI Forensic Intelligence Engine"')
    lines.append('        reference = "https://phishguard.cybersecurity.uz/dossier"')
    lines.append(f'        threat_level = "{threat_level}"')
    lines.append(f"        threat_score = {risk_score}")
    lines.append(f'        sha256 = "{sha256}"')
    lines.append(f'        mitre_technique = "{mitre.split()[0]}"')
    lines.append(f'        date = "{date_short}"')
    lines.append("        version = 1")
    lines.append("")

    lines.append("    strings:")
    if scan_type == "pe":
        lines.append('        $mz = "MZ"')
        lines.append('        $api_inj1 = "VirtualAllocEx" ascii wide')
        lines.append('        $api_inj2 = "WriteProcessMemory" ascii wide')
        lines.append('        $api_inj3 = "CreateRemoteThread" ascii wide')
        lines.append('        $api_hook = "SetWindowsHookEx" ascii wide')
        lines.append('        $sec_upx0 = "UPX0" ascii')
        lines.append('        $sec_upx1 = "UPX1" ascii')
        lines.append('        $pwrsh = "powershell.exe -enc" ascii wide nocase')
        lines.append('        $cmd = "cmd.exe /c" ascii wide nocase')
        lines.append("")
        lines.append("    condition:")
        lines.append("        uint16(0) == 0x5A4D and")
        lines.append("        filesize < 50MB and")
        lines.append("        (")
        lines.append("            2 of ($api_inj*) or")
        lines.append("            $api_hook or")
        lines.append("            ($sec_upx0 and $sec_upx1) or")
        lines.append("            $pwrsh or $cmd")
        lines.append("        )")

    elif scan_type == "apk":
        lines.append('        $zip_header = { 50 4B 03 04 }')
        lines.append('        $manifest = "AndroidManifest.xml" ascii')
        lines.append('        $perm_sms = "android.permission.RECEIVE_SMS" ascii')
        lines.append('        $perm_access = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii')
        lines.append('        $perm_overlay = "android.permission.SYSTEM_ALERT_WINDOW" ascii')
        lines.append('        $str_bank1 = "sendTextMessage" ascii')
        lines.append('        $str_bank2 = "telephony" ascii wide nocase')
        lines.append('        $classes_dex = "classes.dex" ascii')
        lines.append("")
        lines.append("    condition:")
        lines.append("        uint32(0) == 0x04034B50 and")
        lines.append("        $manifest and $classes_dex and")
        lines.append("        (")
        lines.append("            ($perm_sms and $perm_access) or")
        lines.append("            ($perm_overlay and $perm_sms) or")
        lines.append("            ($str_bank1 and $str_bank2)")
        lines.append("        )")

    else:  # URL / Phishing pattern
        clean_url_str = re.sub(r'https?://', '', target_name).split('/')[0]
        lines.append(f'        $target_token = "{clean_url_str}" ascii wide nocase')
        lines.append('        $kw_login = "login" ascii wide nocase')
        lines.append('        $kw_verify = "verify" ascii wide nocase')
        lines.append('        $kw_secure = "secure" ascii wide nocase')
        lines.append('        $kw_pass = "password" ascii wide nocase')
        lines.append('        $kw_card = "card" ascii wide nocase')
        lines.append('        $kw_payme = "payme" ascii wide nocase')
        lines.append('        $kw_click = "click" ascii wide nocase')
        lines.append("")
        lines.append("    condition:")
        lines.append("        $target_token and")
        lines.append("        2 of ($kw_*)")

    lines.append("}")
    lines.append("")

    full_yara_code = "\n".join(lines)
    return {
        "status": "success",
        "rule_name": rule_name,
        "filename": f"{rule_name}.yar",
        "category": category,
        "threat_level": threat_level,
        "yara_code": full_yara_code
    }

