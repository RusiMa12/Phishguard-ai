import hashlib
import io
import re
import zipfile
from pyaxmlparser import APK

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB max APK size

# ---------------------------------------------------------------------------
# Sensitve & Dangerous Android Permissions
# ---------------------------------------------------------------------------
DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.READ_PHONE_STATE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.READ_PRIVILEGED_PHONE_STATE",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.ANSWER_PHONE_CALLS",
}

SMS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
}

SURVEILLANCE_PERMISSIONS = {
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
}

KNOWN_FINANCIAL_BRANDS = [
    "payme", "click", "uzum", "bank", "kapital", "hamkor", "agro", "sqb",
    "nbu", "ipoteka", "xalq", "anor", "tbc", "sber", "tinkoff", "binance",
    "telegram", "whatsapp", "viber", "metamask", "trustwallet",
]

# Social engineering lures commonly abused in Telegram / SMS malware campaigns
LURE_KEYWORDS = [
    # Uzbek
    "to'y", "to`y", "toydan", "kelin", "kuyov", "arxivi", "arxiv", "rasm", "rasmlar",
    "surat", "foto", "tasdiqlash", "chek", "kvitansiya", "jarima", "yhx", "soliq",
    "subsidiyasi", "kredit", "ovoz_bering", "tabrik", "aksiyasi", "yutuq", "sovg'a",
    # Russian
    "свадьба", "свадьбы", "архив", "фото", "фотки", "видео", "квитанция", "чек",
    "штраф", "повестка", "документ", "оплата", "подарок", "голосуй", "выигрыш",
    # English
    "wedding", "photo", "archive", "receipt", "invoice", "document", "reward"
]


class InvalidApkError(Exception):
    """File is not a valid Android APK."""


def compute_hashes(file_bytes: bytes) -> dict:
    return {
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "md5": hashlib.md5(file_bytes).hexdigest(),
    }


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (0.0 to 8.0). High entropy (> 7.4) indicates packed/encrypted code."""
    if not data:
        return 0.0
    import math
    entropy = 0.0
    length = len(data)
    for x in range(256):
        count = data.count(x)
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
    return entropy


def _inspect_zip_contents(file_bytes: bytes) -> dict:
    """
    Safely inspect the internal entries of the APK ZIP container in memory.
    Detects hidden secondary payloads, encrypted stager binaries, anti-analysis checks,
    multiple DEX files, and suspicious scripts.
    """
    dex_files = []
    hidden_payloads = []
    encrypted_stagers = []
    dex_anti_analysis = []
    dex_anti_av = []
    uses_package_installer_api = False
    has_root_tools = False
    has_shell_scripts = False

    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
            for info in z.infolist():
                name_lower = info.filename.lower()

                # DEX tracking
                if name_lower.endswith(".dex"):
                    dex_files.append(info.filename)

                # Hidden payloads in assets/ or res/
                if name_lower.startswith(("assets/", "res/raw/", "res/")):
                    # Known executable/dropper extensions
                    if name_lower.endswith((".apk", ".jar", ".dex", ".exe", ".dll", ".bin", ".dat", ".cache", ".snapshot")):
                        hidden_payloads.append(info.filename)

                    # High entropy encrypted payload detection (e.g. assets/st0)
                    if info.file_size >= 4096:
                        try:
                            sample_bytes = z.read(info.filename)
                            ent = calculate_entropy(sample_bytes[:32768])
                            if ent > 7.4:
                                encrypted_stagers.append(f"{info.filename} ({info.file_size // 1024} KB, entropy: {ent:.2f})")
                        except Exception:
                            pass

                # Shell scripts
                if name_lower.endswith(".sh"):
                    has_shell_scripts = True

                # Root exploitation tools
                if any(tool in name_lower for tool in ("/su", "/busybox", "daemonsu", "magisk")):
                    has_root_tools = True

            # Inspect classes.dex for evasion strings and installer APIs
            if "classes.dex" in z.namelist():
                try:
                    dex_data = z.read("classes.dex").lower()

                    # Anti-analysis tools
                    for tool in ["httptoolkit", "http toolkit", "frida", "xposed", "substrate", "rootbeer"]:
                        if tool.encode() in dex_data:
                            dex_anti_analysis.append(tool)

                    # Anti-AV scanner evasion
                    for av in ["sophos", "kaspersky", "drweb", "eset", "avast", "bitdefender"]:
                        if av.encode() in dex_data:
                            dex_anti_av.append(av)

                    # Dynamic package installer usage
                    if b"canrequestpackageinstalls" in dex_data or b"packageinstaller" in dex_data:
                        uses_package_installer_api = True
                except Exception:
                    pass

    except Exception:
        pass

    return {
        "dex_count": len(dex_files),
        "dex_files": dex_files,
        "hidden_payloads": hidden_payloads,
        "has_hidden_payloads": len(hidden_payloads) > 0,
        "encrypted_stagers": encrypted_stagers,
        "has_encrypted_payload": len(encrypted_stagers) > 0,
        "dex_anti_analysis": dex_anti_analysis,
        "dex_anti_av": dex_anti_av,
        "uses_package_installer_api": uses_package_installer_api,
        "has_root_tools": has_root_tools,
        "has_shell_scripts": has_shell_scripts,
    }


def parse_apk(file_bytes: bytes, filename: str = None) -> dict:
    """
    Disassembles APK structure safely in memory without writing to disk or executing code.
    """
    if len(file_bytes) < 4 or file_bytes[:2] != b"PK":
        raise InvalidApkError("File does not start with the ZIP/PK signature - not a valid APK.")

    try:
        apk = APK(file_bytes, raw=True)
    except Exception as exc:
        raise InvalidApkError(f"The file could not be parsed as a valid APK: {exc}")

    if not apk.get_package():
        raise InvalidApkError("No AndroidManifest.xml package name found - not a valid APK.")

    permissions = set(apk.get_permissions() or [])
    dangerous_found = sorted(permissions & DANGEROUS_PERMISSIONS)
    has_sms_permissions = bool(permissions & SMS_PERMISSIONS)
    has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in permissions
    has_accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions
    has_overlay_and_accessibility = has_overlay and has_accessibility

    surveillance_found = sorted(permissions & SURVEILLANCE_PERMISSIONS)
    has_broad_surveillance = len(surveillance_found) >= 3

    try:
        native_libraries = apk.get_libraries() or []
    except Exception:
        native_libraries = []

    # Internal ZIP archive inspection
    zip_meta = _inspect_zip_contents(file_bytes)

    # SDK evasion analysis
    target_sdk = apk.get_target_sdk_version()
    min_sdk = apk.get_min_sdk_version()
    evades_runtime_permissions = False
    try:
        if target_sdk and int(target_sdk) < 23:
            evades_runtime_permissions = True
    except (ValueError, TypeError):
        pass

    # Brand / Typosquatting in package name
    pkg_lower = (apk.get_package() or "").lower()
    app_lower = (apk.get_app_name() or "").lower()
    spoofed_brand = None
    for brand in KNOWN_FINANCIAL_BRANDS:
        if (brand in pkg_lower or brand in app_lower) and not pkg_lower.startswith(("com.google.", "org.telegram.")):
            # Flag if brand keyword is used in unofficial package name
            spoofed_brand = brand
            break

    # Debuggable APK detection
    is_debuggable = False
    try:
        if hasattr(apk, "is_debuggable"):
            is_debuggable = bool(apk.is_debuggable())
    except Exception:
        pass

    # Masquerading & Social Engineering Lure Detection
    app_name_str = apk.get_app_name() or ""
    filename_str = filename or ""
    combined_names = f"{filename_str} {app_name_str}".lower()

    # Disguised media extensions (e.g. .jpeg, .jpg, .png, .pdf, .mp4, .doc)
    disguised_pattern = r"(\.jpe?g|\.png|\.webp|\.mp4|\.mkv|\.pdf|\.docx?|\.xlsx?|\.zip|\.rar)(\s*\(\d+\))?(\.apk)?$"
    has_double_ext = bool(re.search(disguised_pattern, filename_str.lower()))
    app_name_has_media_ext = bool(re.search(r"\.(jpe?g|png|webp|mp4|pdf|docx?|zip)\b", app_name_str.lower()))
    is_masquerading_media = has_double_ext or app_name_has_media_ext

    # Lure keywords (e.g. to'y, arxiv, rasm, chek)
    matched_lures = [kw for kw in LURE_KEYWORDS if kw in combined_names]

    return {
        "package_name": apk.get_package() or "unknown",
        "app_name": apk.get_app_name() or "unknown",
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "evades_runtime_permissions": evades_runtime_permissions,
        "is_signed": bool(apk.is_signed()),
        "is_debuggable": is_debuggable,
        "is_multidex": bool(apk.is_multidex() or zip_meta["dex_count"] > 1),
        "dex_count": zip_meta["dex_count"],
        "hidden_payloads": zip_meta["hidden_payloads"],
        "has_hidden_payloads": zip_meta["has_hidden_payloads"],
        "encrypted_stagers": zip_meta["encrypted_stagers"],
        "has_encrypted_payload": zip_meta["has_encrypted_payload"],
        "dex_anti_analysis": zip_meta["dex_anti_analysis"],
        "dex_anti_av": zip_meta["dex_anti_av"],
        "anti_security_evasion": len(zip_meta["dex_anti_analysis"]) > 0 or len(zip_meta["dex_anti_av"]) > 0,
        "uses_package_installer_api": zip_meta["uses_package_installer_api"],
        "is_masquerading_media": is_masquerading_media,
        "has_double_ext": has_double_ext,
        "app_name_has_media_ext": app_name_has_media_ext,
        "matched_lures": matched_lures,
        "has_root_tools": zip_meta["has_root_tools"],
        "has_shell_scripts": zip_meta["has_shell_scripts"],
        "permission_count": len(permissions),
        "permissions": sorted(permissions),
        "dangerous_permissions": dangerous_found,
        "has_sms_permissions": has_sms_permissions,
        "has_overlay": has_overlay,
        "has_accessibility": has_accessibility,
        "has_overlay_and_accessibility": has_overlay_and_accessibility,
        "has_broad_surveillance": has_broad_surveillance,
        "surveillance_permissions": surveillance_found,
        "requests_install_packages": "android.permission.REQUEST_INSTALL_PACKAGES" in permissions,
        "requests_device_admin": "android.permission.BIND_DEVICE_ADMIN" in permissions,
        "queries_all_packages": "android.permission.QUERY_ALL_PACKAGES" in permissions,
        "ignores_battery_opt": "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" in permissions,
        "boot_persistence": "android.permission.RECEIVE_BOOT_COMPLETED" in permissions,
        "spoofed_brand": spoofed_brand,
        "activity_count": len(apk.get_activities() or []),
        "service_count": len(apk.get_services() or []),
        "receiver_count": len(apk.get_receivers() or []),
        "native_library_count": len(native_libraries),
    }


# ---------------------------------------------------------------------------
# Advanced Threat Scoring Engine
# ---------------------------------------------------------------------------
APK_RISK_WEIGHTS = {
    "is_masquerading_media": 40,
    "has_encrypted_payload": 35,
    "anti_security_evasion": 25,
    "social_engineering_lure": 20,
    "many_dangerous_permissions": 20,
    "overlay_and_accessibility": 30,
    "surveillance_suite": 25,
    "install_packages": 20,
    "hidden_payloads": 25,
    "not_signed": 20,
    "sms_permissions": 20,
    "device_admin": 20,
    "query_all_packages": 15,
    "runtime_perm_evasion": 15,
    "root_tools": 20,
    "brand_spoofing": 20,
    "boot_persistence": 10,
    "debuggable_flag": 10,
}

DANGEROUS_PERMISSION_THRESHOLD = 4


def calculate_static_risk(apk_info: dict) -> dict:
    score = 0
    indicators = []
    positive_signals = []
    mitre_tags = []

    # 1. Masquerading / Double Extension (MITRE ATT&CK Mobile: T1036.007)
    if apk_info.get("is_masquerading_media"):
        score += APK_RISK_WEIGHTS["is_masquerading_media"]
        ext_note = "ilova nomi rasm/hujjat kengaytmasi (.jpeg/.jpg/.pdf) bilan tugaydi" if apk_info.get("app_name_has_media_ext") else "fayl soxta ikki qavatli kengaytmadan foydalanmoqda (.jpeg.apk)"
        indicators.append(
            f"[MITRE T1036.007] Double Extension Masquerading: Disguised as a photo or document ({ext_note}) to fool Telegram/SMS victims into installing malware"
        )
        mitre_tags.append("T1036.007: Double File Extension Masquerading")

    # 2. High-Entropy Encrypted Stager Payload (MITRE ATT&CK Mobile: T1407 / T1027)
    if apk_info.get("has_encrypted_payload"):
        score += APK_RISK_WEIGHTS["has_encrypted_payload"]
        stagers = ", ".join(apk_info["encrypted_stagers"][:2])
        indicators.append(
            f"[MITRE T1027/T1407] Encrypted Stager Payload: Found high-entropy packed binary in assets ({stagers}) designed to evade static scanners and execute Stage-2 banking trojan"
        )
        mitre_tags.append("T1027: Obfuscated/Encrypted Payload")

    # 3. Anti-Analysis & Mobile Antivirus Evasion (MITRE ATT&CK Mobile: T1562.001)
    if apk_info.get("anti_security_evasion"):
        score += APK_RISK_WEIGHTS["anti_security_evasion"]
        tools = apk_info.get("dex_anti_analysis", []) + apk_info.get("dex_anti_av", [])
        tools_str = ", ".join(tools[:6])
        indicators.append(
            f"[MITRE T1562.001] Anti-Analysis & AV Defense Evasion: Contains code specifically looking for analysis environments and mobile antivirus products ({tools_str})"
        )
        mitre_tags.append("T1562.001: Impair Defenses")

    # 4. Social Engineering Lure Keywords
    if apk_info.get("matched_lures"):
        score += APK_RISK_WEIGHTS["social_engineering_lure"]
        lures_str = ", ".join(apk_info["matched_lures"][:4])
        indicators.append(
            f"Social Engineering Lure: Uses psychological lure terms ({lures_str}) commonly seen in phishing wedding-photo / archive campaigns"
        )

    # 5. Banking Trojan / Overlay Hijacking (MITRE ATT&CK Mobile: T1417)
    if apk_info["has_overlay_and_accessibility"]:
        score += APK_RISK_WEIGHTS["overlay_and_accessibility"]
        indicators.append(
            "[MITRE T1417] Critical Banking Trojan Pattern: Requests both SYSTEM_ALERT_WINDOW (screen overlay) "
            "and BIND_ACCESSIBILITY_SERVICE (keystroke and UI hijacking) - signature of advanced Android trojans"
        )
        mitre_tags.append("T1417: Input Capture & Overlay")
    else:
        positive_signals.append("No overlay + accessibility-service combination detected")

    # 6. Spyware / Surveillance Profile (MITRE ATT&CK Mobile: T1430, T1429)
    if apk_info.get("has_broad_surveillance"):
        score += APK_RISK_WEIGHTS["surveillance_suite"]
        surv_perms = ", ".join(p.replace("android.permission.", "") for p in apk_info["surveillance_permissions"])
        indicators.append(
            f"[MITRE T1430/T1429] Broad Surveillance / Spyware Profile: Requests concurrent access to {surv_perms}"
        )
        mitre_tags.append("T1430: Location & Sensor Tracking")
    elif len(apk_info["dangerous_permissions"]) >= DANGEROUS_PERMISSION_THRESHOLD:
        score += APK_RISK_WEIGHTS["many_dangerous_permissions"]
        perms = ", ".join(p.replace("android.permission.", "") for p in apk_info["dangerous_permissions"][:6])
        indicators.append(f"Requests an unusually high number of sensitive permissions: {perms}")
    else:
        positive_signals.append("Requested permissions are within a normal range")

    # 7. Hidden Secondary Payloads / Dropper Stager (MITRE ATT&CK Mobile: T1407)
    if apk_info.get("has_hidden_payloads"):
        score += APK_RISK_WEIGHTS["hidden_payloads"]
        files = ", ".join(apk_info["hidden_payloads"][:3])
        indicators.append(
            f"[MITRE T1407] Hidden Executable Payload: Found suspicious embedded binary files inside archive ({files}) - classic dropper technique"
        )
        mitre_tags.append("T1407: Download / Load Secondary Code")

    # 8. Dropper Behavior: Requesting Package Installation
    if apk_info["requests_install_packages"]:
        score += APK_RISK_WEIGHTS["install_packages"]
        indicators.append(
            "[MITRE T1475] Dropper / App Installer: Can silently request or trigger installation of secondary APK packages"
        )
        mitre_tags.append("T1475: Install Additional Apps")
    else:
        positive_signals.append("Does not request permission to install other packages")

    # 9. SMS Fraud / Interception (MITRE ATT&CK Mobile: T1412)
    if apk_info["has_sms_permissions"]:
        score += APK_RISK_WEIGHTS["sms_permissions"]
        indicators.append(
            "[MITRE T1412] SMS Fraud / OTP Interception: Requests SMS read/write/receive permissions - vulnerable to 2FA code theft"
        )
        mitre_tags.append("T1412: SMS Data Capture")
    else:
        positive_signals.append("No SMS-related permissions requested")

    # 10. Device Admin Privileges (MITRE ATT&CK Mobile: T1400)
    if apk_info["requests_device_admin"]:
        score += APK_RISK_WEIGHTS["device_admin"]
        indicators.append(
            "[MITRE T1400] Ransomware / Evasion Defense: Requests BIND_DEVICE_ADMIN privileges to prevent app uninstallation and lock device"
        )
        mitre_tags.append("T1400: Device Admin Abuse")
    else:
        positive_signals.append("Does not request device administrator privileges")

    # 11. Package Enumeration (Target Discovery)
    if apk_info.get("queries_all_packages"):
        score += APK_RISK_WEIGHTS["query_all_packages"]
        indicators.append(
            "[MITRE T1418] Financial App Reconnaissance: Requests QUERY_ALL_PACKAGES to inventory all installed banking and cryptocurrency apps"
        )
        mitre_tags.append("T1418: Application Discovery")

    # 12. Runtime Permission Evasion (Target SDK < 23)
    if apk_info.get("evades_runtime_permissions"):
        score += APK_RISK_WEIGHTS["runtime_perm_evasion"]
        indicators.append(
            f"Permission Evasion: Target SDK version ({apk_info['target_sdk']}) bypasses Android 6.0+ runtime permission prompts"
        )

    # 13. Brand Impersonation / Typosquatting
    if apk_info.get("spoofed_brand"):
        score += APK_RISK_WEIGHTS["brand_spoofing"]
        indicators.append(
            f"Brand Spoofing Risk: Package or application name references financial brand '{apk_info['spoofed_brand']}' without verified domain binding"
        )

    # 14. Root exploitation tools
    if apk_info.get("has_root_tools"):
        score += APK_RISK_WEIGHTS["root_tools"]
        indicators.append("Root Exploitation: Contains embedded binaries associated with root privilege escalation (su/magisk)")

    # 15. Digital Signature Check
    if not apk_info["is_signed"]:
        score += APK_RISK_WEIGHTS["not_signed"]
        indicators.append("Untrusted APK: The application has no valid digital signature block")
    else:
        positive_signals.append("The APK includes a valid cryptographic signature block")

    # 16. Persistence / Battery optimization evasion
    if apk_info.get("ignores_battery_opt") and apk_info.get("boot_persistence"):
        score += APK_RISK_WEIGHTS["boot_persistence"]
        indicators.append("Aggressive Persistence: Configured to autostart on boot (RECEIVE_BOOT_COMPLETED) and bypass battery sleep restrictions")

    # 17. Debuggable Flag
    if apk_info.get("is_debuggable"):
        score += APK_RISK_WEIGHTS["debuggable_flag"]
        indicators.append("Tampering Exposure: Application is marked as debuggable in manifest (allows memory dumping and code injection)")

    # Compound Threat Multipliers
    is_masq = apk_info.get("is_masquerading_media", False)
    has_enc = apk_info.get("has_encrypted_payload", False)
    req_inst = apk_info.get("requests_install_packages", False)
    has_dropper_combo = is_masq and (req_inst or has_enc)

    if has_dropper_combo:
        score += 30
        indicators.append(
            "[CRITICAL THREAT] Confirmed Malicious Trojan-Dropper: Combines media file masquerading with package installer execution / encrypted stagers"
        )
        mitre_tags.append("T1475: Dropper Execution")

    critical_triggers = sum([
        apk_info["has_overlay_and_accessibility"],
        apk_info.get("has_hidden_payloads", False),
        has_enc,
        is_masq,
        has_dropper_combo,
        apk_info["has_sms_permissions"] and req_inst,
        apk_info["requests_device_admin"] and apk_info.get("has_overlay", False),
    ])
    if critical_triggers >= 2:
        score += 20
        indicators.append("Compound Multiplier: Multiple critical threat signatures detected simultaneously, elevating risk confidence")

    final_score = min(max(score, 0), 100)
    return {
        "static_risk_score": final_score,
        "indicators": indicators,
        "positive_signals": positive_signals,
        "mitre_tags": mitre_tags,
    }

