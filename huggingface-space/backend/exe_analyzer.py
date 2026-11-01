"""
exe_analyzer.py
----------------
Статический анализ Windows-исполняемых файлов (PE - Portable Executable).

ГЛАВНОЕ ПРАВИЛО БЕЗОПАСНОСТИ: файл НИКОГДА не запускается и не
интерпретируется как код. Вся работа - это чтение и разбор его
внутренней структуры (заголовки, секции, таблица импортов) как
обычных байтов, с помощью библиотеки pefile.

Что такое PE-файл (для отчёта/защиты курсовой):
Windows-программы (.exe, .dll) хранятся в формате PE - это структура
с заголовками (сколько секций кода/данных, откуда начинается выполнение),
самими секциями (код, данные, ресурсы) и таблицей импортов (какие функции
из каких системных библиотек программа собирается использовать).
Вредоносные программы часто имеют характерные отклонения в этой структуре -
их мы и ищем.
"""

import hashlib
import math
import time
from datetime import datetime, timezone

import pefile

# API-функции, которые часто используются вредоносным ПО. Само по себе
# наличие одной такой функции ничего не доказывает - многие легитimate
# программы тоже их используют. Сигналом считается только СОЧЕТАНИЕ
# нескольких таких функций (см. SUSPICIOUS_API_THRESHOLD ниже).
# API-функции, которые часто используются вредоносным ПО.
SUSPICIOUS_APIS = {
    # Memory allocation and injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
    "QueueUserAPC", "SetThreadContext", "GetThreadContext", "ResumeThread",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    # Dynamic library resolution
    "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    # Input capture & Keylogging
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
    # Process creation & command execution
    "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "CreateProcessA", "CreateProcessW",
    # Anti-analysis & evasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "OutputDebugStringA", "FindWindowA", "FindWindowW",
    # Persistence & registry
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
    # Cryptographic & Ransomware operations
    "CryptEncrypt", "CryptGenRandom", "CryptAcquireContextA", "BCryptEncrypt",
    # Network, C2 & Download
    "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenUrlA",
    "InternetReadFile", "WSAStartup", "connect", "send", "WinHttpOpen", "WinHttpConnect",
    # Privilege escalation & tokens
    "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA", "LookupPrivilegeValueW",
}
SUSPICIOUS_API_THRESHOLD = 3

# MITRE ATT&CK Technique API Clusters
INJECTION_APIS = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC"}
HOLLOWING_APIS = {"NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext", "ResumeThread"}
KEYLOGGING_APIS = {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState"}
ANTI_DEBUG_APIS = {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"}
CRYPTO_APIS = {"CryptEncrypt", "BCryptEncrypt", "CryptGenRandom"}
DOWNLOADER_APIS = {"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA", "WinHttpOpen"}

# Signatures for malicious commands and strings inside executable
DANGEROUS_RAW_STRINGS = [
    (b"vssadmin delete shadows", "Ransomware shadow-copy deletion command (vssadmin)"),
    (b"wbadmin delete catalog", "Backup destruction command (wbadmin)"),
    (b"powershell -enc", "Obfuscated encoded PowerShell invocation"),
    (b"powershell -w hidden", "Hidden window PowerShell execution"),
    (b"cmd.exe /c", "Silent CMD execution pattern"),
    (b"currentversion\\run", "Registry Run key persistence"),
    (b"certutil -urlcache", "Living-off-the-land file retrieval via certutil"),
    (b"bitsadmin /transfer", "Background file transfer via bitsadmin"),
]

# Секции с энтропией выше этого порога считаются "почти случайными"
HIGH_ENTROPY_THRESHOLD = 7.0

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB, требование раздела 18 ТЗ


class InvalidExecutableError(Exception):
    """Файл не является валидным PE-исполняемым файлом."""


def compute_hashes(file_bytes: bytes) -> dict:
    return {
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "md5": hashlib.md5(file_bytes).hexdigest(),
    }


def _machine_type_name(machine: int) -> str:
    return {
        0x14C: "x86 (32-bit)",
        0x8664: "x64 (AMD64)",
        0x1C0: "ARM",
        0xAA64: "ARM64",
    }.get(machine, f"unknown (0x{machine:X})")


def _section_characteristics(section) -> dict:
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_WRITE = 0x80000000
    flags = section.Characteristics
    executable = bool(flags & IMAGE_SCN_MEM_EXECUTE)
    writable = bool(flags & IMAGE_SCN_MEM_WRITE)
    return {"executable": executable, "writable": writable, "writable_and_executable": executable and writable}


KNOWN_PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", ".aspack", ".fsg", ".themida", ".vmp",
    ".mpress", ".nsp", "pecompact", ".petite", "pec2", "pec3", ".enigma",
}


def _scan_embedded_strings(file_bytes: bytes) -> list[str]:
    """Scan raw PE bytes for high-risk commands and persistence mechanisms."""
    found = []
    file_lower = file_bytes.lower()
    for pattern, desc in DANGEROUS_RAW_STRINGS:
        if pattern in file_lower:
            found.append(desc)
    return found



def parse_pe(file_bytes: bytes) -> dict:
    """
    Разбирает PE-структуру файла и возвращает словарь с безопасными
    статическими характеристиками. Файл передаётся как БАЙТЫ в памяти -
    он никогда не пишется на диск и никогда не исполняется.
    """
    if len(file_bytes) < 2 or file_bytes[:2] != b"MZ":
        raise InvalidExecutableError("File does not start with the MZ signature - not a valid Windows executable.")

    try:
        pe = pefile.PE(data=file_bytes, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
            ]
        )
    except pefile.PEFormatError as exc:
        raise InvalidExecutableError(f"The file could not be parsed as a valid PE file: {exc}")

    # --- Заголовки ---
    machine_type = _machine_type_name(pe.FILE_HEADER.Machine)
    entry_point_raw = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entry_point = hex(entry_point_raw)
    image_base = hex(pe.OPTIONAL_HEADER.ImageBase)
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)

    timestamp = pe.FILE_HEADER.TimeDateStamp
    try:
        compile_time = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError, OverflowError):
        compile_time = None

    # --- Секции ---
    sections = []
    entropies = []
    has_writable_executable_section = False
    packer_found = []
    ep_section_name = "unknown"
    ep_in_last_section = False

    for i, section in enumerate(pe.sections):
        name = section.Name.decode(errors="replace").rstrip("\x00")
        lower_name = name.lower()
        if lower_name in KNOWN_PACKER_SECTIONS:
            packer_found.append(name)

        entropy = round(section.get_entropy(), 3)
        entropies.append(entropy)
        chars = _section_characteristics(section)
        if chars["writable_and_executable"]:
            has_writable_executable_section = True

        # Проверка расположения Entry Point
        sec_start = section.VirtualAddress
        sec_end = sec_start + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if sec_start <= entry_point_raw < sec_end:
            ep_section_name = name
            if i == len(pe.sections) - 1 and len(pe.sections) > 1:
                ep_in_last_section = True

        sections.append({
            "name": name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": entropy,
            **chars,
        })

    max_entropy = max(entropies) if entropies else 0.0

    # --- Импорты ---
    imported_dlls = []
    imported_functions = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="replace") if entry.dll else "unknown"
            imported_dlls.append(dll_name)
            for imp in entry.imports:
                if imp.name:
                    imported_functions.append(imp.name.decode(errors="replace"))

    suspicious_found = sorted(set(imported_functions) & SUSPICIOUS_APIS)

    # --- Цифровая подпись и проверка целостности структуры PKCS#7 ---
    has_signature = False
    signature_is_valid_header = False
    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]:
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        if security_dir.VirtualAddress != 0 and security_dir.Size > 8:
            has_signature = True
            try:
                cert_offset = security_dir.VirtualAddress
                cert_size = security_dir.Size
                if cert_offset + cert_size <= len(file_bytes):
                    cert_header = file_bytes[cert_offset:cert_offset + 8]
                    dw_length = int.from_bytes(cert_header[0:4], "little")
                    w_revision = int.from_bytes(cert_header[4:6], "little")
                    w_cert_type = int.from_bytes(cert_header[6:8], "little")
                    if 8 <= dw_length <= cert_size and w_revision in (0x0100, 0x0200) and w_cert_type == 0x0002:
                        signature_is_valid_header = True
            except Exception:
                pass

    # --- TLS Callbacks (код, запускаемый до Entry Point) ---
    has_tls = False
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        has_tls = True
    elif len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]:
        tls_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]]
        has_tls = bool(tls_dir.VirtualAddress != 0 and tls_dir.Size != 0)

    # --- Check section size disparity (uninitialized memory for shellcode / unpacking) ---
    has_section_size_anomaly = False
    for sec in pe.sections:
        if sec.SizeOfRawData > 0 and (sec.Misc_VirtualSize / max(sec.SizeOfRawData, 1)) > 5.0 and sec.Misc_VirtualSize > 65536:
            has_section_size_anomaly = True
            break

    # --- Overlay ---
    overlay_offset = pe.get_overlay_data_start_offset()
    overlay_size = len(file_bytes) - overlay_offset if overlay_offset is not None else 0

    # --- Embedded dangerous string signatures ---
    embedded_threats = _scan_embedded_strings(file_bytes)

    pe.close()

    return {
        "machine_type": machine_type,
        "entry_point": entry_point,
        "image_base": image_base,
        "is_dll": is_dll,
        "compile_timestamp": compile_time,
        "compile_timestamp_raw": timestamp,
        "number_of_sections": len(sections),
        "sections": sections,
        "max_section_entropy": max_entropy,
        "has_writable_executable_section": has_writable_executable_section,
        "has_packer_sections": len(packer_found) > 0,
        "packer_section_name": ", ".join(packer_found),
        "ep_section_name": ep_section_name,
        "ep_in_last_section": ep_in_last_section,
        "has_tls_callbacks": has_tls,
        "has_section_size_anomaly": has_section_size_anomaly,
        "embedded_threats": embedded_threats,
        "imported_dll_count": len(imported_dlls),
        "imported_function_count": len(imported_functions),
        "imported_dlls": imported_dlls,
        "suspicious_imports": suspicious_found,
        "has_digital_signature": has_signature,
        "signature_is_valid_header": signature_is_valid_header,
        "overlay_size": overlay_size,
    }


# --- Rule-based статический Risk Score ---

STATIC_RISK_WEIGHTS = {
    "high_entropy": 25,
    "writable_executable_section": 25,
    "suspicious_imports": 20,
    "packer_detected": 20,
    "ep_anomaly": 15,
    "forged_signature": 15,
    "no_signature": 10,
    "tls_callbacks": 10,
    "large_overlay": 10,
    "bad_timestamp": 10,
    "few_imports": 10,
    "section_size_anomaly": 15,
    "embedded_threats": 25,
    "attack_cluster": 20,
}
LARGE_OVERLAY_THRESHOLD = 100 * 1024  # 100 KB


def calculate_static_risk(pe_info: dict) -> dict:
    """Тот же принцип, что и в risk_engine.py для URL: явные правила с весами,
    результат от 0 до 100, плюс список причин на понятном языке."""
    score = 0
    indicators = []
    positive_signals = []

    if pe_info["max_section_entropy"] >= HIGH_ENTROPY_THRESHOLD:
        score += STATIC_RISK_WEIGHTS["high_entropy"]
        indicators.append(f"High section entropy detected ({pe_info['max_section_entropy']}) - possible packing or encryption")
    else:
        positive_signals.append("Section entropy is within a normal range (no signs of packing)")

    if pe_info["has_writable_executable_section"]:
        score += STATIC_RISK_WEIGHTS["writable_executable_section"]
        indicators.append("A section is both writable and executable - unusual for normal compiled programs")
    else:
        positive_signals.append("No writable+executable sections found")

    if pe_info.get("has_packer_sections"):
        score += STATIC_RISK_WEIGHTS["packer_detected"]
        indicators.append(f"Known executable packer/protector signature detected ({pe_info['packer_section_name']})")

    if pe_info.get("ep_in_last_section"):
        score += STATIC_RISK_WEIGHTS["ep_anomaly"]
        indicators.append(f"Entry point is located in the last section ({pe_info.get('ep_section_name')}) - common pattern of injected shellcode")

    if pe_info.get("has_tls_callbacks"):
        score += STATIC_RISK_WEIGHTS["tls_callbacks"]
        indicators.append("Thread Local Storage (TLS) callbacks detected - code executes before the main entry point")

    # Section VirtualSize vs RawSize disparity (unpacking staging)
    if pe_info.get("has_section_size_anomaly"):
        score += STATIC_RISK_WEIGHTS["section_size_anomaly"]
        indicators.append("Section size anomaly: Virtual memory reservation is significantly larger than raw disk size (staging for unpacked payload)")

    # Embedded command / threat signatures
    if pe_info.get("embedded_threats"):
        score += STATIC_RISK_WEIGHTS["embedded_threats"]
        for threat_desc in pe_info["embedded_threats"][:3]:
            indicators.append(f"Malicious string signature detected: {threat_desc}")

    # MITRE ATT&CK Correlated API clusters
    imports_set = set(pe_info.get("suspicious_imports", []))
    if INJECTION_APIS & imports_set and len(INJECTION_APIS & imports_set) >= 2:
        score += STATIC_RISK_WEIGHTS["attack_cluster"]
        matched = ", ".join(INJECTION_APIS & imports_set)
        indicators.append(f"[MITRE T1055] Process Injection pattern: Imports coordinated memory injection APIs ({matched})")

    if HOLLOWING_APIS & imports_set and len(HOLLOWING_APIS & imports_set) >= 2:
        score += STATIC_RISK_WEIGHTS["attack_cluster"]
        matched = ", ".join(HOLLOWING_APIS & imports_set)
        indicators.append(f"[MITRE T1055.012] Process Hollowing / RunPE pattern: Imports section unmapping & thread context APIs ({matched})")

    if KEYLOGGING_APIS & imports_set:
        score += 15
        matched = ", ".join(KEYLOGGING_APIS & imports_set)
        indicators.append(f"[MITRE T1056.001] Input Capture / Keylogger: Imports keystroke monitoring APIs ({matched})")

    if ANTI_DEBUG_APIS & imports_set and len(ANTI_DEBUG_APIS & imports_set) >= 2:
        score += 10
        matched = ", ".join(ANTI_DEBUG_APIS & imports_set)
        indicators.append(f"[MITRE T1622] Anti-Debugging & Evasion: Imports debugger detection APIs ({matched})")

    if len(pe_info["suspicious_imports"]) >= SUSPICIOUS_API_THRESHOLD:
        score += STATIC_RISK_WEIGHTS["suspicious_imports"]
        apis = ", ".join(pe_info["suspicious_imports"][:6])
        indicators.append(f"Multiple sensitive API imports detected: {apis}")
    else:
        positive_signals.append("No unusual combination of sensitive API imports")

    if not pe_info["has_digital_signature"]:
        score += STATIC_RISK_WEIGHTS["no_signature"]
        indicators.append("The executable is not digitally signed")
    elif not pe_info.get("signature_is_valid_header", True):
        score += STATIC_RISK_WEIGHTS["forged_signature"]
        indicators.append("Malformed or forged digital signature header detected (tampered security directory)")
    else:
        positive_signals.append("The executable includes a structurally valid PKCS#7 digital signature block")

    if pe_info["overlay_size"] > LARGE_OVERLAY_THRESHOLD:
        score += STATIC_RISK_WEIGHTS["large_overlay"]
        indicators.append(f"A large amount of data ({pe_info['overlay_size']} bytes) is appended after the PE structure (overlay)")
    else:
        positive_signals.append("No unusually large overlay data found")

    if pe_info["compile_timestamp"] is None or pe_info["compile_timestamp_raw"] == 0:
        score += STATIC_RISK_WEIGHTS["bad_timestamp"]
        indicators.append("The compile timestamp is missing or invalid - sometimes altered to hide build origin")
    else:
        positive_signals.append("The compile timestamp looks valid")

    if pe_info["imported_function_count"] < 3:
        score += STATIC_RISK_WEIGHTS["few_imports"]
        indicators.append("Very few imported functions - can indicate obfuscation or dynamic API resolution")
    else:
        positive_signals.append("A normal number of imported functions were found")

    # Multi-threat amplification (Compound multiplier)
    critical_pe_triggers = sum([
        pe_info["has_writable_executable_section"],
        pe_info["max_section_entropy"] >= HIGH_ENTROPY_THRESHOLD,
        bool(INJECTION_APIS & imports_set and len(INJECTION_APIS & imports_set) >= 2),
        bool(pe_info.get("has_packer_sections")),
        bool(pe_info.get("embedded_threats")),
    ])
    if critical_pe_triggers >= 2:
        score += 15
        indicators.append("Compound Multiplier: Co-occurrence of multiple high-severity evasion and code execution indicators")

    final_score = min(max(score, 0), 100)
    return {
        "static_risk_score": final_score,
        "indicators": indicators,
        "positive_signals": positive_signals,
    }



def combine_static_and_ml(static_result: dict, ml_probability) -> dict:
    """
    Объединяет static_risk_score (правила из calculate_static_risk) с
    ML-вероятностью в единый Final Score - тот же принцип, что и
    risk_engine.combine_with_ml() для URL.

    Сейчас (Phase 5) это временная, простая формула 50/50 - у нас всего
    два источника сопоставимой надёжности (оба вычислены статически, без
    внешней проверки). В Phase 7, когда добавится VirusTotal, здесь
    появится полноценный risk_fusion.py с тремя источниками и более
    детально обоснованными весами.
    """
    result = dict(static_result)

    if ml_probability is None:
        result["final_score"] = static_result["static_risk_score"]
        result["ml_available"] = False
        result["local_ai_score"] = None
        return result

    local_ai_score = round(ml_probability * 100)
    final_score = round(0.5 * static_result["static_risk_score"] + 0.5 * local_ai_score)
    result["final_score"] = min(max(final_score, 0), 100)
    result["ml_available"] = True
    result["local_ai_score"] = local_ai_score
    return result


# --- Признаки для ML-модели (Phase 5) ---

# Тот же принцип, что и ML_FEATURE_COLUMNS в url_features.py: фиксированный
# порядок числовых признаков, одинаковый и при обучении, и при предсказании.
EXE_ML_FEATURE_COLUMNS = [
    "file_size", "number_of_sections", "max_section_entropy",
    "has_writable_executable_section", "imported_dll_count",
    "imported_function_count", "suspicious_import_count",
    "has_digital_signature", "overlay_size", "is_dll",
    "has_valid_timestamp",
]


def exe_features_to_vector(file_size: int, pe_info: dict) -> dict:
    """Превращает результат parse_pe() в плоский числовой словарь для ML,
    в том же духе, что и features_to_vector() в url_features.py."""
    return {
        "file_size": file_size,
        "number_of_sections": pe_info["number_of_sections"],
        "max_section_entropy": pe_info["max_section_entropy"],
        "has_writable_executable_section": int(pe_info["has_writable_executable_section"]),
        "imported_dll_count": pe_info["imported_dll_count"],
        "imported_function_count": pe_info["imported_function_count"],
        "suspicious_import_count": len(pe_info["suspicious_imports"]),
        "has_digital_signature": int(pe_info["has_digital_signature"]),
        "overlay_size": pe_info["overlay_size"],
        "is_dll": int(pe_info["is_dll"]),
        "has_valid_timestamp": int(pe_info["compile_timestamp"] is not None and pe_info["compile_timestamp_raw"] != 0),
    }
