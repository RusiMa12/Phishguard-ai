"""
test_integration.py
--------------------
Полное сквозное тестирование PhishGuard AI - проверяет, что все части
проекта (Phase 1-9) работают вместе правильно.

Это НЕ unit-тесты отдельных функций (они уже есть как `if __name__ ==
"__main__":` блоки в url_features.py, risk_engine.py и т.д.) - это
интеграционные тесты, которые обращаются к РЕАЛЬНО ЗАПУЩЕННОМУ серверу
через HTTP, точно как это делает браузер.

Как запустить:
    1) в одном терминале: uvicorn main:app --port 8000
    2) в другом терминале, из backend/: python test_integration.py

Скрипт печатает PASS/FAIL по каждой проверке и общий итог в конце.
Код выхода: 0 если всё прошло, 1 если хотя бы один тест провалился
(удобно для последующей автоматизации).
"""

import sys
import struct
import time
import requests

BASE_URL = "http://127.0.0.1:8000"
PASSED = []
FAILED = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(name)
        print(f"  FAIL  {name}  {detail}")


def build_minimal_pe(writable_exec: bool = False) -> bytes:
    """Тот же минимальный, но структурно валидный PE-файл, что использовался
    при разработке Phase 4 - без какого-либо реального функционала, только
    заголовки, чтобы pefile мог его корректно разобрать."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 60, 0x40)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 1700000000, 0, 0, 224, 0x0102)
    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 0, 0, 0x200, 0, 0, 0x1000, 0x1000, 0x2000, 0x400000,
        0x1000, 0x200, 4, 0, 0, 0, 4, 0, 0, 0x2000, 0x200, 0, 3, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    optional_header = opt + bytes(16 * 8)
    char = 0x60000020 | (0x80000000 if writable_exec else 0)
    sect = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, char)
    headers = (bytes(dos) + pe_sig + coff + optional_header + sect).ljust(0x200, b"\x00")
    raw = b"\x90\x90\xC3".ljust(0x200, b"\x00")
    return headers + raw


def run_tests():
    print("=" * 60)
    print("PhishGuard AI - Integration Tests")
    print("=" * 60)

    # --- 1. Health ---
    print("\n[1] Health check")
    r = requests.get(f"{BASE_URL}/api/health", timeout=10)
    check("GET /api/health returns 200", r.status_code == 200, f"got {r.status_code}")
    check("health response has status=ok", r.ok and r.json().get("status") == "ok")

    # --- 2. URL analysis: safe ---
    print("\n[2] URL analysis - safe URL")
    r = requests.post(f"{BASE_URL}/api/analyze", json={"url": "https://www.google.com"}, timeout=15)
    check("safe URL returns 200", r.status_code == 200, f"got {r.status_code}")
    data = r.json() if r.ok else {}
    check("safe URL has low risk_score", data.get("risk_score", 100) <= 30, f"got {data.get('risk_score')}")
    check("safe URL classification is Potentially Safe", data.get("classification") == "Potentially Safe")

    # --- 3. URL analysis: phishing-like ---
    print("\n[3] URL analysis - phishing-like URL")
    r = requests.post(
        f"{BASE_URL}/api/analyze",
        json={"url": "http://192.168.1.1/paypal-login/verify-account?user=test@x"},
        timeout=15,
    )
    check("phishing URL returns 200", r.status_code == 200)
    data = r.json() if r.ok else {}
    check("phishing URL has elevated risk_score", data.get("risk_score", 0) >= 50, f"got {data.get('risk_score')}")
    check("phishing URL reasons list is non-empty", len(data.get("reasons", [])) > 0)
    check("phishing URL response includes vt_note (URL VirusTotal check)", bool(data.get("vt_note")))

    # --- 4. URL analysis: input validation ---
    print("\n[4] URL analysis - input validation")
    r = requests.post(f"{BASE_URL}/api/analyze", json={"url": ""}, timeout=10)
    check("empty URL is rejected (422)", r.status_code == 422, f"got {r.status_code}")
    r = requests.post(f"{BASE_URL}/api/analyze", json={"url": "http://" + "a" * 3000 + ".com"}, timeout=10)
    check("oversized URL is rejected (422)", r.status_code == 422, f"got {r.status_code}")
    r = requests.post(f"{BASE_URL}/api/analyze", json={}, timeout=10)
    check("missing field is rejected cleanly, no traceback", r.status_code == 422 and "detail" in r.json())

    # --- 5. EXE analysis: valid file ---
    print("\n[5] EXE analysis - valid PE file")
    pe_bytes = build_minimal_pe(writable_exec=True)
    r = requests.post(
        f"{BASE_URL}/api/analyze-exe",
        files={"file": ("suspicious_test.exe", pe_bytes)},
        timeout=20,
    )
    check("valid EXE returns 200", r.status_code == 200, f"got {r.status_code}")
    data = r.json() if r.ok else {}
    check("EXE response has final_score", "final_score" in data)
    check("W+X section is detected as an indicator", any("writable and executable" in i for i in data.get("indicators", [])))
    check("vt_note is present (VT unavailable or configured)", bool(data.get("vt_note")))

    # --- 6. EXE analysis: rejected inputs ---
    print("\n[6] EXE analysis - rejected inputs")
    r = requests.post(f"{BASE_URL}/api/analyze-exe", files={"file": ("notes.txt", b"hello world")}, timeout=10)
    check("non-.exe file is rejected (400)", r.status_code == 400, f"got {r.status_code}")
    r = requests.post(f"{BASE_URL}/api/analyze-exe", files={"file": ("fake.exe", b"not a real PE file")}, timeout=10)
    check("corrupt .exe is rejected (400), not a 500", r.status_code == 400, f"got {r.status_code}")

    # --- 6b. APK analysis: rejected inputs ---
    # NOTE: a full "valid APK" test isn't included here - unlike the PE test
    # above (built byte-by-byte in build_minimal_pe), a minimal valid APK
    # would require constructing a real ZIP + binary AndroidManifest.xml,
    # which isn't worth the complexity for this test suite. Test with a
    # real .apk locally via the frontend's APK Scanner instead.
    print("\n[6b] APK analysis - rejected inputs")
    r = requests.post(f"{BASE_URL}/api/analyze-apk", files={"file": ("notes.txt", b"hello world")}, timeout=10)
    check("non-.apk file is rejected (400)", r.status_code == 400, f"got {r.status_code}")
    r = requests.post(f"{BASE_URL}/api/analyze-apk", files={"file": ("fake.apk", b"not a real APK/ZIP file")}, timeout=10)
    check("corrupt .apk is rejected (400), not a 500", r.status_code == 400, f"got {r.status_code}")

    # --- 7. Scan history & dashboard ---
    print("\n[7] Scan history & dashboard")
    r = requests.get(f"{BASE_URL}/api/scan-history?limit=5", timeout=10)
    check("scan-history returns 200", r.status_code == 200)
    check("scan-history returns a list", isinstance(r.json(), list))
    r = requests.get(f"{BASE_URL}/api/dashboard", timeout=10)
    check("dashboard returns 200", r.status_code == 200)
    dash = r.json() if r.ok else {}
    check("dashboard total_scans reflects recorded scans", dash.get("total_scans", 0) >= 2, f"got {dash.get('total_scans')}")
    check("dashboard includes apk_scans field", "apk_scans" in dash)

    # --- 8. Enterprise SOC System Status & Auth ---
    print("\n[8] Enterprise SOC System Status & Auth")
    r = requests.get(f"{BASE_URL}/api/system/status", timeout=10)
    check("GET /api/system/status returns 200", r.status_code == 200, f"got {r.status_code}")
    sys_status = r.json() if r.ok else {}
    check("status contains rate_limiter info", "rate_limiter" in sys_status)
    check("status contains dynamic_sandbox info", "dynamic_sandbox" in sys_status)

    # --- 9. Dynamic Behavioral Analysis ---
    print("\n[9] Dynamic Behavioral Analysis Engine")
    r = requests.post(
        f"{BASE_URL}/api/analyze-behavioral",
        json={
            "type": "pe",
            "target_name": "sample_malware.exe",
            "indicators": ["Suspicious API: VirtualAllocEx", "High Entropy"],
            "raw_details": {"suspicious_imports": ["VirtualAllocEx", "WriteProcessMemory", "RegSetValueExA"]},
        },
        timeout=10,
    )
    check("POST /api/analyze-behavioral returns 200", r.status_code == 200, f"got {r.status_code}")
    behav = r.json() if r.ok else {}
    check("behavioral returns process_tree", "process_tree" in behav)
    check("behavioral contains mitre_behaviors", len(behav.get("mitre_behaviors", [])) > 0)

    # --- 10. Rate limiting ---
    print("\n[10] Rate limiting (this takes a moment)")
    statuses = []
    for _ in range(25):
        resp = requests.post(f"{BASE_URL}/api/analyze", json={"url": "https://example.com"}, timeout=10)
        statuses.append(resp.status_code)
    check("rate limit triggers a 429 within rapid requests", 429 in statuses, f"statuses seen: {set(statuses)}")

    # --- Summary ---
    print("\n" + "=" * 60)
    print(f"RESULT: {len(PASSED)} passed, {len(FAILED)} failed")
    print("=" * 60)
    if FAILED:
        print("Failed checks:")
        for name in FAILED:
            print(f"  - {name}")
    return len(FAILED) == 0


if __name__ == "__main__":
    try:
        requests.get(f"{BASE_URL}/api/health", timeout=5)
    except requests.RequestException:
        print(f"ERROR: could not reach {BASE_URL}")
        print("Start the server first: uvicorn main:app --port 8000")
        sys.exit(1)

    success = run_tests()
    sys.exit(0 if success else 1)
