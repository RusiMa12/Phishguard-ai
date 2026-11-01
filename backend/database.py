"""
database.py
-----------
Хранилище истории сканирований на SQLite - встроено в Python, не требует
установки отдельного сервера БД. Каждая проверка URL или EXE записывается
сюда одной строкой; из этих записей строятся Dashboard (раздел 15 ТЗ)
и Scan History (раздел 16 ТЗ).

ПРИВАТНОСТЬ (раздел 16 ТЗ - "для URL не сохраняй чувствительные данные"):
для URL сохраняется только hostname (например "example.com"), а НЕ весь
URL целиком - полный URL может содержать query-параметры с личными
данными (токены авторизации, email, id пользователя и т.д.).
"""

import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "phishguard.db"

# Все возможные уровни риска - используется, чтобы в статистике Dashboard
# показывались нули для уровней, которые ещё ни разу не встречались,
# а не пропускались молча.
ALL_RISK_LEVELS = ["VERY_LOW", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Создаёт таблицу scans, если её ещё нет. Вызывается один раз при старте сервера."""
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,       -- 'URL', 'EXE' или 'APK'
            target TEXT NOT NULL,          -- hostname (для URL) или имя файла (для EXE/APK)
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,      -- VERY_LOW / LOW / MEDIUM / HIGH / CRITICAL
            classification TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def record_scan(scan_type: str, target: str, risk_score: int, risk_level: str, classification: str):
    """Добавляет одну запись в историю. Вызывается из routes.py после каждого анализа."""
    conn = _connect()
    conn.execute(
        "INSERT INTO scans (scan_type, target, risk_score, risk_level, classification, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (scan_type, target, risk_score, risk_level, classification, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()


def get_recent_scans(limit: int = 50, search: str = "", scan_type: str = "", risk_level: str = "") -> list:
    conn = _connect()
    query = "SELECT scan_type, target, risk_score, risk_level, classification, created_at FROM scans WHERE 1=1"
    params = []
    if search:
        query += " AND target LIKE ?"
        params.append(f"%{search.strip()}%")
    if scan_type and scan_type.upper() != "ALL":
        query += " AND scan_type = ?"
        params.append(scan_type.strip().upper())
    if risk_level and risk_level.upper() != "ALL":
        query += " AND risk_level = ?"
        params.append(risk_level.strip().upper())
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, tuple(params)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_dashboard_stats() -> dict:
    conn = _connect()

    total = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
    url_count = conn.execute("SELECT COUNT(*) c FROM scans WHERE scan_type = 'URL'").fetchone()["c"]
    exe_count = conn.execute("SELECT COUNT(*) c FROM scans WHERE scan_type = 'EXE'").fetchone()["c"]
    apk_count = conn.execute("SELECT COUNT(*) c FROM scans WHERE scan_type = 'APK'").fetchone()["c"]
    threats = conn.execute(
        "SELECT COUNT(*) c FROM scans WHERE risk_level IN ('HIGH', 'CRITICAL')"
    ).fetchone()["c"]
    avg_row = conn.execute("SELECT AVG(risk_score) a FROM scans").fetchone()
    average_risk = round(avg_row["a"]) if avg_row["a"] is not None else 0

    raw_level_counts = {
        row["risk_level"]: row["c"]
        for row in conn.execute("SELECT risk_level, COUNT(*) c FROM scans GROUP BY risk_level").fetchall()
    }
    level_counts = {level: raw_level_counts.get(level, 0) for level in ALL_RISK_LEVELS}

    conn.close()

    return {
        "total_scans": total,
        "url_scans": url_count,
        "exe_scans": exe_count,
        "apk_scans": apk_count,
        "threats_detected": threats,
        "average_risk": average_risk,
        "level_counts": level_counts,
        "classification_breakdown": {
            "safe": level_counts["VERY_LOW"] + level_counts["LOW"],
            "suspicious": level_counts["MEDIUM"],
            "malicious": level_counts["HIGH"] + level_counts["CRITICAL"],
        },
    }
