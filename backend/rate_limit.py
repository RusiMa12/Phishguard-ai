"""
rate_limit.py
-------------
Taqsimlangan (Distributed) va Mahalliy (In-Memory) Rate Limiting moduli.

Xususiyatlari:
  1) Redis integratsiyasi: Agar REDIS_URL berilgan bo'lsa va redis kutubxonasi mavjud bo'lsa,
     ko'p serverli / ko'p workerli (cluster) rejimda taqsimlangan rate limiting ishlatiladi.
  2) Avtomatik Fallback: Agar Redis mavjud bo'lmasa yoki ulanishda xatolik yuz bersa,
     tizim avtomatik ravishda xavfsiz in-memory (thread-safe Lock) rejimiga o'tadi.
  3) Dinamik sozlash: RATE_LIMIT_MAX_REQUESTS va RATE_LIMIT_WINDOW_SECONDS orqali
     cheklovlarni .env fayldan boshqarish mumkin.
"""

import os
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, Any, Optional
from fastapi import Request, HTTPException

# Konfiguratsiya (.env orqali boshqariladi)
WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", 60))
MAX_REQUESTS_PER_WINDOW = int(os.environ.get("RATE_LIMIT_MAX_REQUESTS", 20))
REDIS_URL = os.environ.get("REDIS_URL", "").strip()

# In-Memory saqlash mexanizmi (Fallback va lokal muhit uchun)
_requests: dict = defaultdict(list)
_lock = Lock()

# Redis mijozi (ixtiyoriy)
_redis_client = None
_redis_available = False

if REDIS_URL:
    try:
        import redis
        _redis_client = redis.from_url(REDIS_URL, socket_timeout=2.0, socket_connect_timeout=2.0)
        _redis_client.ping()
        _redis_available = True
    except Exception as exc:
        _redis_available = False
        _redis_client = None


def get_rate_limiter_status() -> Dict[str, Any]:
    """Rate limiter joriy holati va ishlatilayotgan backend haqida ma'lumot."""
    return {
        "backend": "redis" if _redis_available and _redis_client else "in_memory",
        "redis_configured": bool(REDIS_URL),
        "redis_connected": _redis_available,
        "window_seconds": WINDOW_SECONDS,
        "max_requests": MAX_REQUESTS_PER_WINDOW,
    }


def _client_ip(request: Request) -> str:
    # Nginx / Reverse Proxy / Cloudflare ortida haqiqiy IP-manzilni olish
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
        if client_ip:
            return client_ip
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


def _check_redis_rate_limit(ip: str) -> bool:
    """Redis atomik tranzaksiyasi orqali so'rovlar chegarasini tekshirish."""
    global _redis_available
    if not _redis_client:
        return False

    key = f"phishguard:ratelimit:{ip}"
    try:
        current = _redis_client.incr(key)
        if current == 1:
            _redis_client.expire(key, WINDOW_SECONDS)
        return current <= MAX_REQUESTS_PER_WINDOW
    except Exception:
        # Redis vaqtincha uzilsa, xatolik berib qolmasdan in-memory rejimiga o'tadi
        _redis_available = False
        return False


def enforce_rate_limit(request: Request):
    """
    FastAPI-bog'liqligi (dependency).
    So'rovlar soni belgilangan limitdan oshganda HTTPException 429 xatosini qaytaradi.
    """
    ip = _client_ip(request)
    now = time.time()

    # 1. Agar Redis sozlangan va faol bo'lsa, Redis orqali tekshirish
    if _redis_available and _redis_client:
        allowed = _check_redis_rate_limit(ip)
        if not allowed and _redis_available:
            raise HTTPException(
                status_code=429,
                detail=f"Too many requests. Limit is {MAX_REQUESTS_PER_WINDOW} requests per {WINDOW_SECONDS} seconds - please slow down.",
            )
        elif allowed:
            return

    # 2. In-Memory fallback tekshiruvi (Thread-safe)
    with _lock:
        # Xotirani keraksiz eski yozuvlardan tozalash (Memory leak oldini olish)
        if len(_requests) > 200:
            dead_ips = [k for k, v in _requests.items() if not v or (now - v[-1] >= WINDOW_SECONDS)]
            for k in dead_ips:
                del _requests[k]

        timestamps = _requests[ip]
        # Faqat joriy oyna (WINDOW_SECONDS) ichidagi so'rovlarni qoldirish
        timestamps[:] = [t for t in timestamps if now - t < WINDOW_SECONDS]

        if len(timestamps) >= MAX_REQUESTS_PER_WINDOW:
            raise HTTPException(
                status_code=429,
                detail=f"Too many requests. Limit is {MAX_REQUESTS_PER_WINDOW} requests per {WINDOW_SECONDS} seconds - please slow down.",
            )

        timestamps.append(now)
