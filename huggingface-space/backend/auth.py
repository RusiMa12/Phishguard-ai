"""
auth.py
-------
PhishGuard AI — Korporativ SOC Autentifikatsiya va Ruxsatlar Tizimi (RBAC).

Xususiyatlari:
  1) Role-Based Access Control (RBAC):
     - 'ADMIN': Barcha operatsiyalar, konfiguratsiya va tizim monitoringi.
     - 'ANALYST': URL, EXE, APK tahlillari, YARA qoidalarini yaratish va hisobotlarni eksport qilish.
     - 'VIEWER': Faqat Dashboard va skanerlash tarixini ko'rish.
  2) Moslashuvchan rejim:
     - API_KEY_REQUIRED=False (sukut bo'yicha): O'quv muhiti, lokal sinovlar va mavjud frontend
       uchun avtomatik ruxsat beradi.
     - API_KEY_REQUIRED=True: Korporativ production / SOC tarmog'ida qat'iy API kalitlarini talab qiladi.
  3) 'X-API-Key' sarlavhasi yoki 'Authorization: Bearer <kalit>' orqali qabul qilinadi.
"""

import os
from typing import Optional, Dict, Any, List
from fastapi import Request, HTTPException, Security, status
from fastapi.security import APIKeyHeader

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Konfiguratsiya (.env orqali o'rnatiladi)
API_KEY_REQUIRED = os.environ.get("API_KEY_REQUIRED", "false").lower() in ("true", "1", "yes")

# Rolli API kalitlari
DEFAULT_KEYS = {
    os.environ.get("PHISHGUARD_ADMIN_KEY", "pg-admin-supersecret-token"): "ADMIN",
    os.environ.get("PHISHGUARD_ANALYST_KEY", "pg-analyst-soc-token"): "ANALYST",
    os.environ.get("PHISHGUARD_VIEWER_KEY", "pg-viewer-public-token"): "VIEWER",
}


class UserRole:
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"
    ANONYMOUS = "ANONYMOUS"


def get_current_role(request: Request) -> Dict[str, Any]:
    """
    So'rov yuborgan foydalanuvchining roli va ma'lumotlarini aniqlaydi.
    """
    # 1. 'X-API-Key' sarlavhasini tekshirish
    api_key = request.headers.get("X-API-Key")

    # 2. 'Authorization: Bearer ...' sarlavhasini tekshirish
    if not api_key:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            api_key = auth_header.split(" ", 1)[1].strip()

    # 3. Agar kalit mavjud bo'lsa
    if api_key:
        role = DEFAULT_KEYS.get(api_key)
        if role:
            return {"authenticated": True, "role": role, "key_id": api_key[:6] + "..."}
        if API_KEY_REQUIRED:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Noto'g'ri yoki muddati o'tgan API kaliti taqdim etildi.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 4. Agar kalit berilmagan bo'lsa
    if API_KEY_REQUIRED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tizimga kirish uchun 'X-API-Key' yoki 'Authorization: Bearer <key>' sarlavhasi talab qilinadi.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Ochiq (O'quv/Development) rejimida to'liq ruxsat (ANALYST roli bilan) beriladi
    return {"authenticated": False, "role": UserRole.ANALYST, "key_id": "open-access"}


def require_roles(allowed_roles: List[str]):
    """
    Muayyan rollarga ega foydalanuvchilargina endpointga kirishini ta'minlovchi dekorator/dependency.
    """
    def role_checker(request: Request):
        user_info = get_current_role(request)
        if user_info["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Ushbu amalni bajarish uchun ruxsat yetarli emas. Talab qilinadigan rollar: {allowed_roles}",
            )
        return user_info
    return role_checker
