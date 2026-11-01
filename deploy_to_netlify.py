"""
deploy_to_netlify.py
--------------------
PhishGuard AI Frontendini to'g'ridan-to'g'ri Netlify API orqali avtomatik deploy qilish skripti.
Zero-dependency: faqat Python standart kutubxonasi (zipfile, io) va 'requests' ishlatadi.

Ishlatish:
  python deploy_to_netlify.py --token <SIZNING_NETLIFY_TOKENINGIZ>
  yoki .env faylida NETLIFY_AUTH_TOKEN ko'rsatilgan bo'lsa:
  python deploy_to_netlify.py
"""

import os
import sys
import io
import zipfile
import argparse
from pathlib import Path

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import requests
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent
load_dotenv(ROOT_DIR / "backend" / ".env")
load_dotenv(ROOT_DIR / ".env")

FRONTEND_DIR = ROOT_DIR / "frontend"
NETLIFY_API_BASE = "https://api.netlify.com/api/v1"


def create_frontend_zip() -> bytes:
    """Frontend papkasidagi barcha fayllarni (HTML, CSS, JS, _redirects) xotirada ZIP arxiviga aylantiradi."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in FRONTEND_DIR.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(FRONTEND_DIR)
                # Ignore git or temporary files
                if any(part.startswith(".") for part in rel_path.parts):
                    if rel_path.name != "_redirects":
                        continue
                zf.write(file_path, arcname=str(rel_path).replace("\\", "/"))
    zip_buffer.seek(0)
    return zip_buffer.getvalue()


def deploy_site(token: str, site_name: str = "phishguard-ai-soc") -> dict:
    if not token:
        raise ValueError("Netlify shaxsiy kirish tokeni (Personal Access Token) topilmadi.")

    print(f"📦 1. Frontend fayllari arxivlanmoqda ({FRONTEND_DIR})...")
    zip_bytes = create_frontend_zip()
    print(f"   Arxiv hajmi: {len(zip_bytes) / 1024:.1f} KB")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/zip",
    }

    print("🚀 2. Netlify API orqali sayt yaratilmoqda va yuklanmoqda...")
    # Netlify zip deployment endpoint
    deploy_url = f"{NETLIFY_API_BASE}/sites"
    
    response = requests.post(deploy_url, data=zip_bytes, headers=headers, timeout=60)
    
    if response.status_code not in (200, 201):
        err_msg = response.text
        try:
            err_msg = response.json().get("message", err_msg)
        except Exception:
            pass
        raise RuntimeError(f"Netlify xatolik qaytardi ({response.status_code}): {err_msg}")

    site_data = response.json()
    return site_data


def main():
    parser = argparse.ArgumentParser(description="Deploy PhishGuard AI frontend to Netlify")
    parser.add_argument("--token", help="Netlify Personal Access Token", default=os.environ.get("NETLIFY_AUTH_TOKEN"))
    parser.add_argument("--name", help="Custom site subdomain", default="")
    args = parser.parse_args()

    token = args.token or os.environ.get("NETLIFY_AUTH_TOKEN")
    if not token:
        print("=" * 60)
        print("XATOLIK: Netlify Access Token berilmadi.")
        print("=" * 60)
        print("Token olish juda oson:")
        print("1. https://app.netlify.com/user/applications sahifasiga kiring.")
        print("2. 'Personal access tokens' bo'limida 'New access token' tugmasini bosing.")
        print("3. Yaratilgan tokenni quyidagicha ishga tushiring:")
        print("   python deploy_to_netlify.py --token nfp_xxxxxxxxxxxxxxx")
        sys.exit(1)

    try:
        data = deploy_site(token, args.name)
        url = data.get("ssl_url") or data.get("url")
        admin_url = data.get("admin_url")
        site_id = data.get("id")

        print("=" * 60)
        print("✅ TABRIKLAYMIZ! SAYT NETLIFY'GA MUVAFFAQIYATLI JOYLASHTIRILDI!")
        print("=" * 60)
        print(f"🌐 Jonli sayt manzili: {url}")
        if admin_url:
            print(f"⚙️ Netlify boshqaruv paneli: {admin_url}")
        print(f"🆔 Sayt ID: {site_id}")
        print("=" * 60)
    except Exception as exc:
        print(f"❌ Xatolik yuz berdi: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
