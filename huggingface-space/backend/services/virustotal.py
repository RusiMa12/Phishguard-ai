"""
services/virustotal.py
-----------------------
Второй, независимый уровень анализа EXE-файлов - проверка через
VirusTotal (сервис, объединяющий десятки антивирусных движков).

БЕЗОПАСНОСТЬ API-КЛЮЧА (раздел 10 ТЗ):
  - ключ ЧИТАЕТСЯ из переменной окружения VIRUSTOTAL_API_KEY, он НИКОГДА
    не хранится в коде;
  - используйте .env файл локально (см. .env.example) - .env добавлен
    в .gitignore и никогда не попадёт в git/GitHub;
  - ключ никогда не логируется и не возвращается клиенту.

Архитектура:
    EXE -> SHA-256 -> VirusTotal (проверка уже известного хэша)
                        |
                        +-- если файл неизвестен VirusTotal и разрешена
                            загрузка -> upload -> статус "pending"
                            (сам анализ на стороне VirusTotal занимает
                            время, поэтому мы не блокируем запрос -
                            см. check_analysis_status ниже)
"""

import os
import base64
import requests

VT_API_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 15  # секунд - не даём запросу зависнуть навсегда


def get_api_key():
    """Читает ключ из переменной окружения. None, если не настроен."""
    return os.environ.get("VIRUSTOTAL_API_KEY") or None


def is_configured() -> bool:
    return get_api_key() is not None


def _headers():
    return {"x-apikey": get_api_key()}


def _stats_to_result(stats: dict, extra: dict = None) -> dict:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0) + stats.get("harmless", 0)
    total = malicious + suspicious + undetected + stats.get("timeout", 0)
    result = {
        "status": "completed",
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "total_engines": total,
    }
    if extra:
        result.update(extra)
    return result


def lookup_hash(sha256: str) -> dict:
    """
    Проверяет, известен ли файл VirusTotal по его SHA-256 - самый
    частый и быстрый случай (не требует загрузки самого файла).

    Возвращает один из статусов:
      not_configured - ключ не задан (см. .env.example)
      completed      - есть отчёт, malicious/suspicious/undetected заполнены
      not_found      - VirusTotal раньше не видел этот файл
      unavailable    - сетевая ошибка, таймаут, или сам VirusTotal недоступен
    """
    if not is_configured():
        return {"status": "not_configured"}

    try:
        response = requests.get(
            f"{VT_API_BASE}/files/{sha256}",
            headers=_headers(),
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        return {"status": "unavailable"}

    if response.status_code == 404:
        return {"status": "not_found"}
    if response.status_code == 401:
        return {"status": "unavailable", "detail": "Invalid VirusTotal API key"}
    if response.status_code == 429:
        return {"status": "unavailable", "detail": "VirusTotal rate limit reached - try again later"}
    if response.status_code != 200:
        return {"status": "unavailable"}

    try:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        permalink = f"https://www.virustotal.com/gui/file/{sha256}"
        return _stats_to_result(stats, extra={"permalink": permalink})
    except (KeyError, ValueError):
        return {"status": "unavailable"}


def upload_file(file_bytes: bytes, filename: str) -> dict:
    """
    Загружает файл в VirusTotal для анализа, если хэш ещё неизвестен.
    VirusTotal сам анализ выполняет не мгновенно, поэтому мы НЕ ждём
    результат здесь - возвращаем analysis_id и статус "pending",
    результат можно проверить через check_analysis_status() позже.
    """
    if not is_configured():
        return {"status": "not_configured"}

    try:
        response = requests.post(
            f"{VT_API_BASE}/files",
            headers=_headers(),
            files={"file": (filename, file_bytes)},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        return {"status": "unavailable"}

    if response.status_code != 200:
        return {"status": "unavailable"}

    try:
        analysis_id = response.json()["data"]["id"]
        return {"status": "pending", "analysis_id": analysis_id}
    except (KeyError, ValueError):
        return {"status": "unavailable"}


def check_analysis_status(analysis_id: str) -> dict:
    """Проверяет статус ранее запущенного анализа (после upload_file() или
    submit_url()) - оба используют один и тот же VirusTotal endpoint."""
    if not is_configured():
        return {"status": "not_configured"}

    try:
        response = requests.get(
            f"{VT_API_BASE}/analyses/{analysis_id}",
            headers=_headers(),
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        return {"status": "unavailable"}

    if response.status_code != 200:
        return {"status": "unavailable"}

    try:
        data = response.json()["data"]["attributes"]
        if data["status"] != "completed":
            return {"status": "pending", "analysis_id": analysis_id}
        return _stats_to_result(data["stats"])
    except (KeyError, ValueError):
        return {"status": "unavailable"}


def _url_id(url: str) -> str:
    """VirusTotal идентифицирует URL по base64 (URL-safe, без padding) от
    самой строки URL - так требует API v3 (см. developers.virustotal.com)."""
    return base64.urlsafe_b64encode(url.strip().encode()).decode().rstrip("=")


def lookup_url(url: str) -> dict:
    """
    Проверяет, известен ли VirusTotal сам URL (не файл) - тот же принцип,
    что и lookup_hash(), но для ссылок. Статусы те же: not_configured,
    completed, not_found, unavailable.
    """
    if not is_configured():
        return {"status": "not_configured"}

    try:
        response = requests.get(
            f"{VT_API_BASE}/urls/{_url_id(url)}",
            headers=_headers(),
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        return {"status": "unavailable"}

    if response.status_code == 404:
        return {"status": "not_found"}
    if response.status_code == 401:
        return {"status": "unavailable", "detail": "Invalid VirusTotal API key"}
    if response.status_code == 429:
        return {"status": "unavailable", "detail": "VirusTotal rate limit reached - try again later"}
    if response.status_code != 200:
        return {"status": "unavailable"}

    try:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        permalink = f"https://www.virustotal.com/gui/url/{_url_id(url)}"
        return _stats_to_result(stats, extra={"permalink": permalink})
    except (KeyError, ValueError):
        return {"status": "unavailable"}


def submit_url(url: str) -> dict:
    """
    Отправляет URL на анализ VirusTotal, если он ещё неизвестен. Как и
    upload_file(), не ждёт результата - возвращает analysis_id со статусом
    "pending", проверяемым позже через check_analysis_status().
    """
    if not is_configured():
        return {"status": "not_configured"}

    try:
        response = requests.post(
            f"{VT_API_BASE}/urls",
            headers=_headers(),
            data={"url": url},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        return {"status": "unavailable"}

    if response.status_code != 200:
        return {"status": "unavailable"}

    try:
        analysis_id = response.json()["data"]["id"]
        return {"status": "pending", "analysis_id": analysis_id}
    except (KeyError, ValueError):
        return {"status": "unavailable"}
