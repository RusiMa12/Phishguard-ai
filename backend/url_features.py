"""
url_features.py
----------------
Извлекает признаки (features) из URL как из ТЕКСТОВОЙ СТРОКИ.

ВАЖНО (безопасность): этот модуль НЕ открывает URL в браузере, НЕ отправляет
туда сетевые запросы и НЕ выполняет никакого кода с проверяемого сайта.
Всё, что здесь происходит - это разбор текста самой ссылки с помощью
стандартной библиотеки Python (urllib, re).

Проверка количества редиректов требует реального HTTP-запроса к сайту.
Согласно требованиям проекта (раздел "Безопасность"), такие внешние
проверки должны быть отдельным, отключаемым модулем - поэтому здесь
redirect_count всегда None, а сама проверка будет добавлена позже
как опциональный модуль (services/reputation.py), а не в это ядро анализа.
"""

import re
import math
from collections import Counter
from urllib.parse import urlparse, parse_qs

# Ключевые слова, которые часто встречаются в фишинговых URL
# (не доказательство фишинга само по себе, а один из сигналов)
SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "password", "signin", "webscr", "ebayisapi",
    "paypal", "suspend", "urgent", "click", "bonus", "gift",
]

# Популярные сервисы сокращения ссылок - злоумышленники используют их,
# чтобы скрыть настоящий адрес назначения
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "cutt.ly",
]

# TLD (доменные зоны), которые статистически чаще используются в фишинге,
# в основном из-за очень низкой или нулевой цены регистрации.
# TLD (доменные зоны), которые статистически чаще используются в фишинге,
# в основном из-за очень низкой или нулевой цены регистрации.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "country", "kim", "cricket", "science", "gdn", "loan", "download",
    "racing", "review", "win", "bid", "stream", "accountant",
    "monster", "club", "space", "live", "shop", "rest", "buzz", "cfd", "sbs", "quest",
}

# High-profile brands target in phishing campaigns and their official domains
TARGET_BRANDS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "binance": "binance.com",
    "telegram": "telegram.org",
    "whatsapp": "whatsapp.com",
    "payme": "payme.uz",
    "click": "click.uz",
    "uzum": "uzum.uz",
    "kapitalbank": "kapitalbank.uz",
    "hamkorbank": "hamkorbank.uz",
    "agrobank": "agrobank.uz",
    "sqb": "sqb.uz",
    "nbu": "nbu.uz",
    "ipotekabank": "ipotekabank.uz",
    "anorbank": "anorbank.uz",
    "tbcbank": "tbcbank.uz",
}

# Найдено через error_analysis.py (анализ false negatives обученной модели):
# ссылки, ведущие напрямую на исполняемый/скриптовый файл - частый способ
# распространения вредоносного ПО через фишинговые письма/сообщения.
EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "msi", "js", "vbs", "jar", "ps1",
}

# Параметры в query string, которые часто используются в open-redirect /
# фишинговых схемах ("отправь на настоящий сайт, но потом перекинь на поддельный")
SUSPICIOUS_QUERY_PARAMS = {"redirect", "url", "next", "continue", "return", "goto", "dest"}


MULTI_PART_TLDS = {
    "com.uz", "co.uz", "org.uz", "gov.uz", "edu.uz", "net.uz",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "go.jp",
    "co.nz", "net.nz", "org.nz",
    "com.br", "org.br", "gov.br",
    "co.in", "net.in", "org.in", "gov.in",
    "com.tr", "org.tr", "gov.tr",
    "com.ru", "net.ru", "org.ru",
}

# Регулярное выражение для проверки, является ли hostname IPv4-адресом
IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)


def _is_ip_address(host: str) -> bool:
    """Проверяет hostname на все формы IP-адресов (IPv4, IPv6, dword, hex)."""
    if not host:
        return False
    if IP_PATTERN.match(host):
        return True
    if (host.startswith("[") and host.endswith("]")) or host.count(":") >= 2:
        return True
    if host.isdigit():
        try:
            return 0 <= int(host) <= 4294967295
        except ValueError:
            pass
    if host.startswith("0x") and len(host) <= 10:
        try:
            return 0 <= int(host, 16) <= 4294967295
        except ValueError:
            pass
    return False


def _shannon_entropy(s: str) -> float:
    """
    Энтропия Шеннона - показывает, насколько "случайно" выглядит строка.
    Обычные слова (google, facebook) имеют низкую энтропию.
    Случайно сгенерированные домены (xj29fk2.com) имеют высокую энтропию -
    это частый признак автоматически сгенерированных фишинговых доменов.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_features(url: str) -> dict:
    """
    Главная функция модуля.

    Вход:  url - произвольная строка, введённая пользователем.
    Выход: словарь с числовыми и булевыми признаками.
           risk_engine.py (следующий этап) превратит их в Risk Score.
    """
    url = url.strip()

    # urlparse умеет аккуратно разбивать URL на части (схема, домен, путь...),
    # но только если есть "://". Если пользователь ввёл просто "example.com"
    # без http(s)://, добавляем схему сами - иначе hostname определится неверно.
    parse_target = url if "://" in url else "http://" + url

    parsed = urlparse(parse_target)
    hostname = (parsed.hostname or "").lower()
    scheme = parsed.scheme or ""
    path = parsed.path or ""
    query = parsed.query or ""

    scheme_stripped = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)

    domain_parts = hostname.split(".") if hostname else []
    # Учитываем многосоставные доменные зоны (.com.uz, .co.uk и т.д.)
    is_multi_tld = any(hostname.endswith("." + mtld) or hostname == mtld for mtld in MULTI_PART_TLDS)
    subdomain_count = max(len(domain_parts) - 3, 0) if is_multi_tld else max(len(domain_parts) - 2, 0)
    tld = ".".join(domain_parts[-2:]) if is_multi_tld and len(domain_parts) >= 2 else (domain_parts[-1] if domain_parts else "")

    # IDN / Homograph / Punycode атаки (например, kirill 'о' в 'google.com'):
    has_non_ascii = any(ord(ch) > 127 for ch in hostname)
    try:
        idna_hostname = hostname.encode("idna").decode("ascii")
    except Exception:
        idna_hostname = hostname

    has_punycode = (
        hostname.startswith("xn--")
        or ".xn--" in hostname
        or idna_hostname.startswith("xn--")
        or ".xn--" in idna_hostname
        or has_non_ascii
    )

    query_params = parse_qs(query)
    digit_count = sum(ch.isdigit() for ch in scheme_stripped)
    letter_count = sum(ch.isalpha() for ch in scheme_stripped)
    special_char_count = sum(not ch.isalnum() for ch in scheme_stripped)

    suspicious_path = any(w in path.lower() for w in SUSPICIOUS_WORDS) or "//" in path

    path_segments = path.rsplit(".", 2)
    path_extension = path_segments[-1].lower() if len(path_segments) > 1 else ""
    has_double_extension = len(path_segments) == 3 and path_segments[-1].lower() in EXECUTABLE_EXTENSIONS
    suspicious_query = any(p.lower() in SUSPICIOUS_QUERY_PARAMS for p in query_params.keys()) or "http" in query.lower()

    # Brand Impersonation / Targeted Phishing Spoofing check
    brand_impersonation = None
    url_lower = url.lower()
    for brand, legit_domain in TARGET_BRANDS.items():
        if brand in url_lower:
            is_legit = hostname == legit_domain or hostname.endswith("." + legit_domain)
            if not is_legit and (brand in hostname or brand in path.lower()):
                brand_impersonation = brand
                break

    # Non-standard web port check
    has_suspicious_port = bool(parsed.port and parsed.port not in (80, 443))

    # Open redirect / URL in URL cloaking
    has_embedded_url = bool(re.search(r"https?://", path + query, re.IGNORECASE))

    return {
        "url": url,
        "url_length": len(scheme_stripped),
        "hostname": hostname,
        "hostname_length": len(hostname),
        "domain_dot_count": hostname.count("."),
        "subdomain_count": subdomain_count,
        "has_ip_address": _is_ip_address(hostname),
        "has_https": scheme == "https",
        "at_symbol_count": scheme_stripped.count("@"),
        "hyphen_count": scheme_stripped.count("-"),
        "underscore_count": scheme_stripped.count("_"),
        "slash_count": scheme_stripped.count("/"),
        "question_mark_count": scheme_stripped.count("?"),
        "equals_count": scheme_stripped.count("="),
        "percent_count": scheme_stripped.count("%"),
        "is_url_shortener": any(short in hostname for short in URL_SHORTENERS),
        "suspicious_words_found": [w for w in SUSPICIOUS_WORDS if w in url.lower()],
        "has_punycode": has_punycode,
        "unusual_hostname_length": len(hostname) > 30,
        "redirect_count": None,
        "brand_impersonation": brand_impersonation,
        "has_suspicious_port": has_suspicious_port,
        "has_embedded_url": has_embedded_url,

        # --- признаки для ML ---
        "path_length": len(path),
        "query_param_count": len(query_params),
        "special_char_count": special_char_count,
        "digit_ratio": round(digit_count / len(scheme_stripped), 4) if scheme_stripped else 0.0,
        "letter_ratio": round(letter_count / len(scheme_stripped), 4) if scheme_stripped else 0.0,
        "hostname_entropy": round(_shannon_entropy(hostname), 4),
        "has_suspicious_path": suspicious_path,
        "has_suspicious_query": suspicious_query,
        "has_suspicious_tld": tld in SUSPICIOUS_TLDS or domain_parts[-1] in SUSPICIOUS_TLDS if domain_parts else False,
        "has_executable_extension": path_extension in EXECUTABLE_EXTENSIONS,
        "has_double_extension": has_double_extension,
    }



# Список признаков, которые реально идут в ML-модель (в этом порядке).
# ВАЖНО: и train_url_model.py, и ml_url_model.py используют именно этот
# список - так гарантируется, что модель обучается и делает предсказания
# на признаках в одинаковом порядке и формате.
ML_FEATURE_COLUMNS = [
    "url_length", "hostname_length", "domain_dot_count", "subdomain_count",
    "has_ip_address", "has_https", "at_symbol_count", "hyphen_count",
    "underscore_count", "slash_count", "question_mark_count", "equals_count",
    "percent_count", "is_url_shortener", "suspicious_word_count",
    "has_punycode", "unusual_hostname_length", "path_length",
    "query_param_count", "special_char_count", "digit_ratio", "letter_ratio",
    "hostname_entropy", "has_suspicious_path", "has_suspicious_query",
    "has_suspicious_tld", "has_executable_extension", "has_double_extension",
]


def features_to_vector(features: dict) -> dict:
    """
    Превращает словарь от extract_features() в "плоский" числовой словарь,
    готовый для scikit-learn: булевы значения -> 0/1, список слов -> их количество.
    Строковые поля (url, hostname) и redirect_count (всегда None) не идут в ML.
    """
    return {
        "url_length": features["url_length"],
        "hostname_length": features["hostname_length"],
        "domain_dot_count": features["domain_dot_count"],
        "subdomain_count": features["subdomain_count"],
        "has_ip_address": int(features["has_ip_address"]),
        "has_https": int(features["has_https"]),
        "at_symbol_count": features["at_symbol_count"],
        "hyphen_count": features["hyphen_count"],
        "underscore_count": features["underscore_count"],
        "slash_count": features["slash_count"],
        "question_mark_count": features["question_mark_count"],
        "equals_count": features["equals_count"],
        "percent_count": features["percent_count"],
        "is_url_shortener": int(features["is_url_shortener"]),
        "suspicious_word_count": len(features["suspicious_words_found"]),
        "has_punycode": int(features["has_punycode"]),
        "unusual_hostname_length": int(features["unusual_hostname_length"]),
        "path_length": features["path_length"],
        "query_param_count": features["query_param_count"],
        "special_char_count": features["special_char_count"],
        "digit_ratio": features["digit_ratio"],
        "letter_ratio": features["letter_ratio"],
        "hostname_entropy": features["hostname_entropy"],
        "has_suspicious_path": int(features["has_suspicious_path"]),
        "has_suspicious_query": int(features["has_suspicious_query"]),
        "has_suspicious_tld": int(features["has_suspicious_tld"]),
        "has_executable_extension": int(features["has_executable_extension"]),
        "has_double_extension": int(features["has_double_extension"]),
    }


# Небольшая проверка при прямом запуске файла: python url_features.py
# Позволяет убедиться, что модуль работает, не поднимая весь сервер.
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/paypal-login/verify-account?user=test@x",
        "https://secure-bank-login.xn--80ak6aa92e.com/update",
    ]
    for u in test_urls:
        print(f"\nURL: {u}")
        for key, value in extract_features(u).items():
            print(f"  {key}: {value}")
