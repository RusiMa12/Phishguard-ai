"""
risk_engine.py
--------------
Превращает признаки (features) из url_features.py в Risk Score (0-100%).

Система весов вынесена в словарь RISK_WEIGHTS - единственное место,
которое нужно менять, если хочется сделать анализ строже или мягче.
Это и называется "модульная система оценки" в требованиях проекта.

ПРИМЕЧАНИЕ: сообщения в reasons/positive_signals написаны на английском,
потому что именно на этом языке построен весь интерфейс платформы
(см. frontend) - они выводятся пользователю напрямую, без перевода.
"""

# Веса каждого правила. Чем выше число - тем сильнее признак повышает риск.
RISK_WEIGHTS = {
    "unusual_url_length": 10,
    "has_ip_address": 25,
    "has_at_symbol": 20,
    "suspicious_words": 15,
    "excessive_subdomains": 10,
    "has_punycode": 20,
    "is_url_shortener": 15,
    "no_https": 10,
    "unusual_hostname_length": 15,
    "executable_extension": 25,  # найдено через error_analysis.py - см. url_features.py
    "brand_impersonation": 30,
    "suspicious_tld": 15,
    "embedded_url": 15,
    "suspicious_port": 10,
}

URL_LENGTH_THRESHOLD = 75
SUBDOMAIN_THRESHOLD = 3

# Границы уровней риска (0-20 / 21-40 / 41-60 / 61-80 / 81-100)
RISK_LEVELS = [
    (20, "VERY_LOW", "Potentially Safe"),
    (40, "LOW", "Potentially Safe"),
    (60, "MEDIUM", "Suspicious"),
    (80, "HIGH", "Suspicious"),
    (100, "CRITICAL", "Potentially Malicious"),
]

# Вес rule-based скора и ML-вероятности в итоговом Risk Score.
# Rule-based получает больший вес (60%), потому что он детерминированный
# и полностью объясним - каждый балл соответствует конкретному, видимому
# пользователю признаку. ML даёт 40% - он улавливает паттерны из реального
# датасета, которые сложно выразить вручную написанными правилами,
# но остаётся "чёрным ящиком", поэтому не должен доминировать в итоге.
RULE_WEIGHT = 0.6
ML_WEIGHT = 0.4

# Пороги для перевода ML-вероятности (0.0-1.0) в 3 класса.
# Датасет, на котором обучалась модель, бинарный (safe/malicious),
# поэтому класс "SUSPICIOUS" - это намеренно введённая зона неопределённости
# вокруг границы принятия решения, а не отдельный класс из обучающих данных.
ML_SAFE_THRESHOLD = 0.3
ML_PHISHING_THRESHOLD = 0.7

# ИЗВЕСТНОЕ ОГРАНИЧЕНИЕ МОДЕЛИ (важно для защиты курсовой работы):
# ML-модель обучена ТОЛЬКО на лексических признаках URL (длина, кол-во
# символов, энтропия и т.д.) - у неё нет понятия "репутации домена".
# Поэтому короткий, но малоизвестный вредоносный домен и короткий,
# всемирно известный домен (например google.com) могут иметь почти
# одинаковые лексические признаки - модель их различить не может.
# Это подтверждённое, задокументированное ограничение lexical-only моделей
# в литературе по фишинг-детекции, а не ошибка кода.
#
# Практическое смягчение (так же поступают браузеры и антивирусы -
# allowlist доверенных доменов): для короткого списка широко известных
# доменов ML-вклад в итоговый счёт снижается. ОГРАНИЧЕНИЕ ЭТОГО ПОДХОДА:
# он также ослабляет ML-сигнал для поддоменов вида evil.google.com или
# accounts.google.com/phishing-redirect - в реальности такие поддомены
# иногда используются в атаках (например, через Google Docs/Sites).
# Это компромисс, который стоит явно упомянуть в разделе "Limitations".
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "instagram.com",
    "twitter.com", "x.com", "whatsapp.com", "amazon.com", "microsoft.com", "apple.com",
    "netflix.com", "linkedin.com", "reddit.com", "github.com", "stackoverflow.com",
    "yahoo.com", "bing.com", "ebay.com", "paypal.com", "wordpress.com",
    "cloudflare.com", "mozilla.org", "python.org", "npmjs.com", "pypi.org",
    "anthropic.com", "openai.com", "coursera.org", "un.org", "who.int", "nasa.gov",
    # O'zbekiston davlat, ta'lim, OAV va moliya xizmatlari
    "kun.uz", "gazeta.uz", "daryo.uz", "cbu.uz", "gov.uz", "my.gov.uz", "president.uz",
    "soliq.uz", "lex.uz", "edu.uz", "ziyonet.uz", "tuit.uz", "nuu.uz", "wiut.uz", "inha.uz",
    "payme.uz", "click.uz", "uzum.uz", "hamkorbank.uz", "kapitalbank.uz", "agrobank.uz",
    "sqb.uz", "nbu.uz", "ipotekabank.uz", "xalqbanki.uz", "anorbank.uz", "tbcbank.uz",
}


def _is_trusted_domain(hostname: str) -> bool:
    """True, если hostname совпадает с доверенным доменом или является его поддоменом."""
    hostname = (hostname or "").lower()
    return any(hostname == d or hostname.endswith("." + d) for d in TRUSTED_DOMAINS)


def score_to_level(score: int):
    """По итоговому проценту определяет уровень риска и общую классификацию."""
    for max_score, level, classification in RISK_LEVELS:
        if score <= max_score:
            return level, classification
    return "CRITICAL", "Potentially Malicious"


def calculate_risk(features: dict) -> dict:
    """
    Вход:  features - словарь от extract_features() из url_features.py
    Выход: risk_score (только rule-based), risk_level, classification,
           reasons (что насторожило), positive_signals (что в порядке).
    """
    score = 0
    reasons = []
    positive_signals = []

    if features["url_length"] > URL_LENGTH_THRESHOLD:
        score += RISK_WEIGHTS["unusual_url_length"]
        reasons.append(f"URL length ({features['url_length']} characters) is significantly above normal")
    else:
        positive_signals.append("URL length is within normal range")

    if features["has_ip_address"]:
        score += RISK_WEIGHTS["has_ip_address"]
        reasons.append("An IP address is used instead of a domain name")
    else:
        positive_signals.append("A regular domain name is used, not an IP address")

    if features["at_symbol_count"] > 0:
        score += RISK_WEIGHTS["has_at_symbol"]
        reasons.append("The URL contains an '@' character, which can hide the real destination")
    else:
        positive_signals.append("No '@' character detected")

    if features["suspicious_words_found"]:
        score += RISK_WEIGHTS["suspicious_words"]
        words = ", ".join(features["suspicious_words_found"])
        reasons.append(f"Suspicious keywords detected: {words}")
    else:
        positive_signals.append("No suspicious keywords detected")

    if features["subdomain_count"] > SUBDOMAIN_THRESHOLD:
        score += RISK_WEIGHTS["excessive_subdomains"]
        reasons.append(f"An excessive number of subdomains is used ({features['subdomain_count']})")
    else:
        positive_signals.append("Subdomain count is within normal range")

    if features["has_punycode"]:
        score += RISK_WEIGHTS["has_punycode"]
        reasons.append("The domain uses Punycode or lookalike homoglyphs (e.g. Cyrillic/Greek lookalike characters) - a deception technique")
    else:
        positive_signals.append("Punycode is not used")

    if features["is_url_shortener"]:
        score += RISK_WEIGHTS["is_url_shortener"]
        reasons.append("A link-shortening service is used, which hides the real destination")
    else:
        positive_signals.append("The link is not shortened by a third-party service")

    if not features["has_https"]:
        score += RISK_WEIGHTS["no_https"]
        reasons.append("The connection is not secured with HTTPS")
    else:
        positive_signals.append("A secure HTTPS connection is used")

    if features["unusual_hostname_length"]:
        score += RISK_WEIGHTS["unusual_hostname_length"]
        reasons.append(f"The domain has an unusually long structure ({features['hostname_length']} characters)")
    else:
        positive_signals.append("Domain length is within normal range")

    if features["has_executable_extension"]:
        score += RISK_WEIGHTS["executable_extension"]
        note = " (double extension - a common disguise technique)" if features["has_double_extension"] else ""
        reasons.append(f"The link points directly to an executable/script file{note}")
    else:
        positive_signals.append("The link does not point to an executable file")

    if features.get("brand_impersonation"):
        score += RISK_WEIGHTS["brand_impersonation"]
        brand_name = features["brand_impersonation"].upper()
        reasons.append(f"Brand Impersonation Phishing: URL references recognized brand '{brand_name}' on an unverified domain")

    if features.get("has_embedded_url"):
        score += RISK_WEIGHTS["embedded_url"]
        reasons.append("Open redirect / URL cloaking pattern: Contains an embedded URL inside path or query parameters")

    if features.get("has_suspicious_port"):
        score += RISK_WEIGHTS["suspicious_port"]
        reasons.append("Non-standard web port detected in destination address")

    if features.get("has_suspicious_tld"):
        score += RISK_WEIGHTS["suspicious_tld"]
        reasons.append("High-risk top-level domain (TLD) frequently associated with disposable phishing campaigns")

    # Compound threat multiplier when multiple deception techniques are active concurrently
    phish_triggers = sum([
        bool(features.get("brand_impersonation")),
        features["has_ip_address"],
        features["at_symbol_count"] > 0,
        features["has_punycode"],
        features.get("has_embedded_url", False),
        len(features["suspicious_words_found"]) >= 2,
    ])
    if phish_triggers >= 2:
        score += 15
        reasons.append("Compound Threat: Multiple deceptive evasion patterns detected concurrently")

    final_score = min(max(score, 0), 100)
    level, classification = score_to_level(final_score)

    return {
        "risk_score": final_score,
        "risk_level": level,
        "classification": classification,
        "reasons": reasons,
        "positive_signals": positive_signals,
    }



def _ml_classification(probability: float) -> str:
    """Переводит ML-вероятность (0.0-1.0) в 3-классовую метку."""
    if probability < ML_SAFE_THRESHOLD:
        return "SAFE"
    if probability < ML_PHISHING_THRESHOLD:
        return "SUSPICIOUS"
    return "PHISHING"


def combine_with_ml(rule_result: dict, ml_probability, hostname: str = "") -> dict:
    """
    Объединяет rule-based результат (calculate_risk) с ML-вероятностью
    в единый Final Risk Score.

    Вход:
      rule_result    - словарь от calculate_risk()
      ml_probability - float 0.0-1.0 (вероятность, что URL вредоносный)
                        или None, если ML-модель недоступна (нет models/url_model.pkl)
      hostname       - hostname URL (для проверки TRUSTED_DOMAINS, см. выше)

    Выход: копия rule_result с добавленными полями:
      final_score, ml_probability, ml_classification, ml_available
    (final_score заменяет risk_score/risk_level/classification в ответе API).
    """
    result = dict(rule_result)

    if ml_probability is None:
        # ML-модель не обучена/недоступна - используем только rule-based анализ,
        # как явно разрешено требованиями проекта.
        result["final_score"] = rule_result["risk_score"]
        result["ml_available"] = False
        result["ml_probability"] = None
        result["ml_classification"] = None
        return result

    ml_weight = ML_WEIGHT
    positive_signals = list(rule_result["positive_signals"])
    trusted = _is_trusted_domain(hostname)
    if trusted:
        # Смягчение известного ограничения модели (см. комментарий у TRUSTED_DOMAINS) -
        # для доменов из allowlist доверяем ML-модели значительно меньше.
        ml_weight = 0.05
        positive_signals.append("Domain matches a recognized, widely-known trusted domain list")

    rule_weight = 1 - ml_weight
    ml_score = ml_probability * 100
    final_score = round(rule_weight * rule_result["risk_score"] + ml_weight * ml_score)
    final_score = min(max(final_score, 0), 100)

    level, classification = score_to_level(final_score)
    ml_class = _ml_classification(ml_probability)

    reasons = list(rule_result["reasons"])
    # Если ML увидела риск, который rule-based движок не поймал явными правилами -
    # честно об этом сообщаем, а не молчим о расхождении (но не для доверенных доменов -
    # там мы уже знаем, что ML-сигнал ненадёжен, см. ограничение выше).
    if not trusted and ml_probability >= ML_PHISHING_THRESHOLD and rule_result["risk_score"] < 40:
        reasons.append(
            "The ML model flagged this URL as statistically risky based on patterns "
            "learned from real-world data, even though few explicit rule-based indicators were triggered"
        )

    result["final_score"] = final_score
    result["risk_level"] = level
    result["classification"] = classification
    result["reasons"] = reasons
    result["positive_signals"] = positive_signals
    result["ml_available"] = True
    result["ml_probability"] = round(ml_probability, 4)
    result["ml_classification"] = ml_class
    return result


# Проверка при прямом запуске: python risk_engine.py
if __name__ == "__main__":
    from url_features import extract_features

    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/paypal-login/verify-account?user=test@x",
        "https://secure-bank-login.xn--80ak6aa92e.com/update",
    ]
    for u in test_urls:
        feats = extract_features(u)
        result = calculate_risk(feats)
        print(f"\nURL: {u}")
        print(f"  Risk Score (rule-based only): {result['risk_score']}%")
        print(f"  Risk Level: {result['risk_level']}")
        print(f"  Classification: {result['classification']}")
        print(f"  Reasons: {result['reasons']}")
        print(f"  Positive signals: {result['positive_signals']}")
