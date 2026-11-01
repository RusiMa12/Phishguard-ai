"""
ml_url_model.py
----------------
Загружает уже обученную ML-модель (models/url_model.pkl, создаётся
скриптом train_url_model.py) и делает предсказание для одного URL.

Если файл модели не найден (train_url_model.py ещё не запускался),
модуль НЕ падает с ошибкой - приложение просто продолжает работать
в rule-based режиме, как явно требуется в проекте.
"""

from pathlib import Path
import joblib

from url_features import features_to_vector

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "url_model.pkl"

_model_cache = None  # модель загружается один раз и переиспользуется


def _load_model():
    """Загружает models/url_model.pkl в память (один раз за время работы сервера)."""
    global _model_cache
    if _model_cache is not None:
        return _model_cache

    if not MODEL_PATH.exists():
        return None

    try:
        _model_cache = joblib.load(MODEL_PATH)
    except Exception:
        # Файл повреждён или несовместим - работаем без ML, не роняем сервер
        _model_cache = None
    return _model_cache


def is_available() -> bool:
    """Проверяет, обучена ли модель и готова ли она к использованию."""
    return _load_model() is not None


def get_model_metrics() -> dict:
    """Возвращает реальные метрики модели (accuracy/precision/recall/F1), сохранённые
    при обучении. Используется на Dashboard, чтобы НЕ выдумывать точность модели."""
    bundle = _load_model()
    if bundle is None:
        return {}
    return bundle.get("metrics", {})


def predict_probability(features: dict):
    """
    Вход:  features - словарь от extract_features() (url_features.py)
    Выход: float 0.0-1.0 - вероятность того, что URL вредоносный,
           либо None, если модель недоступна.
    """
    bundle = _load_model()
    if bundle is None:
        return None

    model = bundle["model"]
    feature_columns = bundle["feature_columns"]

    vector = features_to_vector(features)
    # Строго в том же порядке признаков, в котором модель обучалась.
    # Передаём как DataFrame (не голый список) с теми же именами колонок,
    # что и при обучении - иначе scikit-learn выдаёт предупреждение
    # "X does not have valid feature names" (модель работает и без этого,
    # но так чище и без лишнего шума в логах).
    import pandas as pd
    ordered_values = pd.DataFrame([[vector[col] for col in feature_columns]], columns=feature_columns)

    # predict_proba возвращает [P(class=0), P(class=1)] - нам нужна P(malicious)
    probability = model.predict_proba(ordered_values)[0][1]
    return float(probability)


# Проверка при прямом запуске: python ml_url_model.py
if __name__ == "__main__":
    from url_features import extract_features

    print("Model available:", is_available())
    print("Model metrics:", get_model_metrics())

    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/paypal-login/verify-account?user=test@x",
        "https://secure-bank-login.xn--80ak6aa92e.com/update",
        "https://bit.ly/3xK9zQ2",
    ]
    for u in test_urls:
        p = predict_probability(extract_features(u))
        print(f"{u} -> phishing probability: {p:.4f}" if p is not None else f"{u} -> ML unavailable")
