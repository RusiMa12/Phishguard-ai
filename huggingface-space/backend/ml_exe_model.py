"""
ml_exe_model.py
----------------
Загружает обученную EXE ML-модель (models/exe_model.pkl, создаётся
train_exe_model.py) и делает предсказание для одного файла.

Если модель не обучена (нет датасета - см. train_exe_model.py), модуль
НЕ падает с ошибкой. is_available() вернёт False, и routes.py продолжит
использовать только exe_analyzer.calculate_static_risk(), как и требуется.
"""

from pathlib import Path
import joblib

from exe_analyzer import exe_features_to_vector

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "exe_model.pkl"

_model_cache = None


def _load_model():
    global _model_cache
    if _model_cache is not None:
        return _model_cache
    if not MODEL_PATH.exists():
        return None
    try:
        _model_cache = joblib.load(MODEL_PATH)
    except Exception:
        _model_cache = None
    return _model_cache


def is_available() -> bool:
    return _load_model() is not None


def get_model_metrics() -> dict:
    """Реальные Accuracy/Precision/Recall/F1 модели, для честного отображения на Dashboard."""
    bundle = _load_model()
    return bundle.get("metrics", {}) if bundle else {}


def predict_probability(file_size: int, pe_info: dict):
    """
    Вход:  file_size, pe_info - как возвращает exe_analyzer.parse_pe()
    Выход: float 0.0-1.0 (вероятность, что файл вредоносный) или None,
           если модель ещё не обучена.
    """
    bundle = _load_model()
    if bundle is None:
        return None

    model = bundle["model"]
    feature_columns = bundle["feature_columns"]
    vector = exe_features_to_vector(file_size, pe_info)
    ordered = [[vector[col] for col in feature_columns]]

    probability = model.predict_proba(ordered)[0][1]
    return float(probability)
