"""
schemas.py
----------
Здесь описана СТРУКТУРА данных, которые приходят в API и уходят из него.
Pydantic автоматически проверяет, что данные правильного типа
(например, что url - это строка, а risk_score - число).

Если фронтенд пришлёт что-то неправильное (например, число вместо строки),
FastAPI сам вернёт понятную ошибку 422, и мы не будем падать где-то глубже в коде.
"""

from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional


class AnalyzeRequest(BaseModel):
    """Что присылает фронтенд, когда пользователь нажимает 'Analyze URL'."""
    url: str = Field(
        ..., min_length=1, max_length=2048,
        description="URL для анализа, например https://example.com (макс. 2048 символов - как в большинстве браузеров)",
    )


class AnalyzeResponse(BaseModel):
    """
    Что backend возвращает после анализа.
    На этом этапе (Backend skeleton) поля features/reasons/recommendations
    будут пустыми - мы заполним их на следующих этапах (url_features.py, risk_engine.py).
    """
    url: str
    risk_score: int = Field(..., ge=0, le=100, description="Итоговый (rule + ML) риск от 0 до 100")
    risk_level: str = Field(..., description="VERY_LOW / LOW / MEDIUM / HIGH / CRITICAL")
    classification: str = Field(..., description="Potentially Safe / Suspicious / Potentially Malicious")
    rule_score: int = Field(0, ge=0, le=100, description="Риск, посчитанный ТОЛЬКО rule-based движком (risk_engine.py)")
    ml_available: bool = Field(False, description="Обучена ли ML-модель (models/url_model.pkl существует)")
    ml_probability: Optional[float] = Field(None, description="Вероятность 0.0-1.0, что URL вредоносный (по мнению ML)")
    ml_classification: Optional[str] = Field(None, description="SAFE / SUSPICIOUS / PHISHING (по мнению одной только ML-модели)")
    features: Dict[str, Any] = Field(default_factory=dict, description="Извлечённые признаки URL")
    reasons: List[str] = Field(default_factory=list, description="Обнаруженные подозрительные признаки")
    positive_signals: List[str] = Field(default_factory=list, description="Признаки, говорящие в пользу безопасности")
    recommendations: List[str] = Field(default_factory=list, description="Рекомендации пользователю")
    virustotal: Dict[str, Any] = Field(default_factory=lambda: {"status": "not_configured"}, description="Результат проверки самого URL через VirusTotal")
    vt_note: str = Field("", description="Пояснение, как именно VirusTotal повлиял (или не повлиял) на итоговый счёт")
    xai_analysis: List[Dict[str, Any]] = Field(default_factory=list, description="Explainable AI: Feature importance and decision contribution")


class HealthResponse(BaseModel):
    """Ответ на GET /api/health - просто подтверждает, что сервер жив."""
    status: str
    service: str


class ExeAnalyzeResponse(BaseModel):
    filename: str
    file_size_bytes: int
    sha256: str
    sha1: str
    md5: str

    machine_type: str
    entry_point: str
    image_base: str
    is_dll: bool
    compile_timestamp: Optional[str]
    number_of_sections: int
    sections: List[Dict[str, Any]]
    has_digital_signature: bool
    overlay_size: int
    imported_dll_count: int
    imported_function_count: int
    suspicious_imports: List[str]

    static_risk_score: int = Field(..., ge=0, le=100)
    local_ai_score: Optional[int] = Field(None, description="Заполнится, если models/exe_model.pkl обучен (Phase 5)")
    virustotal: Dict[str, Any] = Field(default_factory=lambda: {"status": "not_configured"})
    vt_note: str = Field("", description="Пояснение от risk_fusion.py, как именно VirusTotal повлиял (или не повлиял) на итог")

    final_score: int = Field(..., ge=0, le=100)
    risk_level: str
    classification: str
    indicators: List[str]
    positive_signals: List[str]
    recommendations: List[str]
    xai_analysis: List[Dict[str, Any]] = Field(default_factory=list, description="Explainable AI for PE executable")
    behavioral_analysis: Dict[str, Any] = Field(default_factory=dict, description="Dinamik xatti-harakatlar (Sandbox profile)")


class ApkAnalyzeResponse(BaseModel):
    filename: str
    file_size_bytes: int
    sha256: str
    sha1: str
    md5: str

    package_name: str
    app_name: str
    version_name: Optional[str]
    version_code: Optional[str]
    min_sdk: Optional[str]
    target_sdk: Optional[str]
    is_signed: bool
    is_multidex: bool
    permission_count: int
    permissions: List[str]
    dangerous_permissions: List[str]
    activity_count: int
    service_count: int
    receiver_count: int
    native_library_count: int

    static_risk_score: int = Field(..., ge=0, le=100)
    virustotal: Dict[str, Any] = Field(default_factory=lambda: {"status": "not_configured"})
    vt_note: str = Field("", description="Пояснение, как именно VirusTotal повлиял (или не повлиял) на итог")

    final_score: int = Field(..., ge=0, le=100)
    risk_level: str
    classification: str
    indicators: List[str]
    positive_signals: List[str]
    recommendations: List[str]
    xai_analysis: List[Dict[str, Any]] = Field(default_factory=list, description="Explainable AI for Android APK")
    behavioral_analysis: Dict[str, Any] = Field(default_factory=dict, description="Dinamik xatti-harakatlar (Sandbox profile)")



class ScanHistoryEntry(BaseModel):
    """Одна строка в Scan History (раздел 16 ТЗ)."""
    scan_type: str = Field(..., description="'URL' или 'EXE'")
    target: str = Field(..., description="hostname для URL, имя файла для EXE")
    risk_score: int
    risk_level: str
    classification: str
    created_at: str


class ClassificationBreakdown(BaseModel):
    safe: int
    suspicious: int
    malicious: int


class DashboardResponse(BaseModel):
    """Ответ на GET /api/dashboard (раздел 15 ТЗ) - реальная статистика из data/phishguard.db."""
    total_scans: int
    url_scans: int
    exe_scans: int
    apk_scans: int
    threats_detected: int
    average_risk: int
    level_counts: Dict[str, int] = Field(..., description="Количество сканов по каждому из 5 уровней риска")
    classification_breakdown: ClassificationBreakdown
