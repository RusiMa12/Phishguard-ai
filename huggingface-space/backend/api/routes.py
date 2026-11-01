"""
routes.py
---------
Здесь описано, ЧТО происходит, когда кто-то обращается к нашему API.

  - GET  /api/health   - проверка "сервер жив?"
  - POST /api/analyze  - анализ URL: rule-based (url_features.py + risk_engine.py)
                          + ML (ml_url_model.py), объединённые в risk_engine.combine_with_ml()
"""

from typing import Dict, Any, List
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from fastapi.concurrency import run_in_threadpool
from pathlib import Path
from models.schemas import (
    AnalyzeRequest, AnalyzeResponse, HealthResponse, ExeAnalyzeResponse, ApkAnalyzeResponse,
    ScanHistoryEntry, DashboardResponse,
)
from url_features import extract_features
from risk_engine import calculate_risk, combine_with_ml, score_to_level
from ml_url_model import predict_probability
from exe_analyzer import (
    compute_hashes, parse_pe, calculate_static_risk, combine_static_and_ml,
    InvalidExecutableError, MAX_FILE_SIZE,
)
from ml_exe_model import predict_probability as predict_exe_probability
from apk_analyzer import (
    compute_hashes as compute_apk_hashes, parse_apk, calculate_static_risk as calculate_apk_static_risk,
    InvalidApkError, MAX_FILE_SIZE as MAX_APK_SIZE,
)
from services import virustotal, geolocator, sandbox
from risk_fusion import combine_final, fuse_scores
from rate_limit import enforce_rate_limit, get_rate_limiter_status
from xai_explainer import explain_url_decision, explain_exe_decision, explain_apk_decision
from auth import get_current_role, require_roles
import database

from model_evaluation import get_scientific_metrics
from pdf_report_generator import generate_soc_pdf_report
from fastapi.responses import Response

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health_check():
    """Простая проверка: если сервер отвечает - значит backend работает."""
    return HealthResponse(status="ok", service="PhishGuard AI backend")


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_url(request: AnalyzeRequest, submit_if_unknown: bool = False, _rl: None = Depends(enforce_rate_limit)):
    """
    Полный анализ URL, три независимых слоя:
      1) url_features.py разбирает URL на признаки;
      2) risk_engine.calculate_risk() даёт rule-based Risk Score;
      3) ml_url_model.predict_probability() даёт ML-вероятность
         (или None, если models/url_model.pkl ещё не обучен - train_url_model.py);
      4) risk_engine.combine_with_ml() объединяет rule-based + ML в один локальный счёт;
      5) services/virustotal.lookup_url() проверяет сам URL через VirusTotal;
      6) risk_fusion.fuse_scores() объединяет локальный анализ с VirusTotal -
         та же логика (и та же взвешенная, не наивно-усреднённая формула),
         что используется для EXE в Phase 7.

    Если ML-модель или VirusTotal недоступны, итоговый результат корректно
    опирается на то, что доступно - приложение никогда не падает.
    """
    features = extract_features(request.url)
    rule_result = calculate_risk(features)
    ml_probability = predict_probability(features)
    local = combine_with_ml(rule_result, ml_probability, features["hostname"])

    vt_result = virustotal.lookup_url(request.url)
    if vt_result["status"] == "not_found" and submit_if_unknown:
        vt_result = virustotal.submit_url(request.url)

    fused = fuse_scores(
        local["final_score"], local["reasons"], local["positive_signals"], vt_result, subject="URL",
    )
    final_score = fused["final_score"]
    risk_level, classification = score_to_level(final_score)

    if risk_level in ("HIGH", "CRITICAL"):
        recommendations = [
            "Do not click this link or enter any personal information on it",
            "Verify the sender's address if this link arrived by email or messenger",
        ]
    elif risk_level == "MEDIUM":
        recommendations = [
            "Proceed with caution and verify the destination before entering any data",
        ]
    else:
        recommendations = [
            "No clear phishing indicators were found, but continue practicing basic caution",
        ]

    # Записываем в историю (Phase 8) - только hostname, не весь URL с query-параметрами
    database.record_scan(
        scan_type="URL",
        target=features["hostname"] or request.url,
        risk_score=final_score,
        risk_level=risk_level,
        classification=classification,
    )

    # Explainable AI: Feature importance and decision contribution
    xai = explain_url_decision(features, rule_result["risk_score"], local.get("ml_probability"))

    return AnalyzeResponse(
        url=request.url,
        risk_score=final_score,
        risk_level=risk_level,
        classification=classification,
        rule_score=rule_result["risk_score"],
        ml_available=local["ml_available"],
        ml_probability=local["ml_probability"],
        ml_classification=local["ml_classification"],
        features=features,
        reasons=fused["reasons"],
        positive_signals=fused["positive_signals"],
        recommendations=recommendations,
        virustotal=vt_result,
        vt_note=fused["vt_note"],
        xai_analysis=xai,
    )



@router.post("/analyze-exe", response_model=ExeAnalyzeResponse)
async def analyze_exe(file: UploadFile = File(...), upload_if_unknown: bool = False, _rl: None = Depends(enforce_rate_limit)):
    """
    Статический анализ Windows-исполняемого файла (.exe) + проверка через VirusTotal.

    Безопасность (раздел 18 ТЗ):
      - файл НИКОГДА не записывается на диск и НИКОГДА не запускается -
        всё чтение происходит в оперативной памяти;
      - имени файла не доверяем - проверяем реальные байты (сигнатура MZ);
      - размер файла ограничен MAX_FILE_SIZE (50 MB).

    VirusTotal (Phase 6) + Risk Fusion (Phase 7):
      - всегда пытаемся проверить SHA-256 (один быстрый запрос);
      - если ключ не настроен - virustotal.status = "not_configured";
      - если хэш неизвестен VirusTotal И upload_if_unknown=True - файл
        загружается на анализ (см. .env.example для настройки ключа);
        загрузка не включена по умолчанию, чтобы не тратить лимит
        бесплатного API ключа на каждый повторный запрос;
      - risk_fusion.combine_final() объединяет static+ML результат с
        VirusTotal в Final Score - НЕ простым средним, а с весом,
        зависящим от силы консенсуса антивирусных движков
        (см. комментарии в risk_fusion.py).
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    # Не доверяем имени файла (раздел 18 ТЗ): берём только сам basename
    # (на случай если кто-то пришлёт "../../something.exe") и обрезаем
    # длину для безопасного отображения/хранения в истории.
    safe_filename = Path(file.filename).name[:255] or "unnamed.exe"

    if not safe_filename.lower().endswith(".exe"):
        raise HTTPException(status_code=400, detail="Only .exe files are supported.")

    content = await file.read()

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail=f"File exceeds the {MAX_FILE_SIZE // (1024*1024)} MB limit.")

    try:
        pe_info = await run_in_threadpool(parse_pe, content)
    except InvalidExecutableError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    hashes = compute_hashes(content)
    static_result = calculate_static_risk(pe_info)

    ml_probability = predict_exe_probability(len(content), pe_info)
    local_combined = combine_static_and_ml(static_result, ml_probability)

    vt_result = await run_in_threadpool(virustotal.lookup_hash, hashes["sha256"])
    if vt_result["status"] == "not_found" and upload_if_unknown:
        vt_result = await run_in_threadpool(virustotal.upload_file, content, safe_filename)

    fusion = combine_final(local_combined, vt_result)

    # Записываем в историю (Phase 8)
    database.record_scan(
        scan_type="EXE",
        target=safe_filename,
        risk_score=fusion["final_score"],
        risk_level=fusion["risk_level"],
        classification=fusion["classification"],
    )

    return ExeAnalyzeResponse(
        filename=safe_filename,
        file_size_bytes=len(content),
        sha256=hashes["sha256"],
        sha1=hashes["sha1"],
        md5=hashes["md5"],
        machine_type=pe_info["machine_type"],
        entry_point=pe_info["entry_point"],
        image_base=pe_info["image_base"],
        is_dll=pe_info["is_dll"],
        compile_timestamp=pe_info["compile_timestamp"],
        number_of_sections=pe_info["number_of_sections"],
        sections=pe_info["sections"],
        has_digital_signature=pe_info["has_digital_signature"],
        overlay_size=pe_info["overlay_size"],
        imported_dll_count=pe_info["imported_dll_count"],
        imported_function_count=pe_info["imported_function_count"],
        suspicious_imports=pe_info["suspicious_imports"],
        static_risk_score=static_result["static_risk_score"],
        local_ai_score=local_combined["local_ai_score"],
        virustotal=vt_result,
        vt_note=fusion["vt_note"],
        final_score=fusion["final_score"],
        risk_level=fusion["risk_level"],
        classification=fusion["classification"],
        indicators=fusion["reasons"],
        positive_signals=fusion["positive_signals"],
        recommendations=fusion["recommendations"],
        xai_analysis=explain_exe_decision(pe_info, static_result["static_risk_score"]),
        behavioral_analysis=sandbox.reconstruct_behavioral_profile(
            target_type="pe",
            target_name=safe_filename,
            suspicious_indicators=fusion["reasons"],
            raw_details=pe_info,
        ),
    )



@router.post("/analyze-apk", response_model=ApkAnalyzeResponse)
async def analyze_apk(file: UploadFile = File(...), submit_if_unknown: bool = False, _rl: None = Depends(enforce_rate_limit)):
    """
    Статический анализ Android-приложения (.apk) + проверка через VirusTotal.

    Тот же принцип безопасности, что и для EXE (раздел 18 ТЗ):
      - файл НИКОГДА не записывается на диск и НИКОГДА не устанавливается/
        запускается - весь разбор происходит в оперативной памяти
        (apk_analyzer.parse_apk использует APK(..., raw=True));
      - имени файла не доверяем - проверяем реальную сигнатуру ZIP/PK и то,
        что внутри действительно нашёлся package name в AndroidManifest.xml;
      - размер файла ограничен MAX_APK_SIZE (100 MB - APK обычно крупнее EXE).

    Нет отдельной ML-модели для APK (как и для EXE - см. раздел про EXE ML) -
    final_score основан на static analysis (разрешения, подпись, компоненты)
    + VirusTotal, через ту же risk_fusion.fuse_scores(), что и для URL/EXE.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    safe_filename = Path(file.filename).name[:255] or "unnamed.apk"
    if not safe_filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are supported.")

    content = await file.read()

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if len(content) > MAX_APK_SIZE:
        raise HTTPException(status_code=400, detail=f"File exceeds the {MAX_APK_SIZE // (1024*1024)} MB limit.")

    try:
        apk_info = await run_in_threadpool(parse_apk, content, safe_filename)
    except InvalidApkError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    hashes = compute_apk_hashes(content)
    static_result = calculate_apk_static_risk(apk_info)

    vt_result = await run_in_threadpool(virustotal.lookup_hash, hashes["sha256"])
    if vt_result["status"] == "not_found" and submit_if_unknown:
        vt_result = await run_in_threadpool(virustotal.upload_file, content, safe_filename)

    fused = fuse_scores(
        static_result["static_risk_score"], static_result["indicators"], static_result["positive_signals"],
        vt_result, subject="APK",
    )
    final_score = fused["final_score"]
    risk_level, classification_label = score_to_level(final_score)
    classification_map = {
        "Potentially Safe": "BENIGN",
        "Suspicious": "SUSPICIOUS",
        "Potentially Malicious": "MALICIOUS",
    }
    classification = classification_map.get(classification_label, classification_label)

    if risk_level in ("HIGH", "CRITICAL"):
        recommendations = [
            "Do not install this application.",
            "Verify the source of the APK before proceeding.",
            "If already installed, uninstall it and check for unauthorized account activity.",
        ]
    elif risk_level == "MEDIUM":
        recommendations = ["Exercise caution - verify the app's source and requested permissions before installing."]
    else:
        recommendations = ["No strong risk indicators were found, but always install apps from trusted sources."]

    database.record_scan(
        scan_type="APK",
        target=f"{apk_info['package_name']} ({safe_filename})",
        risk_score=final_score,
        risk_level=risk_level,
        classification=classification,
    )

    return ApkAnalyzeResponse(
        filename=safe_filename,
        file_size_bytes=len(content),
        sha256=hashes["sha256"],
        sha1=hashes["sha1"],
        md5=hashes["md5"],
        package_name=apk_info["package_name"],
        app_name=apk_info["app_name"],
        version_name=apk_info["version_name"],
        version_code=apk_info["version_code"],
        min_sdk=apk_info["min_sdk"],
        target_sdk=apk_info["target_sdk"],
        is_signed=apk_info["is_signed"],
        is_multidex=apk_info["is_multidex"],
        permission_count=apk_info["permission_count"],
        permissions=apk_info["permissions"],
        dangerous_permissions=apk_info["dangerous_permissions"],
        activity_count=apk_info["activity_count"],
        service_count=apk_info["service_count"],
        receiver_count=apk_info["receiver_count"],
        native_library_count=apk_info["native_library_count"],
        static_risk_score=static_result["static_risk_score"],
        virustotal=vt_result,
        vt_note=fused["vt_note"],
        final_score=final_score,
        risk_level=risk_level,
        classification=classification,
        indicators=fused["reasons"],
        positive_signals=fused["positive_signals"],
        recommendations=recommendations,
        xai_analysis=explain_apk_decision(apk_info, static_result["static_risk_score"]),
        behavioral_analysis=sandbox.reconstruct_behavioral_profile(
            target_type="apk",
            target_name=f"{apk_info['package_name']} ({safe_filename})",
            suspicious_indicators=fused["reasons"],
            raw_details=apk_info,
        ),
    )



@router.get("/vt-status/{analysis_id}")
def vt_status(analysis_id: str):
    """
    Проверка статуса анализа, запущенного через upload_file() (когда хэш
    изначально был неизвестен VirusTotal). VirusTotal обрабатывает файл не
    мгновенно, поэтому фронтенд может вызывать этот эндпоинт повторно,
    пока статус не станет "completed".
    """
    return virustotal.check_analysis_status(analysis_id)


@router.get("/scan-history", response_model=list[ScanHistoryEntry])
def scan_history(limit: int = 50, search: str = "", scan_type: str = "", risk_level: str = ""):
    """Последние проверки (URL, EXE, APK), с поддержкой поиска и фильтрации."""
    return database.get_recent_scans(limit=limit, search=search, scan_type=scan_type, risk_level=risk_level)


@router.get("/dashboard", response_model=DashboardResponse)
def dashboard():
    """Реальная статистика по всем проверкам, сохранённым в data/phishguard.db."""
    return database.get_dashboard_stats()


@router.get("/model-metrics")
def model_metrics():
    """
    Bitiruv malakaviy ishi (BMI) va ilmiy baholash uchun
    Machine Learning modellari va gibrid tizim metrikalari.
    """
    return get_scientific_metrics()


@router.post("/export-pdf")
def export_pdf_report(payload: dict):
    """
    SOC ekspertiza hisobotini rasmiy PDF formatida yuklab olish.
    """
    scan_type = payload.get("scan_type", "URL")
    target_data = payload.get("data", {})
    pdf_bytes = generate_soc_pdf_report(scan_type, target_data)
    filename = f"PhishGuard_SOC_Report_{scan_type}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/threat-map/live")
def get_live_threat_map():
    """
    Jonli Kiber-Tahdidlar Xaritasi uchun real vaqt telemetriyasi.
    Haqiqiy skanerlash tarixi + global tahlil qatlamlarini birlashtiradi.
    """
    recent_scans = database.get_recent_scans(limit=25)
    return geolocator.get_threat_map_telemetry(db_scans=recent_scans)


@router.get("/threat-map/local-uz")
def get_local_uzbekistan_threat_map():
    """
    O'zbekiston Respublikasi ichki hududiy kiber-xaritasi uchun telemetriya.
    Viloyatlar o'rtasidagi real vaqt ichki tahdid traektoriyalarini qaytaradi.
    """
    return geolocator.get_uzbekistan_local_telemetry(count=25)


@router.get("/brand-radar/presets")
def get_brand_presets():
    """
    O'zbekistonning eng ommabop brendlari ro'yxati (Payme, Click, Uzum, NBU, va h.k.).
    """
    from services.brand_radar import UZBEK_BRAND_PRESETS
    return {
        "status": "success",
        "presets": UZBEK_BRAND_PRESETS
    }


@router.post("/brand-radar/scan")
def scan_brand_radar(payload: Dict[str, Any]):
    """
    Brend klonlari, omogliflar va typosquatting domenlarini tahlil qilish.
    """
    from services.brand_radar import scan_brand_impersonation
    brand_id = payload.get("brand_id", "")
    custom_name = payload.get("custom_name", "")
    custom_domain = payload.get("custom_domain", "")
    return scan_brand_impersonation(brand_id=brand_id, custom_name=custom_name, custom_domain=custom_domain)


@router.post("/yara/generate")
def generate_threat_yara_rule(payload: Dict[str, Any]):
    """
    Skanerlangan obyekt bo'yicha YARA 4.x qoidasi generatsiya qilish.
    """
    from services.yara_generator import generate_yara_rule
    return generate_yara_rule(payload)


@router.post("/analyze-behavioral")
def analyze_dynamic_behavior(payload: Dict[str, Any], _rl: None = Depends(enforce_rate_limit)):
    """
    Fayl yoki artefaktning xatti-harakatlari (Sandbox / Dynamic Behavioral Reconstruction).
    """
    target_type = payload.get("type", "pe")
    target_name = payload.get("target_name", "target_sample")
    indicators = payload.get("indicators", [])
    raw_details = payload.get("raw_details", {})
    return sandbox.reconstruct_behavioral_profile(
        target_type=target_type,
        target_name=target_name,
        suspicious_indicators=indicators,
        raw_details=raw_details,
    )


@router.get("/system/status")
def system_telemetry_status(user: Dict[str, Any] = Depends(get_current_role)):
    """
    SOC Tizimi umumiy telemetriyasi, Rate Limiter (Redis/In-Memory),
    Dinamik Sandbox va Autentifikatsiya (RBAC) holati.
    """
    import ml_url_model
    import ml_exe_model
    return {
        "status": "operational",
        "service": "PhishGuard AI Enterprise SOC Backend",
        "user_role": user.get("role", "ANONYMOUS"),
        "authenticated": user.get("authenticated", False),
        "rate_limiter": get_rate_limiter_status(),
        "dynamic_sandbox": {
            "remote_available": sandbox.is_remote_sandbox_available(),
            "mode": "hybrid_reconstruction",
        },
        "virustotal_configured": virustotal.is_configured(),
        "models": {
            "url_model_ready": ml_url_model.is_available(),
            "exe_model_ready": ml_exe_model.is_available(),
        },
    }


@router.post("/auth/verify")
def verify_credentials(user: Dict[str, Any] = Depends(get_current_role)):
    """
    Foydalanuvchi yoki SOC tahlilchisi API kalitini tekshirish.
    """
    return {
        "valid": True,
        "role": user.get("role"),
        "key_id": user.get("key_id"),
        "message": f"Foydalanuvchi tizimda muvaffaqiyatli tasdiqlandi. Roli: {user.get('role')}",
    }



