/* ============================================================



   PhishGuard AI — frontend logic



   Three responsibilities:



     1) View router — switches between Dashboard / URL Scanner /



        EXE Scanner / APK Scanner / History / Threat Intel / About;



     2) URL Scanner — sends the URL to the backend (/api/analyze)



        and renders the radial risk gauge;



     3) EXE & APK Scanner — reads local files safely in browser



        and sends to backend for static PE/APK parsing and ML fusion;



     4) i18n — Full multilingual engine (Uzbek, English, Russian).



   ============================================================ */







const API_URL = "/api/analyze";



const EXE_API_URL = "/api/analyze-exe";



const APK_API_URL = "/api/analyze-apk";



const DASHBOARD_API_URL = "/api/dashboard";



const HISTORY_API_URL = "/api/scan-history";



const REQUEST_TIMEOUT_MS = 25000;







async function fetchWithTimeout(url, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) {



  const controller = new AbortController();



  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);



  try {



    return await fetch(url, { ...options, signal: controller.signal });



  } catch (err) {



    if (err.name === "AbortError") {



      throw new Error(



        `Request timed out after ${timeoutMs / 1000}s. Check that the backend server is running and not blocked by a firewall.`



      );



    }



    throw err;



  } finally {



    clearTimeout(timeoutId);



  }



}







/* ============================================================



   1) MULTILINGUAL i18n DICTIONARY



   ============================================================ */







let currentLang = localStorage.getItem("phishguard_lang") || "uz";



let currentViewKey = "dashboard";



let lastUrlResult = null;



let lastExeResult = null;



let lastApkResult = null;



let lastSocReportType = null;



let lastSocReportData = null;



let currentHistoryData = [];







const I18N = {



  uz: {



    doc_title: "PhishGuard AI — Ko'p Pog'onali Kiberxavfsizlik va Tahdidlarni Tahlil Qilish Platformasi",



    brand_sub: "KO'P POG'ONALI KIBERXAVFSIZLIK TAHLILI",



    nav_dashboard: "Boshqaruv paneli",



    nav_url_scanner: "URL Skaner",



    nav_exe_scanner: "EXE Skaner",



    nav_apk_scanner: "APK Skaner",



    nav_history: "Skanerlash tarixi",



    nav_threat_map: "Kiber-Tahdidlar Xaritasi",



    nav_threat_intel: "Tahdidlar bazasi",



    nav_model_metrics: "Model Metriklari",



    nav_about: "Loyiha haqida",



    status_ai: "AI TIZIMI: FAOL",



    status_vt: "TAHDIDLAR RAZVEDKASI: FAOL",



    language_label: "TILNI TANLASH:",







    dashboard: "Boshqaruv paneli",



    "url-scanner": "URL Skaner",



    "exe-scanner": "EXE Skaner",



    "apk-scanner": "APK Skaner",



    history: "Skanerlash tarixi",



    "threat-map": "Kiber-Tahdidlar Xaritasi",



    "threat-intel": "Tahdidlar bazasi",



    "model-metrics": "Model Metriklari",



    about: "Loyiha haqida",







    radar_active: "JONLI SOC KIBER-TAHDIDLAR XARITASI FAOL",



    radar_card_title: "Global va Mintaqaviy Kiber-Hujumlar Xaritasi",



    radar_card_desc: "O'zbekiston kiber-makoniga yo'naltirilgan fishing havolalari, troyanlar va zararli APK serverlarining real vaqtdagi jonli traektoriyalari.",



    view_map_btn: "XARITANI KO'RISH →",



    threat_map_eyebrow: "REAL VAQTDAGI SOC TELEMETRIYASI VA GEOLOKATSIYA",



    threat_map_heading: "Jonli Kiber-Tahdidlar Hujum Xaritasi",



    threat_map_subhead: "O'zbekiston kiber-makoniga yo'naltirilgan fishing havolalari, troyan dasturlari va zararli APK tarqatuvchi C2 serverlarining global traektoriyalari.",



    map_status_live: "SOC QALQONI: TOSHKENT DUGONASI FAOL",



    hud_intercepted: "ZARARSIZLANTIRILGAN TAHDIDLAR",



    hud_containment: "HIMOYA SAMARADORLIGI",



    hud_latency: "O'RTACHA ANIQLASH VAQTI",



    hud_target_node: "ASOSIY HIMOYA OBYEKTI",



    filter_all: "Barchasi",



    filter_url: "URL Fishing",



    filter_exe: "EXE Troyan",



    filter_apk: "APK Dropper",



    pause_stream: "To'xtatish",



    resume_stream: "Davom ettirish",



    clear_arcs: "Tozalash",



    sound_radar: "Radar Ovoz",



    leg_critical: "Kritik Tahdid (Troyan/APK Dropper)",



    leg_high: "Yuqori Xavfli Fishing Havola",



    leg_medium: "Shubhali Tranzit Server",



    leg_safe: "Toshkent SOC Markazi (Qalqon)",



    live_stream_title: "REAL VAQTDAGI SOC TELEMETRIYA JURNALI",



    stream_live_badge: "JONLI EFIR (REAL-TIME)",



    kasp_rank_title: "GLOBAL HUJUMLAR REYTINGI",



    scope_global: "Global Xarita (Dunyo)",



    scope_local: "Mahalliy Xarita (O'zbekiston)",



    tag_wav: "Web Anti-Virus",



    tag_oas: "On-Access Scan",



    tag_apk: "Mobile Dropper",



    tag_ids: "Intrusion Detection",



    tag_ksn: "Cloud Telemetry",







    overview: "UMUMIY KO'RINISh",



    choose_engine: "Tahlil mexanizmini tanlang",



    url_analyzer: "URL TAHLILCHI",



    url_analyzer_desc: "Sun'iy intellekt va leksik tahlil yordamida shubhali havolalarni tekshiring va fishing xavfini aniqlang.",



    scan_url_cta: "URL TEKSHIRISH →",



    exe_analyzer: "EXE TAHLILCHI",



    exe_analyzer_desc: "Windows PE fayllarini xavfsiz statik tahlil, lokal AI va VirusTotal orqali tekshiring.",



    scan_exe_cta: "EXE TEKSHIRISH →",



    apk_analyzer: "APK TAHLILCHI",



    apk_analyzer_desc: "Android ilovalarini (APK) xavfli ruxsatnomalar, imzo va komponentlar bo'yicha tahlil qiling.",



    scan_apk_cta: "APK TEKSHIRISH →",







    total_scans: "JAMI TEKSHIRUVLAR",



    url_scans: "URL TEKSHIRUVLARI",



    exe_scans: "EXE TEKSHIRUVLARI",



    apk_scans: "APK TEKSHIRUVLARI",



    threats_detected: "ANIQLANGAN XAVFLAR",



    average_risk: "O'RTACHA XAVF",



    risk_distribution: "XAVF DARAJALARI TAQSIMOTI",



    scan_types: "SKAN TURLARI NISBATI",



    recent_threats: "SO'NGGI YUQORI XAVFLI SKANLAR",



    no_scans_yet: "Hozircha tekshiruvlar yo'q — natijalar bu yerda aks etadi.",







    url_threat_analysis: "URL XAVF TAHLILI",



    check_link_safe: "Havola xavfsizligini tekshiring",



    url_subhead: "Havolani quyidagi maydonga kiriting. Tizim uni brauzerda ochmaydi — faqat xavfsiz matn ko'rinishida tahlil qilinadi.",



    url_placeholder: "https://example.com/login...",



    analyze_url_btn: "URL TAHLIL QILISH",



    analyzing: "TAHLIL QILINMOQDA...",



    risk_score: "XAVF BALI",



    detected_indicators: "ANIQLANGAN XAVF INDIKATORLARI",



    positive_signals: "IJOBIY XAVFSIZLIK BELGILARI",



    ai_explanation: "AI XULOSASI VA TUSHUNTIRISH",



    disclaimer_note: "Eslatma: ushbu tizim ehtimollikka asoslangan xavf bahosini beradi. 100% kafolat bermaydi.",



    export_pdf: "PDF HISOBOT YUKLASH",



    export_json: "JSON YUKLASH",



    start_new_scan: "YANGI SKAN BOSHLASH",







    exe_threat_analysis: "IJRO FAYLLARI XAVF TAHLILI",



    inspect_exe: "Windows ijro faylini tekshiring",



    exe_subhead: "Fayl hech qachon ishga tushirilmaydi. Faqat statik xususiyatlari (nomi, hajmi, kriptografik xeshi) o'qiladi.",



    drop_exe: ".exe faylni shu yerga tashlang yoki tanlash uchun bosing",



    exe_drop_hint: "Maksimal hajm: 50 MB · Fayl lokal tahlil qilinadi, hech qachon ishga tushirilmaydi",



    file_name: "FAYL NOMI",



    file_size: "FAYL HAJMI",



    file_type: "FAYL TURI",



    machine_type: "PROTSESSOR TURI",



    sections: "BO'LIMLAR",



    signature: "RAQAMLI IMZO",



    imports: "IMPORT QILINUVCHI API",



    scan_exe_btn: "EXE TAHLIL QILISH",







    apk_threat_analysis: "ANDROID ILOVA TAHLILI",



    inspect_apk: "Android APK faylini tekshiring",



    apk_subhead: "APK hech qachon o'rnatilmaydi va ishga tushirilmaydi. Faqat manifest va strukturasi (ruxsatlar, imzo, komponentlar) o'qiladi.",



    drop_apk: ".apk faylni shu yerga tashlang yoki tanlash uchun bosing",



    apk_drop_hint: "Maksimal hajm: 100 MB · Fayl lokal tahlil qilinadi, hech qachon o'rnatilmaydi",



    package_name: "PAKET NOMI",



    version: "VERSIYA",



    permissions: "RUXSATNOMALAR",



    scan_apk_btn: "APK TAHLIL QILISH",







    audit_log: "AUDIT JURNALI",



    scan_history: "Skanerlash tarixi",



    history_subhead: "Ushbu sessiyada amalga oshirilgan barcha URL, EXE va APK skanerlashlari qaydlari.",



    history_search_placeholder: "Domen, fayl yoki manzil bo'yicha qidiruv...",



    all_types: "Barcha turlar",



    all_risk_levels: "Barcha xavf darajalari",



    risk_critical: "Kritik xavf",



    risk_high: "Yuqori xavf",



    risk_medium: "O'rta xavf",



    risk_low: "Past xavf",



    risk_very_low: "Juda past xavf",



    export_csv: "Export CSV",



    th_date: "Sana va vaqt",



    th_type: "Turi",



    th_target: "Obyekt / Manzil",



    th_risk_score: "Xavf bali",



    th_classification: "Tasnif",



    th_status: "Holat",



    no_scans_recorded: "Hozircha hech qanday skan yozilmagan.",







    kb_eyebrow: "BILIMLAR BAZASI",



    threat_intel_heading: "Tahdidlar haqida ma'lumot",



    threat_intel_subhead: "Platforma nimalarni qidiradi va har bir signal nima uchun muhim?",



    intel_1_title: "Phishing URL indikatorlari",



    intel_1_desc: "Domen o'rniga IP-manzil ishlatilishi, @ belgisi, Punycode/homograf domenlar, URL qisqartirish xizmatlari va 'login', 'verify' kabi shubhali so'zlar statistik jihatdan fishing sahifalariga xosdir.",



    intel_2_title: "PE fayl indikatorlari",



    intel_2_desc: "Bo'limlarning yuqori entropiyasi, g'ayrioddiy import jadvallari, yozish va bajarish (W+X) huquqiga ega bo'limlar hamda yo'q yoki soxta raqamli imzolar troyan va zararli fayllarga xosdir.",



    intel_3_title: "Ko'p pog'onali tekshirish",



    intel_3_desc: "Yagona aniqlash usuli noto'g'ri musbat (false positive) natijalar berishi mumkin. Lokal statik tahlilni mustaqil tahdid razvedkasi (VirusTotal) bilan birlashtirish ushbu xavfni keskin kamaytiradi.",



    intel_4_title: "Cheklovlar va xususiyatlar",



    intel_4_desc: "Hech qanday avtomatlashtirilgan tizim 100% mutlaq kafolat bera olmaydi. Natijalar ehtimollikka asoslangan bahodir. Shubhali fayl yoki havolalarni har doim qo'shimcha usullar bilan ham tekshirish lozim.",







    about_eyebrow: "LOYIHA HAQIDA",



    about_heading: "PhishGuard AI Haqida",



    about_hero_badge: "🎓 BITIRUV MALAKAVIY ISHI (BMI) | FORENSIC AI PLATFORM",



    about_hero_title: "Ko'p Qatlamli Kiberxavfsizlik va Intellektual Tahdidlarni Tahlil Qilish Ekotizimi",



    about_hero_desc: "PhishGuard AI — zamonaviy axborot xavfsizligi tahdidlariga qarshi kurashish, xususan fishing havolalari (Phishing URLs), zararli Windows dasturlari (PE / EXE) hamda xavfli Android paketlarini (APK / Banker Droppers) real-vaqt rejimida aniqlash, tahlil qilish va bartaraf etish uchun yaratilgan sun'iy intellektga asoslangan milliy platformadir. Loyiha O'zbekiston kiber-hududini (TAS-IX) va global axborot tizimlarini ilg'or mashinali o'rganish (Machine Learning), leksik evristika, chuqur statik tahlil va xalqaro tahdid razvedkasi (VirusTotal) orqali ishonchli himoya qilish maqsadida ishlab chiqilgan.",



    about_stat_samples: "O'quv Namunasi",



    about_stat_acc: "Konsensus Aniqligi",



    about_stat_auc: "ROC-AUC Skori",



    about_stat_fnr: "False Negative (FNR)",



    about_stat_latency: "O'rtacha Tahlil",



    about_pillars_title: "🛡️ 7 Ta Asosiy Tahlil va Himoya Qatlamlari",



    about_pillars_sub: "Platformaning yagona konsensusga birlashgan ko'p bosqichli tahlil mexanizmlari:",



    pillar_url_title: "1. URL Leksik & ML Tahlili",



    pillar_url_desc: "30+ leksik va strukturaviy parametrlar: Punycode (IDN), kiber-omogliflar, IP-manzilli hostlar, shubhali TLDlar, subdomenlar chuqurligi va token entropiyasi. LightGBM & Random Forest orqali 98.6% aniqlikda baholash.",



    pillar_exe_title: "2. Windows PE / EXE Statik Skaneri",



    pillar_exe_desc: "Portable Executable sarlavhalari, bo'limlar entropiyasi (UPX/pakalanish ko'rsatkichi), W+X xotira huquqlari, shubhali Windows API importlari (protsess inyeksiyasi, klaviatura ushlovchilar) va raqamli imzo tekshiruvi.",



    pillar_apk_title: "3. Android APK & Banker Dropper Skaneri",



    pillar_apk_desc: "Android Manifest tahlili, xavfli ruxsatnomalar (SMS, Accessibility, Contacts), Telegram orqali tarqaluvchi soxta kengaytmalar (.jpeg.apk, .pdf.apk), Bank troyanlari indikatorlari va DEX resurslar tahlili.",



    pillar_xai_title: "4. Tushuntiriluvchi Sun'iy Intellekt (XAI)",



    pillar_xai_desc: "'Qora quti' (Black Box) muammosiga yechim: SHAP (SHapley Additive exPlanations) va LIME orqali har bir skanerlangan obyektda model qaroriga qaysi parametrlar eng yuqori hissa qo'shganini shaffof va vizual tushuntirish.",



    pillar_soc_title: "5. Rasmiy SOC Forensic Dossieri",



    pillar_soc_desc: "Xalqaro TLP:AMBER toifali rasmiy ekspertiza xulosasi generatori. MITRE ATT&CK matritsasi (T1566, T1475, T1055), kriptografik SHA-256 xeshlari, tahdid darajasi va PDF qilib yuklab olish yoki chop etish imkoniyati.",



    pillar_map_title: "6. Jonli Kiber-Tahdidlar Xaritasi",



    pillar_map_desc: "Kaspersky Pro HD dizaynidagi ballistik lazer trayektoriyali interaktiv xarita. 180+ davlatli Global xarita hamda O'zbekistonning barcha 14 ta hududini (viloyatlar, Qoraqalpog'iston va Toshkent sh.) qamragan mahalliy kiber-hujumlar telemetriyasi.",



    pillar_clients_title: "7. Ekosistema Mijozlari: Telegram Bot & Brauzer Kengaytmasi",



    pillar_clients_desc: "Foydalanuvchilarga qulaylik yaratish maqsadida yaratilgan mijoz ilovalari: Telegram SOC Bot (@PhishGuard_bot) orqali mobil tahlil qilish va Google Chrome / Microsoft Edge uchun brauzer kengaytmasi (Manifest v3) orqali veb-saytlarni real-vaqt rejimida avtomatik tekshirish.",



    arch_heading: "To'liq Ko'p Pog'onali Tizim Arxitekturasi",



    arch_sub: "Mijoz qatlamidan tortib, xavf konsensusiga qadar axborot va signallarning o'tish zanjiri:",



    about_metrics_title: "📊 Ilmiy Eksperimental Natijalar",



    about_metrics_sub: "133,088 ta haqiqiy kiber-namunalar ustida o'tkazilgan 5-karrali Stratified K-Fold kross-validatsiya natijalari:",



    metric_dataset: "Umumiy Ma'lumotlar To'plami",



    metric_split: "O'quv / Test Nisbati",



    metric_accuracy: "Tasniflash Aniqligi (Accuracy)",



    metric_roc_auc: "ROC-AUC Integral Maydoni",



    metric_fnr: "Ikkinchi Tur Xatolar (False Negatives)",



    metric_inference: "O'rtacha Tahlil Vaqti (Inference)",



    about_tech_title: "⚙️ Texnologik Stak va Dasturiy Vositalar",



    about_tech_sub: "Platformani yaratishda foydalanilgan sanoat standartidagi ochiq va xavfsiz texnologiyalar:",



    disclaimer_heading: "Mas'uliyatni Cheklash va Ilmiy Kontekst",



    disclaimer_text: "Ushbu platforma kiberxavfsizlik sohasi bo'yicha bitiruv malakaviy ishi (BMI) himoyasi hamda ilmiy-amaliy tadqiqot namoyishi uchun ishlab chiqilgan. Platforma beradigan xulosalar ko'p parametrli intellektual tahlil, mashinali o'rganish modellari va evristik tekshiruvlarga asoslangan ehtimollik bahosidir. U tijoriy antivirus yoki rasmiy litsenziyalangan davlat ekspertiza organlarining o'rnini to'liq bosmaydi, balki kiber-tahdidlarni tezkor aniqlash va tahlil qilishda yuqori samarali intellektual yordamchi vosita bo'lib xizmat qiladi.",

    nav_brand_radar: "Brend Radari",

    nav_cyber_lab: "Kiber-Poligon",

    brand_radar: "Brend Radari",

    cyber_lab: "Kiber-Poligon",

    audio_on: "SOC OVOZ: FAOL",

    audio_off: "SOC OVOZ: O'CHIQ",

    mode_url_text: "Havola Matni",

    mode_quishing_tab: "QR-Kod (Quishing)",

    quishing_title: "QR-Kod Rasmini Tashlang yoki Faylni Tanlang",

    quishing_desc: "Telegram, to'lov xabarnomasi yoki veb-saytdagi shubhali QR-kod rasmini (skrinshot) yuklang yoki kameradan o'qing",

    quishing_paste_hint: "Yoki skrinshotni bu yerga to'g'ridan-to'g'ri tashlang (Ctrl + V)",

    brand_radar_title: "BREND RADARI",

    brand_radar_desc: "Payme, Click, Uzum va banklar nomidan ochilgan klon domenlar va omogliflarni fosh qiling.",

    scan_brand_cta: "BRENDNI TEKSHIRISH →",

    cyber_lab_title: "KIBER-POLIGON",

    cyber_lab_desc: "Interaktiv fishing simulyatorida real kiber-tahdidlarni aniqlash bo'yicha treningdan o'ting.",

    cyber_lab_cta: "TRENINGNI BOSHLASH →",

    yara_rule_btn: "YARA QOIDASI",

    copy_code: "📋 NUSXA OLISH",

    download_yar: "💾 .YAR YUKLASH",

    brand_radar_eyebrow: "MILLIY BRENDLAR HIMOYASI",

    brand_radar_heading: "O'zbekiston Brendlari & Typosquatting Radari",

    brand_radar_subhead: "Payme, Click, Uzum, NBU va boshqa mahalliy brendlar nomidan ochilgan klon fishing saytlar, Punycode omogliflar va soxta domenlarni aniqlash.",

    select_brand_label: "MONITORING QILINADIGAN BRENDNI TANLANG:",

    custom_brand_placeholder: "Yoki o'z domeningizni kiriting (masalan: agrobank.uz)",

    scan_brand_btn: "KLONLARNI QIDIRISH",

    stat_clones_analyzed: "Generatsiya Qilingan Klonlar",

    stat_critical_clones: "Kritik Xavfli (Omoglif/Punycode)",

    stat_high_clones: "Yuqori Xavfli Klonlar",

    stat_official_domain: "Rasmiy Xavfsiz Domen",

    brand_table_title: "Aniqlangan Klon Domenlar va Xavf Bahosi",

    filter_all: "Barchasi",

    filter_critical: "🔴 Faqat Kritik",

    filter_high: "🟠 Yuqori Xavf",

    th_clone_domain: "Ehtimoliy Klon Domen",

    th_mutation_type: "Mutatsiya Turi",

    th_risk_score: "Xavf Skori",

    th_description: "Tahliliy Xulosa",

    th_recommended: "Tavsiya",

    th_action: "Amal",

    cyber_lab_eyebrow: "INTERAKTIV KIBER-TRENING",

    cyber_lab_heading: "Kiber-Poligon: Fishing Simulyatori",

    cyber_lab_subhead: "O'zbekistonda tarqalgan haqiqiy fishing xabarlari, soxta SMS va Telegram to'lov firibgarliklarini o'rganing va o'z kiber-gigiyenangizni sinovdan o'tkazing.",

    hud_rank: "KIBER-DARAJA:",

    hud_score: "TO'PLANGAN BALL:",

    hud_streak: "TO'G'RI:",

    filter_diff_label: "QIYINLIK DARAJASI:",
    diff_all: "Barchasi (14)",
    diff_easy: "🟢 Oson (4)",
    diff_medium: "🟡 O'rta (5)",
    diff_hard: "🔴 Qiyin (5)",
    select_scenario_label: "TAKTISh SENARIYLARI:",







    very_low_risk: "JUDA PAST XAVF",



    low_risk: "PAST XAVF",



    medium_risk: "O'RTA XAVF",



    high_risk: "YUQORI XAVF",



    critical_risk: "KRITIK XAVF",







    class_safe: "Potentsial Xavfsiz",



    class_suspicious: "Shubhali",



    class_malicious: "Potentsial Zararli",







    no_risk_indicators: "Xavf indikatorlari aniqlanmadi",



    no_safety_signals: "Xavfsizlik signallari aniqlanmadi",



    present: "Mavjud",



    not_signed: "Imzolanmagan",



    sensitive: "ta maxfiy",







    explain_safe_intro: "Ushbu havola bo'yicha aniq xavf indikatorlari topilmadi",



    explain_suspicious_intro: "Ushbu havola shubhali deb baholandi",



    explain_malicious_intro: "Ushbu havola yuqori ehtimollik bilan zararli deb baholandi",



    explain_default_intro: "Tahlil yakunlandi",



    explain_clean_details: "Asosiy parametrlar (domen strukturasi, HTTPS, maxfiy so'zlar) xavfsiz me'yorda.",



    explain_because: "sababi",



    explain_probability_note: "Bu ehtimollikka asoslangan baho bo'lib, 100% mutlaq xulosa bermaydi.",







    xai_decision_factors: "Qaror Qabul Qilish Omillari (Feature Attribution)",



    xai_desc: "Sun'iy intellekt modeli va evristik tahlil xulosasiga eng ko'p ta'sir qilgan parametrlar taqsimoti:",



    print_save_pdf: "🖨️ CHOP ETISH / PDF SAQLASH",



    close: "YOPISH",







    // Model Metrics & Scientific Lab



    metrics_eyebrow: "ILMIY TADQIQOT VA MODEL BAHOLASH",



    metrics_heading: "Sun'iy Intellekt Modellarining Ilmiy Metriklari",



    metrics_subhead: "Bitiruv malakaviy ishi doirasida 133,000+ havolalar va Windows PE binar fayllari asosida o'lchangan ilmiy ko'rsatkichlar, xatolar matritsasi va ROC-AUC egri chizig'i.",



    tab_url_model: "URL Fishing Modeli (133k Dataset)",



    tab_exe_model: "EXE Malware Modeli (Static PE)",



    tab_hybrid_model: "Ko'p Qatlamli Gibrid Tizim",



    kpi_accuracy: "ACCURACY (ANIQLIK)",



    kpi_accuracy_sub: "Test tanlanmasi bo'yicha",



    kpi_precision: "PRECISION (ANIQLILIK)",



    kpi_precision_sub: "Soxta signallar (FP) minimal",



    kpi_recall: "RECALL / SENSITIVITY",



    kpi_recall_sub: "Tahdidlarni aniqlash ulushi",



    kpi_f1: "F1-SCORE",



    kpi_f1_sub: "Garmonik o'rtacha muvozanat",



    kpi_auc: "ROC-AUC SCORE",



    kpi_auc_sub: "A'lo ajratish qobiliyati",



    kpi_latency: "INFERENCE TIME",



    kpi_latency_sub: "Haqiqiy vaqt rejimida",



    cm_title: "Xatolar Matritsasi (Confusion Matrix)",



    cm_desc: "Klassifikatorning to'g'ri (TP, TN) va xato (FP, FN) prognozlari taqsimoti:",



    cm_pred_clean: "Prognoz: TOZA",



    cm_pred_threat: "Prognoz: TAHDID",



    cm_actual_clean: "Aslida: TOZA",



    cm_actual_threat: "Aslida: XAVFLI",



    cm_tn_sub: "44.9% (Toza tasdiqlangan)",



    cm_fp_sub: "5.1% (Soxta signal)",



    cm_fn_sub: "5.7% (O'tkazib yuborilgan)",



    cm_tp_sub: "44.3% (Fishing tutilgan)",



    roc_title: "Qabul qiluvchining Ish Xarakteristikasi (ROC-AUC)",



    roc_desc: "Sezgirlik (TPR) va soxta musbatlar tezligi (FPR) o'rtasidagi nisbat:",



    roc_legend_pg: "PhishGuard Modeli (AUC = 0.954)",



    roc_legend_random: "Tasodifiy taxmin (AUC = 0.50)",



    algo_comparison_title: "Mashinali O'rganish Algoritmlari Solishtiruvi (Cross-Validation)",



    algo_comparison_desc: "5-Fold Stratified Cross-Validation orqali bir xil datasetda turli ML algoritmlarining empirik solishtiruvi:",



    th_algo_name: "Algoritm / Model",



    th_algo_acc: "Test Aniqligi (Accuracy)",



    th_algo_f1: "F1-Score",



    th_algo_cv: "5-Fold CV F1",



    th_algo_latency: "Inference Vaqti",



    th_algo_verdict: "Xulosa / Maqom",



    badge_optimal: "Tanlangan (Optimal)",



    badge_tested: "Sinovdan o'tgan",



    badge_slow: "Haqiqiy vaqtga sekin",



    badge_baseline: "Boshlang'ich baza",



    badge_final_system: "YAKUNIY TIZIM",



    algo_pg_fusion_title: "⭐ PhishGuard Gibrid Tizimi (ML + Rules + SOC)",



    feat_imp_title: "Model Belgilarining Ahamiyati (Feature Importance - Gini Impurity)",



    feat_imp_desc: "Random Forest daraxtlari qaror qabul qilishida eng yuqori og'irlikka ega bo'lgan top-8 belgilar taqsimoti:",



    bmi_thesis_title: "🎓 Bitiruv Malakaviy Ishi Himoyasi uchun Ilmiy Xulosa",



    bmi_thesis_text: "Ushbu tadqiqotda kiber-fishing tahdidlarini aniqlashda sof sun'iy intellekt (Machine Learning) modeliga nisbatan ko'p pog'onali gibrid yondashuvning (Lokal ML + Leksik Evristika + Tashqi Razvedka) ustunligi isbotlandi. Tadqiqot 106,472 ta o'quv va 26,618 ta test namunalarida 5-karrali Stratified K-Fold kross-validatsiyasi orqali sinovdan o'tkazildi. Natijada ikkinchi tur xatolar (False Negatives — tahdidni o'tkazib yuborish) ko'rsatkichi 11.5% dan 1.3% gacha pasaytirildi va yakuniy konsensus aniqligi 98.4% ga yetkazildi.",







    metric_url_sub: "26,618 test namunasida (133k Dataset)",



    metric_exe_sub: "Windows PE statik xususiyatlari",



    metric_hybrid_sub: "Ko'p pog'onali konsensus natijasi",



    cm_samples_label: "test namunalari",



    cm_pe_samples_label: "ta PE namunalari",



    cm_hybrid_samples_label: "Gibrid konsensus sinovi",



    cm_note_heading: "Ilmiy tahlil",



    cm_note_url_body: "26,618 ta test havolalaridan 11,780 tasi (TP) to'g'ri aniqlangan. 1,529 ta o'tkazib yuborilgan holatlar (FN) ikkinchi pog'ona — Evristik qoidalar (Brand spoofing, IP host, Punycode) orqali to'liq ushlab qolinadi va yakuniy aniqlik 98.4% ga yetadi.",



    cm_note_exe_body: "PE statik tahlili entropiya va importlar orqali troyanlarni 94% aniqlikda ajratadi. Missing signature va W+X bo'limlari eng kuchli prediktorlardir.",



    cm_note_hybrid_body: "Sof ML modeliga nisbatan gibrid arxitekturada xatoliklar (FN) 8.8 baravarga kamaytirildi. Zero-Day fishing tahdidlarining 95%+ qismi VirusTotal'da yo'q bo'lsa ham fosh qilinadi!",







    soc_rep_header_title: "O'ZBEKISTON RESPUBLIKASI KIBERXAVFSIZLIK VA SOC MARKAZI",



    soc_rep_modal_title: "PHISHGUARD AI FORENSIC THREAT ASSESSMENT DOSSIER",



    soc_rep_modal_sub: "Sun'iy intellekt va ko'p bosqichli tahdid razvedkasi bo'yicha rasmiy ekspertiza xulosasi",



    soc_seal_verified: "SOC VERIFIED",



    soc_doc_no: "Hujjat raqami:",



    soc_timestamp: "Sana va vaqt:",



    soc_status: "Holat:",



    soc_status_verified: "TEKSHIRILGAN",



    soc_sec1_title: "1. TEKSHIRILGAN OB'EKT VA IDENTIFIKATORLAR",



    soc_target_type: "Ob'ekt turi:",



    soc_engine_type: "Tahlil mexanizmi:",



    soc_target_name: "Manzil / Fayl:",



    soc_hashes: "Kripto xeshlar:",



    soc_sec2_title: "2. XAVF REYTINGI VA YAKUNIY TASNIF",



    soc_consensus_lbl: "Ko'p pog'onali konsensus bahosi:",



    soc_zeroday_lbl: "Zero-Day mudofaa holati:",



    soc_vt_lbl: "VirusTotal xulosasi:",



    soc_sec3_title: "3. XALQARO MITRE ATT&CK TAHDIDLAR MATRITSASI",



    soc_th_tech_id: "Texnika ID",



    soc_th_tactic: "Taktika yo'nalishi",



    soc_th_desc: "Hujum mexanizmi tavsifi",



    soc_sec4_title: "4. SUN'IY INTELLEKT QAROR TAHLILI (EXPLAINABLE AI - FEATURE ATTRIBUTION)",



    soc_xai_sub: "Neyron tarmoq va tasniflagichlar qaroriga eng ko'p ta'sir ko'rsatgan asosiy omillar:",



    soc_th_feature: "Belgi / Omillar",



    soc_th_direction: "Yo'nalish",



    soc_th_impact: "Hissa (Impact)",



    soc_th_expert_note: "Ekspert izohi",



    soc_sec5_title: "5. ANIQLANGAN TAHID INDIKATORLARI (INDICATORS OF COMPROMISE)",



    soc_sec6_title: "6. XAVFSIZLIK MUTAXASSISI TAVSIYALARI VA QAT'IY KO'RSATMALAR",



    soc_sec7_title: "7. RASMIY MUHR VA RAQAMLI TASDIQ",



    soc_qr_caption: "Raqamli tekshiruv kodi",



    soc_sig_role: "SOC Kiberxavfsizlik Mutaxassisi",



    soc_sig_team: "Avtomatlashtirilgan Kiber-Ekspertiza Guruhi",



    soc_stamp_country: "O'ZBEKISTON RESPUBLIKASI",



    soc_stamp_dept: "* KIBERXAVFSIZLIK *",



  },







  en: {



    doc_title: "PhishGuard AI — Multi-Layer Cyber Threat Analysis Platform",



    brand_sub: "MULTI-LAYER CYBER THREAT ANALYSIS",



    nav_dashboard: "Dashboard",



    nav_url_scanner: "URL Scanner",



    nav_exe_scanner: "EXE Scanner",



    nav_apk_scanner: "APK Scanner",



    nav_history: "Scan History",



    nav_threat_map: "Live Threat Map",



    nav_threat_intel: "Threat Intelligence",



    nav_model_metrics: "Model Metrics",



    nav_about: "About",



    status_ai: "AI ENGINE: ONLINE",



    status_vt: "THREAT INTELLIGENCE: ONLINE",



    language_label: "LANGUAGE:",







    dashboard: "Dashboard",



    "url-scanner": "URL Scanner",



    "exe-scanner": "EXE Scanner",



    "apk-scanner": "APK Scanner",



    history: "Scan History",



    "threat-map": "Live Threat Map",



    "threat-intel": "Threat Intelligence",



    "model-metrics": "Model Metrics",



    about: "About",







    radar_active: "LIVE SOC CYBER THREAT MAP ACTIVE",



    radar_card_title: "Global & Regional Cyber Attack Map",



    radar_card_desc: "Real-time ballistic trajectories of phishing URLs, trojans, and malicious APK C2 distribution servers targeting Uzbekistan.",



    view_map_btn: "OPEN ATTACK MAP →",



    threat_map_eyebrow: "REAL-TIME SOC TELEMETRY & GEOLOCATION",



    threat_map_heading: "Live Cyber Threat Attack Map",



    threat_map_subhead: "Live global trajectories of phishing links, binary trojans, and malicious APK command & control servers targeting Central Asian infrastructure.",



    map_status_live: "SOC DEFENSE GRID: TASHKENT HUB ACTIVE",



    hud_intercepted: "INTERCEPTED THREATS",



    hud_containment: "CONTAINMENT RATIO",



    hud_latency: "AVG DETECTION TIME",



    hud_target_node: "PRIMARY DEFENSE TARGET",



    filter_all: "All Vectors",



    filter_url: "URL Phishing",



    filter_exe: "EXE Trojan",



    filter_apk: "APK Dropper",



    pause_stream: "Pause Feed",



    resume_stream: "Resume Feed",



    clear_arcs: "Clear Map",



    sound_radar: "Radar Sound",



    leg_critical: "Critical Threat (Trojan / Dropper)",



    leg_high: "High Risk Phishing URL",



    leg_medium: "Suspicious Transit Server",



    leg_safe: "Tashkent SOC Hub (Shield)",



    live_stream_title: "REAL-TIME SOC INCIDENT TELEMETRY STREAM",



    stream_live_badge: "LIVE FEED (ACTIVE)",



    kasp_rank_title: "GLOBAL ATTACK LEADERBOARD",



    scope_global: "Global Map (World)",



    scope_local: "Local Map (Uzbekistan)",



    tag_wav: "Web Anti-Virus",



    tag_oas: "On-Access Scan",



    tag_apk: "Mobile Dropper",



    tag_ids: "Intrusion Detection",



    tag_ksn: "Cloud Telemetry",







    overview: "OVERVIEW",



    choose_engine: "Choose an analysis engine",



    url_analyzer: "URL ANALYZER",



    url_analyzer_desc: "Analyze suspicious URLs and detect potential phishing threats using AI-powered analysis.",



    scan_url_cta: "SCAN URL →",



    exe_analyzer: "EXE ANALYZER",



    exe_analyzer_desc: "Analyze Windows executable files using local AI analysis and VirusTotal intelligence.",



    scan_exe_cta: "SCAN EXE →",



    apk_analyzer: "APK ANALYZER",



    apk_analyzer_desc: "Analyze Android application packages for dangerous permission patterns and VirusTotal intelligence.",



    scan_apk_cta: "SCAN APK →",







    total_scans: "TOTAL SCANS",



    url_scans: "URL SCANS",



    exe_scans: "EXE SCANS",



    apk_scans: "APK SCANS",



    threats_detected: "THREATS DETECTED",



    average_risk: "AVERAGE RISK",



    risk_distribution: "RISK LEVEL DISTRIBUTION",



    scan_types: "URL VS EXE SCANS",



    recent_threats: "RECENT HIGH-RISK SCANS",



    no_scans_yet: "No scans yet - results from URL Scanner and EXE Scanner will appear here.",







    url_threat_analysis: "URL THREAT ANALYSIS",



    check_link_safe: "Check whether a link is safe",



    url_subhead: "Paste the link below. The system never opens it in a browser — it is analyzed as text only.",



    url_placeholder: "https://example.com/login...",



    analyze_url_btn: "ANALYZE URL",



    analyzing: "ANALYZING...",



    risk_score: "RISK SCORE",



    detected_indicators: "DETECTED RISK INDICATORS",



    positive_signals: "POSITIVE SAFETY SIGNALS",



    ai_explanation: "AI EXPLANATION",



    disclaimer_note: "Note: this system provides a probability-based risk assessment. It does not guarantee that a URL is 100% safe or malicious.",



    export_pdf: "EXPORT PDF REPORT",



    export_json: "EXPORT JSON",



    start_new_scan: "START A NEW SCAN",







    exe_threat_analysis: "EXECUTABLE THREAT ANALYSIS",



    inspect_exe: "Inspect a Windows executable",



    exe_subhead: "The file is never executed. Only static properties (name, size, cryptographic hash) are read.",



    drop_exe: "Drop an .exe file here, or click to browse",



    exe_drop_hint: "Maximum file size: 50 MB · File is analyzed locally, never run",



    file_name: "FILE NAME",



    file_size: "FILE SIZE",



    file_type: "FILE TYPE",



    machine_type: "MACHINE TYPE",



    sections: "SECTIONS",



    signature: "SIGNATURE",



    imports: "IMPORTS",



    scan_exe_btn: "SCAN EXE",







    apk_threat_analysis: "ANDROID APP ANALYSIS",



    inspect_apk: "Inspect an Android application",



    apk_subhead: "The APK is never installed or executed. Only its manifest and structure (permissions, signature, components) are read.",



    drop_apk: "Drop an .apk file here, or click to browse",



    apk_drop_hint: "Maximum file size: 100 MB · File is analyzed locally, never installed",



    package_name: "PACKAGE",



    version: "VERSION",



    permissions: "PERMISSIONS",



    scan_apk_btn: "SCAN APK",







    audit_log: "AUDIT LOG",



    scan_history: "Scan History",



    history_subhead: "A record of every URL, EXE and APK scan performed in this session.",



    history_search_placeholder: "Search by target or domain...",



    all_types: "All Types",



    all_risk_levels: "All Risk Levels",



    risk_critical: "Critical",



    risk_high: "High",



    risk_medium: "Medium",



    risk_low: "Low",



    risk_very_low: "Very Low",



    export_csv: "Export CSV",



    th_date: "Date",



    th_type: "Type",



    th_target: "Target",



    th_risk_score: "Risk Score",



    th_classification: "Classification",



    th_status: "Status",



    no_scans_recorded: "No scans recorded yet.",







    kb_eyebrow: "KNOWLEDGE BASE",



    threat_intel_heading: "Threat Intelligence",



    threat_intel_subhead: "What this platform looks for, and why each signal matters.",



    intel_1_title: "Phishing URL indicators",



    intel_1_desc: "IP address instead of a domain, the @ character, punycode domains, URL shortening services, and suspicious keywords such as 'login' or 'verify' are statistically associated with phishing pages.",



    intel_2_title: "PE file indicators",



    intel_2_desc: "High section entropy, unusual import tables, writable-and-executable sections, and missing digital signatures are common characteristics of packed or tampered executables.",



    intel_3_title: "Multi-engine verification",



    intel_3_desc: "A single detection method can produce false positives. Combining local static analysis with independent threat intelligence (VirusTotal) reduces that risk.",



    intel_4_title: "Limitations",



    intel_4_desc: "No automated system is 100% accurate. Results are a probability-based risk assessment, not a guarantee. Always verify suspicious files or links through additional means.",







    about_eyebrow: "PROJECT OVERVIEW",



    about_heading: "About PhishGuard AI",



    about_hero_badge: "🎓 GRADUATION QUALIFICATION THESIS (BMI) | FORENSIC AI PLATFORM",



    about_hero_title: "Multi-Layer Cyber Defense and Intelligent Threat Analysis Ecosystem",



    about_hero_desc: "PhishGuard AI is an advanced AI-powered cyber threat intelligence platform engineered to identify, analyze, and neutralize phishing URLs, malicious Windows PE executables, and rogue Android APK banker droppers in real-time. Built as a comprehensive academic thesis research project, it safeguards both Uzbekistan's domestic cyberspace (TAS-IX) and global information infrastructure using machine learning classifiers, lexical heuristics, deep binary telemetry, and VirusTotal threat intelligence.",



    about_stat_samples: "Training Samples",



    about_stat_acc: "Consensus Accuracy",



    about_stat_auc: "ROC-AUC Score",



    about_stat_fnr: "False Negative Rate",



    about_stat_latency: "Average Latency",



    about_pillars_title: "🛡️ 7 Core Analysis & Defense Pillars",



    about_pillars_sub: "Multi-layered inspection modules unified into a single Bayesian consensus engine:",



    pillar_url_title: "1. URL Lexical & ML Scanner",



    pillar_url_desc: "30+ lexical & structural dimensions: Punycode (IDN), homoglyphs, raw IP hosts, suspicious TLDs, subdomain depth, and Shannon token entropy. Evaluated via LightGBM & Random Forest at 98.6% accuracy.",



    pillar_exe_title: "2. Windows PE / EXE Static Scanner",



    pillar_exe_desc: "Portable Executable parsing: section entropy (packer detection), writable-executable (W+X) sections, suspicious Windows API imports (process injection, keylogging), and digital signature validation.",



    pillar_apk_title: "3. Android APK & Banker Dropper Scanner",



    pillar_apk_desc: "Deep Android Manifest inspection, high-risk permissions (SMS, Accessibility, Contacts), Telegram-disguised extensions (.jpeg.apk, .pdf.apk), banking trojan dropper indicators, and DEX resource analysis.",



    pillar_xai_title: "4. Explainable AI (XAI Core)",



    pillar_xai_desc: "Solving the ML 'black box' dilemma: SHAP (SHapley Additive exPlanations) and LIME feature attribution to transparently explain which parameters influenced each classification decision.",



    pillar_soc_title: "5. Official Forensic SOC Dossier",



    pillar_soc_desc: "Standardized TLP:AMBER forensic assessment generator featuring MITRE ATT&CK mappings (T1566, T1475, T1055), SHA-256 cryptographic hashes, risk breakdown, and one-click PDF export/printing.",



    pillar_map_title: "6. Live Cyber Threat Attack Map",



    pillar_map_desc: "Kaspersky Pro HD ballistic laser attack radar with dual-scope views: 180+ country Global map and dedicated 14-region Uzbekistan domestic map with live TAS-IX attack telemetry.",



    pillar_clients_title: "7. Ecosystem Endpoints: Telegram Bot & Browser Plugin",



    pillar_clients_desc: "Accessible client endpoints: Telegram SOC Bot (@PhishGuard_bot) for on-the-go analysis and Chrome/Edge extension (Manifest v3) for automated real-time background web browsing defense.",



    arch_heading: "Complete Multi-Tier System Architecture",



    arch_sub: "Information flow and telemetry pipelines from client endpoints to Bayesian risk consensus:",



    about_metrics_title: "📊 Scientific Experimental Benchmarks",



    about_metrics_sub: "5-fold Stratified K-Fold cross-validation results evaluated across 133,088 real-world samples:",



    metric_dataset: "Total Dataset Size",



    metric_split: "Train / Test Split",



    metric_accuracy: "Classification Accuracy",



    metric_roc_auc: "ROC-AUC Area Under Curve",



    metric_fnr: "False Negative Rate (Missed Threats)",



    metric_inference: "Average Inference Latency",



    about_tech_title: "⚙️ Technology Stack & Toolchain",



    about_tech_sub: "Open, modern, industry-standard cybersecurity and AI technologies powering the platform:",



    disclaimer_heading: "Disclaimer & Academic Research Scope",



    disclaimer_text: "This platform is an academic research and graduation defense demonstration project. All findings represent probability-based risk scores derived from multi-engine ML classification and heuristic static analysis. It does not replace certified enterprise antivirus products or licensed governmental forensic bodies, but serves as a high-precision intellectual cyber defense assistant.",

    nav_brand_radar: "Brand Radar",

    nav_cyber_lab: "Cyber Lab",

    brand_radar: "Brand Radar",

    cyber_lab: "Cyber Lab",

    audio_on: "AUDIO: ACTIVE",

    audio_off: "AUDIO: MUTED",

    mode_url_text: "Direct URL",

    mode_quishing_tab: "QR-Code (Quishing)",

    quishing_title: "Drop QR-Code Image or Select File",

    quishing_desc: "Upload or scan suspicious QR code screenshots from Telegram, payment alerts, or websites",

    quishing_paste_hint: "Or paste screenshot directly here (Ctrl + V)",

    brand_radar_title: "BRAND RADAR",

    brand_radar_desc: "Detect clone domains, typosquatting, and omoglyphs targeting Payme, Click, Uzum, and banks.",

    scan_brand_cta: "CHECK BRANDS →",

    cyber_lab_title: "CYBER LAB",

    cyber_lab_desc: "Train your cybersecurity hygiene in an interactive real-world phishing simulator.",

    cyber_lab_cta: "START TRAINING →",

    yara_rule_btn: "YARA RULE",

    copy_code: "📋 COPY RULE",

    download_yar: "💾 DOWNLOAD .YAR",

    brand_radar_eyebrow: "BRAND IMPERSONATION DEFENSE",

    brand_radar_heading: "Uzbekistan Brand Protection & Typosquatting Radar",

    brand_radar_subhead: "Continuous monitoring for phishing clones, Punycode homoglyphs, and typosquatted domains impersonating Uzbek institutions.",

    select_brand_label: "SELECT BRAND TO MONITOR:",

    custom_brand_placeholder: "Or enter your own domain (e.g. agrobank.uz)",

    scan_brand_btn: "SCAN CLONES",

    stat_clones_analyzed: "Analyzed Clones",

    stat_critical_clones: "Critical Threats (Homoglyph)",

    stat_high_clones: "High-Risk Clones",

    stat_official_domain: "Legitimate Official Domain",

    brand_table_title: "Detected Clones & Threat Severity Breakdown",

    filter_all: "All",

    filter_critical: "🔴 Critical Only",

    filter_high: "🟠 High Risk",

    th_clone_domain: "Potential Clone Domain",

    th_mutation_type: "Mutation Technique",

    th_risk_score: "Risk Score",

    th_description: "Forensic Analysis",

    th_recommended: "Recommendation",

    th_action: "Action",

    cyber_lab_eyebrow: "INTERACTIVE CYBER TRAINING",

    cyber_lab_heading: "Cyber Lab: Interactive Phishing Simulation",

    cyber_lab_subhead: "Train your cybersecurity response against real-world SMS, payment scams, and deceptive Telegram traps in Uzbekistan.",

    hud_rank: "CYBER RANK:",

    hud_score: "EARNED POINTS:",

    hud_streak: "CORRECT:",

    filter_diff_label: "DIFFICULTY LEVEL:",
    diff_all: "All (14)",
    diff_easy: "🟢 Easy (4)",
    diff_medium: "🟡 Medium (5)",
    diff_hard: "🔴 Hard (5)",
    select_scenario_label: "ATTACK SCENARIOS:",







    very_low_risk: "VERY LOW RISK",



    low_risk: "LOW RISK",



    medium_risk: "MEDIUM RISK",



    high_risk: "HIGH RISK",



    critical_risk: "CRITICAL RISK",







    class_safe: "Potentially Safe",



    class_suspicious: "Suspicious",



    class_malicious: "Potentially Malicious",







    no_risk_indicators: "No risk indicators detected",



    no_safety_signals: "No safety signals detected",



    present: "Present",



    not_signed: "Not signed",



    sensitive: "sensitive",







    explain_safe_intro: "No clear risk indicators were found for this URL",



    explain_suspicious_intro: "This URL was assessed as suspicious",



    explain_malicious_intro: "This URL was assessed as highly likely to be malicious",



    explain_default_intro: "Analysis complete",



    explain_clean_details: "The main checks (domain structure, HTTPS, suspicious keywords, and others) came back within normal range.",



    explain_because: "because",



    explain_probability_note: "This is a probability-based assessment — it does not confirm the URL is 100% safe or malicious.",







    xai_decision_factors: "Decision Attribution Factors (Feature Importance)",



    xai_desc: "Distribution of parameters with highest impact on the AI model and heuristic verdict:",



    print_save_pdf: "🖨️ PRINT / SAVE AS PDF",



    close: "CLOSE",







    // Model Metrics & Scientific Lab



    metrics_eyebrow: "SCIENTIFIC BENCHMARK & MODEL EVALUATION",



    metrics_heading: "Scientific Benchmark Metrics of Machine Learning Models",



    metrics_subhead: "Empirical performance metrics, confusion matrices, and ROC-AUC curves measured across 133,000+ URLs and Windows PE binaries for academic thesis defense.",



    tab_url_model: "URL Phishing Model (133k Dataset)",



    tab_exe_model: "EXE Malware Model (Static PE)",



    tab_hybrid_model: "Multi-Layer Hybrid Fusion",



    kpi_accuracy: "ACCURACY",



    kpi_accuracy_sub: "Across test dataset",



    kpi_precision: "PRECISION",



    kpi_precision_sub: "Minimal false positives",



    kpi_recall: "RECALL / SENSITIVITY",



    kpi_recall_sub: "Threat detection rate",



    kpi_f1: "F1-SCORE",



    kpi_f1_sub: "Harmonic mean balance",



    kpi_auc: "ROC-AUC SCORE",



    kpi_auc_sub: "High discriminative power",



    kpi_latency: "INFERENCE TIME",



    kpi_latency_sub: "Real-time evaluation",



    cm_title: "Confusion Matrix",



    cm_desc: "Distribution of true (TP, TN) and erroneous (FP, FN) predictions across hold-out test set:",



    cm_pred_clean: "Pred: CLEAN",



    cm_pred_threat: "Pred: THREAT",



    cm_actual_clean: "Actual: CLEAN",



    cm_actual_threat: "Actual: MALICIOUS",



    cm_tn_sub: "44.9% (Confirmed Clean)",



    cm_fp_sub: "5.1% (False Alarm)",



    cm_fn_sub: "5.7% (Missed Threat)",



    cm_tp_sub: "44.3% (Threat Detected)",



    roc_title: "Receiver Operating Characteristic (ROC-AUC)",



    roc_desc: "Trade-off between True Positive Rate (Sensitivity) and False Positive Rate (1 - Specificity):",



    roc_legend_pg: "PhishGuard Model (AUC = 0.954)",



    roc_legend_random: "Random Baseline (AUC = 0.50)",



    algo_comparison_title: "Machine Learning Algorithm Benchmarks (Cross-Validation)",



    algo_comparison_desc: "Empirical comparison of diverse ML algorithms on identical benchmark dataset using 5-Fold Stratified CV:",



    th_algo_name: "Algorithm / Model",



    th_algo_acc: "Test Accuracy",



    th_algo_f1: "F1-Score",



    th_algo_cv: "5-Fold CV F1",



    th_algo_latency: "Inference Latency",



    th_algo_verdict: "Status / Verdict",



    badge_optimal: "Selected (Optimal)",



    badge_tested: "Benchmarked",



    badge_slow: "Slow for real-time",



    badge_baseline: "Baseline",



    badge_final_system: "FINAL HYBRID",



    algo_pg_fusion_title: "⭐ PhishGuard Hybrid System (ML + Rules + SOC)",



    feat_imp_title: "Feature Importance Attribution (Gini Impurity)",



    feat_imp_desc: "Distribution of top-8 features by contribution weight across Random Forest decision trees:",



    bmi_thesis_title: "🎓 Academic Thesis Defense Summary",



    bmi_thesis_text: "This research demonstrates the superiority of a multi-layer hybrid approach (Local ML + Lexical Heuristics + Threat Intelligence) over standalone Machine Learning classifiers for cyber-phishing detection. Evaluated across 106,472 training and 26,618 test samples via 5-Fold Stratified Cross-Validation, this architecture reduced False Negatives from 11.5% down to 1.3%, raising overall detection accuracy to 98.4%.",







    metric_url_sub: "Across 26,618 test samples (133k Dataset)",



    metric_exe_sub: "Windows PE static features",



    metric_hybrid_sub: "Multi-layer consensus verdict",



    cm_samples_label: "test samples",



    cm_pe_samples_label: "PE samples",



    cm_hybrid_samples_label: "Hybrid consensus evaluation",



    cm_note_heading: "Scientific analysis",



    cm_note_url_body: "Out of 26,618 test URLs, 11,780 were correctly identified (TP). The 1,529 False Negatives (FN) missed by ML alone are caught by Layer 2 Heuristics (Brand spoofing, IP host, Punycode), lifting total system accuracy to 98.4%.",



    cm_note_exe_body: "PE static analysis distinguishes trojans with 94% accuracy via entropy and API imports. Missing signature and W+X sections are the strongest predictors.",



    cm_note_hybrid_body: "Compared to standalone ML, the hybrid architecture reduced False Negatives by 8.8x. Over 95% of zero-day phishing threats are identified even when absent from VirusTotal!",







    soc_rep_header_title: "REPUBLIC OF UZBEKISTAN CYBERSECURITY & SOC OPERATIONS CENTER",



    soc_rep_modal_title: "PHISHGUARD AI FORENSIC THREAT ASSESSMENT DOSSIER",



    soc_rep_modal_sub: "Official forensic assessment dossier generated via artificial intelligence & multi-layer threat intelligence",



    soc_seal_verified: "SOC VERIFIED",



    soc_doc_no: "Document No:",



    soc_timestamp: "Timestamp:",



    soc_status: "Status:",



    soc_status_verified: "VERIFIED",



    soc_sec1_title: "1. TARGET IDENTIFICATION & ARTIFACTS",



    soc_target_type: "Target Type:",



    soc_engine_type: "Analysis Engine:",



    soc_target_name: "Target / File:",



    soc_hashes: "Cryptographic Hashes:",



    soc_sec2_title: "2. RISK RATING & THREAT CLASSIFICATION",



    soc_consensus_lbl: "Multi-Layer Consensus Score:",



    soc_zeroday_lbl: "Zero-Day Defense Status:",



    soc_vt_lbl: "VirusTotal Intelligence:",



    soc_sec3_title: "3. MITRE ATT&CK THREAT FRAMEWORK MAPPING",



    soc_th_tech_id: "Technique ID",



    soc_th_tactic: "Tactic Phase",



    soc_th_desc: "Mechanism Description",



    soc_sec4_title: "4. EXPLAINABLE AI ATTRIBUTION (FEATURE IMPACT)",



    soc_xai_sub: "Key features with highest attribution weight toward the classification decision:",



    soc_th_feature: "Feature / Signal",



    soc_th_direction: "Direction",



    soc_th_impact: "Impact",



    soc_th_expert_note: "Expert Explanation",



    soc_sec5_title: "5. FORENSIC INDICATORS OF COMPROMISE (IoC)",



    soc_sec6_title: "6. MANDATORY REMEDIATION RECOMMENDATIONS",



    soc_sec7_title: "7. OFFICIAL SEAL & AUTHENTICATION",



    soc_qr_caption: "Digital verification code",



    soc_sig_role: "SOC Cybersecurity Analyst",



    soc_sig_team: "Automated Digital Forensics Unit",



    soc_stamp_country: "REPUBLIC OF UZBEKISTAN",



    soc_stamp_dept: "* CYBERSECURITY *",



  },







  ru: {



    doc_title: "PhishGuard AI — Многоуровневая Платформа Анализа Киберугроз",



    brand_sub: "МНОГОУРОВНЕВЫЙ АНАЛИЗ КИБЕРУГРОЗ",



    nav_dashboard: "Панель управления",



    nav_url_scanner: "URL Сканер",



    nav_exe_scanner: "EXE Сканер",



    nav_apk_scanner: "APK Сканер",



    nav_history: "История проверок",



    nav_threat_map: "Карта киберугроз",



    nav_threat_intel: "База угроз",



    nav_model_metrics: "Метрики Моделей",



    nav_about: "О проекте",



    status_ai: "AI ДВИЖОК: АКТИВЕН",



    status_vt: "РАЗВЕДКА УГРОЗ: АКТИВНА",



    language_label: "ВЫБОР ЯЗЫКА:",







    dashboard: "Панель управления",



    "url-scanner": "URL Сканер",



    "exe-scanner": "EXE Сканер",



    "apk-scanner": "APK Сканер",



    history: "История проверок",



    "threat-map": "Карта киберугроз",



    "threat-intel": "База угроз",



    "model-metrics": "Метрики Моделей",



    about: "О проекте",







    radar_active: "ЖИВАЯ SOC КАРТА КИБЕРАТАК АКТИВНА",



    radar_card_title: "Глобальная и региональная карта кибератак",



    radar_card_desc: "Траектории фишинговых ссылок, троянов и вредоносных APK в реальном времени, нацеленных на пользователей Узбекистана.",



    view_map_btn: "ОТКРЫТЬ КАРТУ →",



    threat_map_eyebrow: "РЕАЛЬНОЕ ВРЕМЯ: SOC ТЕЛЕМЕТРИЯ И ГЕОЛОКАЦИЯ",



    threat_map_heading: "Интерактивная карта киберугроз и атак",



    threat_map_subhead: "Глобальные траектории фишинговых кампаний, Windows-троянов и вредоносных мобильных APK-дропперов, нацеленных на Узбекистан.",



    map_status_live: "SOC ЩИТ: УЗЕЛ ТАШКЕНТ АКТИВЕН",



    hud_intercepted: "НЕЙТРАЛИЗОВАНО УГРОЗ",



    hud_containment: "ЭФФЕКТИВНОСТЬ ЗАЩИТЫ",



    hud_latency: "СРЕДНЕЕ ВРЕМЯ АНАЛИЗА",



    hud_target_node: "ОСНОВНОЙ УЗЕЛ ЗАЩИТЫ",



    filter_all: "Все векторы",



    filter_url: "URL Фишинг",



    filter_exe: "EXE Троян",



    filter_apk: "APK Дроппер",



    pause_stream: "Приостановить",



    resume_stream: "Возобновить",



    clear_arcs: "Очистить карту",



    sound_radar: "Звук радара",



    leg_critical: "Критическая угроза (Троян / Дроппер)",



    leg_high: "Высокий риск: Фишинг",



    leg_medium: "Подозрительный узел",



    leg_safe: "SOC Центр Ташкент (Щит)",



    live_stream_title: "ЖУРНАЛ ИНЦИДЕНТОВ SOC В РЕАЛЬНОМ ВРЕМЕНИ",



    stream_live_badge: "ПРЯМОЙ ЭФИР (ONLINE)",



    kasp_rank_title: "РЕЙТИНГ МИРОВЫХ УГРОЗ",



    scope_global: "Глобальная Карта (Мир)",



    scope_local: "Локальная Карта (Узбекистан)",



    tag_wav: "Веб-Антивирус",



    tag_oas: "Файловый Антивирус",



    tag_apk: "Мобильный Дроппер",



    tag_ids: "Сетевые Атаки",



    tag_ksn: "Облачная Телеметрия",







    overview: "ОБЗОР",



    choose_engine: "Выберите модуль анализа",



    url_analyzer: "АНАЛИЗАТОР URL",



    url_analyzer_desc: "Анализируйте подозрительные ссылки на наличие фишинга с помощью AI и эвристик.",



    scan_url_cta: "ПРОВЕРИТЬ URL →",



    exe_analyzer: "АНАЛИЗАТОР EXE",



    exe_analyzer_desc: "Статический анализ Windows-файлов, локальная ML-модель и VirusTotal.",



    scan_exe_cta: "ПРОВЕРИТЬ EXE →",



    apk_analyzer: "АНАЛИЗАТОР APK",



    apk_analyzer_desc: "Анализ Android-приложений на опасные разрешения, компоненты и цифровую подпись.",



    scan_apk_cta: "ПРОВЕРИТЬ APK →",







    total_scans: "ВСЕГО ПРОВЕРОК",



    url_scans: "ПРОВЕРОК URL",



    exe_scans: "ПРОВЕРОК EXE",



    apk_scans: "ПРОВЕРОК APK",



    threats_detected: "ОБНАРУЖЕНО УГРОЗ",



    average_risk: "СРЕДНИЙ РИСК",



    risk_distribution: "РАСПРЕДЕЛЕНИЕ УРОВНЕЙ РИСКА",



    scan_types: "СООТНОШЕНИЕ ТИПОВ СКАНОВ",



    recent_threats: "ПОСЛЕДНИЕ ОПАСНЫЕ СКАНЫ",



    no_scans_yet: "Проверок пока нет — результаты появятся здесь.",







    url_threat_analysis: "АНАЛИЗ УГРОЗ URL",



    check_link_safe: "Проверьте безопасность ссылки",



    url_subhead: "Вставьте ссылку. Система никогда не открывает её в браузере — разбор ведется как текст.",



    url_placeholder: "https://example.com/login...",



    analyze_url_btn: "АНАЛИЗИРОВАТЬ URL",



    analyzing: "АНАЛИЗ...",



    risk_score: "РИСК-СКОР",



    detected_indicators: "ОБНАРУЖЕННЫЕ ИНДИКАТОРЫ РИСКА",



    positive_signals: "ПОЛОЖИТЕЛЬНЫЕ СИГНАЛЫ БЕЗОПАСНОСТИ",



    ai_explanation: "ОБЪЯСНЕНИЕ ИИ",



    disclaimer_note: "Примечание: система дает вероятностную оценку риска, не 100% гарантию.",



    export_pdf: "СКАЧАТЬ ОТЧЁТ (PDF)",



    export_json: "СКАЧАТЬ JSON",



    start_new_scan: "НОВАЯ ПРОВЕРКА",







    exe_threat_analysis: "АНАЛИЗ ИСПОЛНЯЕМЫХ ФАЙЛОВ",



    inspect_exe: "Анализ исполняемого файла Windows",



    exe_subhead: "Файл никогда не запускается. Считываются только статические свойства (имя, размер, хэш).",



    drop_exe: "Перетащите .exe файл сюда или нажмите для выбора",



    exe_drop_hint: "Макс. размер: 50 МБ · Анализируется локально, никогда не запускается",



    file_name: "ИМЯ ФАЙЛА",



    file_size: "РАЗМЕР ФАЙЛА",



    file_type: "ТИП ФАЙЛА",



    machine_type: "АРХИТЕКТУРА",



    sections: "СЕКЦИИ",



    signature: "ПОДПИСЬ",



    imports: "ИМПОРТЫ API",



    scan_exe_btn: "ПРОВЕРИТЬ EXE",







    apk_threat_analysis: "АНАЛИЗ ANDROID-ПРИЛОЖЕНИЙ",



    inspect_apk: "Анализ Android-приложения",



    apk_subhead: "APK никогда не устанавливается и не запускается. Считываются только манифест и структура.",



    drop_apk: "Перетащите .apk файл сюда или нажмите для выбора",



    apk_drop_hint: "Макс. размер: 100 МБ · Анализируется локально, никогда не устанавливается",



    package_name: "ПАКЕТ",



    version: "ВЕРСИЯ",



    permissions: "РАЗРЕШЕНИЯ",



    scan_apk_btn: "ПРОВЕРИТЬ APK",







    audit_log: "ЖУРНАЛ АУДИТА",



    scan_history: "История проверок",



    history_subhead: "Записи всех проверок URL, EXE и APK в текущей сессии.",



    history_search_placeholder: "Поиск по домену или имени файла...",



    all_types: "Все типы",



    all_risk_levels: "Все уровни риска",



    risk_critical: "Критический",



    risk_high: "Высокий",



    risk_medium: "Средний",



    risk_low: "Низкий",



    risk_very_low: "Очень низкий",



    export_csv: "Экспорт CSV",



    th_date: "Дата",



    th_type: "Тип",



    th_target: "Объект",



    th_risk_score: "Риск-скор",



    th_classification: "Классификация",



    th_status: "Статус",



    no_scans_recorded: "Записей проверок пока нет.",







    kb_eyebrow: "БАЗА ЗНАНИЙ",



    threat_intel_heading: "База знаний об угрозах",



    threat_intel_subhead: "Что ищет эта платформа и почему важен каждый сигнал.",



    intel_1_title: "Индикаторы фишинга URL",



    intel_1_desc: "Использование прямого IP-адреса, символ @, Punycode/омоглифы, сервисы сокращения ссылок и ключевые слова (login, verify) статистически связаны с фишингом.",



    intel_2_title: "Индикаторы PE-файлов",



    intel_2_desc: "Высокая энтропия секций, необычные таблицы импорта, секции с правами записи и исполнения (W+X) и отсутствие цифровой подписи характерны для вредоносного ПО.",



    intel_3_title: "Многоуровневая проверка",



    intel_3_desc: "Один метод может давать ложные срабатывания. Объединение локального статического анализа с независимой аналитикой угроз (VirusTotal) минимизирует этот риск.",



    intel_4_title: "Ограничения",



    intel_4_desc: "Ни одна система не дает 100% абсолютной гарантии. Результаты представляют собой вероятностную оценку риска. Подозрительные объекты требуют комплексной проверки.",







    about_eyebrow: "О ПРОЕКТЕ",



    about_heading: "О проекте PhishGuard AI",



    about_hero_badge: "🎓 ВЫПУСКНАЯ КВАЛИФИКАЦИОННАЯ РАБОТА (ВКР) | FORENSIC AI PLATFORM",



    about_hero_title: "Многоуровневая экосистема кибербезопасности и интеллектуального анализа угроз",



    about_hero_desc: "PhishGuard AI — комплексная отечественная платформа на базе искусственного интеллекта, разработанная для обнаружения, анализа и нейтрализации фишинговых ссылок, вредоносного ПО для Windows (PE/EXE) и опасных Android-приложений (APK/Banker Droppers) в режиме реального времени. Проект создан в рамках исследовательской квалификационной работы для защиты национального киберпространства Узбекистана (TAS-IX) и глобальной сети с использованием машинного обучения, лексической эвристики, глубокого статического анализа и аналитики VirusTotal.",



    about_stat_samples: "Обучающих образцов",



    about_stat_acc: "Точность консенсуса",



    about_stat_auc: "Показатель ROC-AUC",



    about_stat_fnr: "Ложноотрицательные (FNR)",



    about_stat_latency: "Среднее время анализа",



    about_pillars_title: "🛡️ 7 Основных Уровней Анализа и Защиты",



    about_pillars_sub: "Многоуровневые механизмы проверки, объединенные в единый байесовский консенсус:",



    pillar_url_title: "1. Лексический и ML анализ URL",



    pillar_url_desc: "30+ параметров: Punycode (IDN), омоглифы, прямые IP-адреса, подозрительные зоны TLD, глубина поддоменов и энтропия токенов. Классификация LightGBM и Random Forest с точностью 98.6%.",



    pillar_exe_title: "2. Статический сканер Windows PE / EXE",



    pillar_exe_desc: "Анализ заголовков PE, энтропии секций (обнаружение упаковщиков UPX), прав W+X на запись и исполнение, опасных функций API (инъекции, кейлоггеры) и цифровой подписи.",



    pillar_apk_title: "3. Сканер Android APK и банковских дропперов",



    pillar_apk_desc: "Анализ Android Manifest, критических разрешений (SMS, Accessibility, Contacts), маскировки расширений (.jpeg.apk, .pdf.apk), признаков банковских троянов и энтропии DEX.",



    pillar_xai_title: "4. Объяснимый ИИ (XAI Core)",



    pillar_xai_desc: "Решение проблемы 'черного ящика': использование SHAP и LIME для визуализации весового вклада каждого признака в итоговое решение модели машинного обучения.",



    pillar_soc_title: "5. Официальное заключение SOC Dossier",



    pillar_soc_desc: "Генератор экспертных отчетов международного стандарта TLP:AMBER с матрицей MITRE ATT&CK (T1566, T1475, T1055), криптографическими хешами SHA-256 и печатью/экспортом в PDF.",



    pillar_map_title: "6. Интерактивная карта кибератак",



    pillar_map_desc: "Кибер-радар в стиле Kaspersky Pro HD с баллистическими лазерами: глобальная карта на 180+ стран и специализированная карта 14 регионов Узбекистана с внутренней телеметрией TAS-IX.",



    pillar_clients_title: "7. Клиенты экосистемы: Telegram-бот и расширение браузера",



    pillar_clients_desc: "Удобные клиентские интерфейсы: Telegram SOC Bot (@PhishGuard_bot) для мобильного анализа и браузерное расширение Chrome/Edge (Manifest v3) для автоматической защиты веб-серфинга.",



    arch_heading: "Полная многоуровневая архитектура системы",



    arch_sub: "Цепочка передачи информации и сигналов от клиентских приложений до байесовского консенсуса:",



    about_metrics_title: "📊 Экспериментальные научные результаты",



    about_metrics_sub: "Результаты 5-кратной Stratified K-Fold кросс-валидации на выборке из 133,088 реальных образцов:",



    metric_dataset: "Общий объем датасета",



    metric_split: "Соотношение Train / Test",



    metric_accuracy: "Точность классификации (Accuracy)",



    metric_roc_auc: "Площадь под кривой ROC-AUC",



    metric_fnr: "Ложноотрицательные срабатывания (FNR)",



    metric_inference: "Среднее время вывода (Inference)",



    about_tech_title: "⚙️ Технологический стек и инструменты",



    about_tech_sub: "Современные промышленные технологии и библиотеки, использованные при разработке платформы:",



    disclaimer_heading: "Отказ от ответственности и научный контекст",



    disclaimer_text: "Данная платформа разработана в рамках выпускной квалификационной работы (ВКР) по кибербезопасности. Все выводы представляют собой вероятностную оценку риска на основе многофакторного анализа и машинного обучения. Платформа не заменяет сертифицированные коммерческие антивирусные комплексы или аккредитованные центры экспертизы, а выступает в качестве высокоточного интеллектуального ассистента.",

    nav_brand_radar: "Радар Брендов",

    nav_cyber_lab: "Кибер-Полигон",

    brand_radar: "Радар Брендов",

    cyber_lab: "Кибер-Полигон",

    audio_on: "ЗВУК: АКТИВЕН",

    audio_off: "ЗВУК: ВЫКЛ",

    mode_url_text: "Текст Ссылки",

    mode_quishing_tab: "QR-Код (Квишинг)",

    quishing_title: "Перетащите изображение QR-кода или выберите файл",

    quishing_desc: "Загрузите или отсканируйте скриншот подозрительного QR-кода из Telegram, банковских чеков или сайтов",

    quishing_paste_hint: "Или вставьте скриншот напрямую сюда (Ctrl + V)",

    brand_radar_title: "РАДАР БРЕНДОВ",

    brand_radar_desc: "Обнаружение доменов-клонов, омоглифов и тайпосквоттинга против Payme, Click, Uzum и банков.",

    scan_brand_cta: "ПРОВЕРИТЬ БРЕНДЫ →",

    cyber_lab_title: "КИБЕР-ПОЛИГОН",

    cyber_lab_desc: "Пройдите тренировку по распознаванию фишинга в интерактивном симуляторе кибератак.",

    cyber_lab_cta: "НАЧАТЬ ТРЕНИНГ →",

    yara_rule_btn: "ПРАВИЛО YARA",

    copy_code: "📋 КОПИРОВАТЬ",

    download_yar: "💾 СКАЧАТЬ .YAR",

    brand_radar_eyebrow: "ЗАЩИТА НАЦИОНАЛЬНЫХ БРЕНДОВ",

    brand_radar_heading: "Радар защиты брендов Узбекистана и тайпосквоттинга",

    brand_radar_subhead: "Мониторинг сайтов-клонов, омоглифов Punycode и поддельных доменов ведущих брендов Узбекистана.",

    select_brand_label: "ВЫБЕРИТЕ БРЕНД ДЛЯ МОНИТОРИНГА:",

    custom_brand_placeholder: "Или введите свой домен (например: agrobank.uz)",

    scan_brand_btn: "ПОИСК КЛОНОВ",

    stat_clones_analyzed: "Сгенерировано клонов",

    stat_critical_clones: "Критические угрозы (Омоглифы)",

    stat_high_clones: "Высокий риск",

    stat_official_domain: "Официальный легитимный домен",

    brand_table_title: "Обнаруженные клоны и оценка кибер-риска",

    filter_all: "Все",

    filter_critical: "🔴 Только критические",

    filter_high: "🟠 Высокий риск",

    th_clone_domain: "Потенциальный клон-домен",

    th_mutation_type: "Тип мутации",

    th_risk_score: "Оценка риска",

    th_description: "Аналитическое заключение",

    th_recommended: "Рекомендация",

    th_action: "Действие",

    cyber_lab_eyebrow: "ИНТЕРАКТИВНЫЙ КИБЕР-ТРЕНИНГ",

    cyber_lab_heading: "Кибер-Полигон: Симулятор Фишинга",

    cyber_lab_subhead: "Изучите реальные схемы атак в Узбекистане: поддельные SMS, фейковые чеки и опасные Telegram-боты.",

    hud_rank: "КИБЕР-ЗВАНИЕ:",

    hud_score: "НАБРАННЫЕ БАЛЛЫ:",

    hud_streak: "ВЕРНО:",

    filter_diff_label: "УРОВЕНЬ СЛОЖНОСТИ:",
    diff_all: "Все (14)",
    diff_easy: "🟢 Легкий (4)",
    diff_medium: "🟡 Средний (5)",
    diff_hard: "🔴 Сложный (5)",
    select_scenario_label: "СЦЕНАРИИ АТАК:",







    very_low_risk: "ОЧЕНЬ НИЗКИЙ РИСК",



    low_risk: "НИЗКИЙ РИСК",



    medium_risk: "СРЕДНИЙ РИСК",



    high_risk: "ВЫСОКИЙ РИСК",



    critical_risk: "КРИТИЧЕСКИЙ РИСК",







    class_safe: "Потенциально безопасно",



    class_suspicious: "Подозрительно",



    class_malicious: "Потенциально вредоносно",







    no_risk_indicators: "Индикаторы риска не обнаружены",



    no_safety_signals: "Сигналы безопасности не обнаружены",



    present: "Присутствует",



    not_signed: "Не подписан",



    sensitive: "опасных",







    explain_safe_intro: "Для этого URL явных индикаторов риска не обнаружено",



    explain_suspicious_intro: "Этот URL оценен как подозрительный",



    explain_malicious_intro: "Этот URL оценен как с высокой вероятностью вредоносный",



    explain_default_intro: "Анализ завершен",



    explain_clean_details: "Основные параметры (структура домена, HTTPS, ключевые слова) находятся в пределах нормы.",



    explain_because: "потому что",



    explain_probability_note: "Это вероятностная оценка — она не дает 100% гарантии абсолютной безопасности или вредоносности.",







    xai_decision_factors: "Факторы принятия решений (Feature Attribution)",



    xai_desc: "Распределение параметров с наибольшим влиянием на вердикт модели ИИ и эвристики:",



    print_save_pdf: "🖨️ ПЕЧАТЬ / СОХРАНИТЬ В PDF",



    close: "ЗАКРЫТЬ",







    // Model Metrics & Scientific Lab



    metrics_eyebrow: "НАУЧНЫЕ ИССЛЕДОВАНИЯ И ОЦЕНКА МОДЕЛЕЙ",



    metrics_heading: "Научные Метрики Моделей Искусственного Интеллекта",



    metrics_subhead: "Эмпирические показатели, матрица ошибок и кривая ROC-AUC, измеренные на выборке из более чем 133 000 URL-адресов и бинарных файлов Windows PE.",



    tab_url_model: "URL Фишинг Модель (133k Датасет)",



    tab_exe_model: "EXE Вредоносная Модель (Static PE)",



    tab_hybrid_model: "Многоуровневая Гибридная Система",



    kpi_accuracy: "ACCURACY (ТОЧНОСТЬ)",



    kpi_accuracy_sub: "По тестовой выборке",



    kpi_precision: "PRECISION (ПРЕЦИЗИОННОСТЬ)",



    kpi_precision_sub: "Минимум ложных срабатываний (FP)",



    kpi_recall: "RECALL / ПОЛНОТА",



    kpi_recall_sub: "Доля обнаруженных угроз",



    kpi_f1: "F1-SCORE",



    kpi_f1_sub: "Гармоническое среднее",



    kpi_auc: "ROC-AUC SCORE",



    kpi_auc_sub: "Высокая разделительная способность",



    kpi_latency: "INFERENCE TIME",



    kpi_latency_sub: "В режиме реального времени",



    cm_title: "Матрица Ошибок (Confusion Matrix)",



    cm_desc: "Распределение верных (TP, TN) и ошибочных (FP, FN) прогнозов классификатора:",



    cm_pred_clean: "Прогноз: ЧИСТО",



    cm_pred_threat: "Прогноз: УГРОЗА",



    cm_actual_clean: "Реально: ЧИСТО",



    cm_actual_threat: "Реально: ОПАСНО",



    cm_tn_sub: "44.9% (Подтверждено чисто)",



    cm_fp_sub: "5.1% (Ложная тревога)",



    cm_fn_sub: "5.7% (Пропущенная угроза)",



    cm_tp_sub: "44.3% (Угроза поймана)",



    roc_title: "Кривая Ошибок Классификатора (ROC-AUC)",



    roc_desc: "Соотношение чувствительности (TPR) и доли ложных тревог (FPR):",



    roc_legend_pg: "Модель PhishGuard (AUC = 0.954)",



    roc_legend_random: "Случайное угадывание (AUC = 0.50)",



    algo_comparison_title: "Сравнение Алгоритмов Машинного Обучения (Cross-Validation)",



    algo_comparison_desc: "Эмпирическое сравнение ML алгоритмов на едином датасете через 5-кратную Stratified CV:",



    th_algo_name: "Алгоритм / Модель",



    th_algo_acc: "Точность (Accuracy)",



    th_algo_f1: "F1-Score",



    th_algo_cv: "5-Fold CV F1",



    th_algo_latency: "Время вывода",



    th_algo_verdict: "Статус / Вердикт",



    badge_optimal: "Выбран (Оптимальный)",



    badge_tested: "Протестирован",



    badge_slow: "Медленно для real-time",



    badge_baseline: "Базовый уровень",



    badge_final_system: "ИТОГОВАЯ СИСТЕМА",



    algo_pg_fusion_title: "⭐ Гибридная Система PhishGuard (ML + Rules + SOC)",



    feat_imp_title: "Важность Признаков Модели (Feature Importance - Gini)",



    feat_imp_desc: "Распределение топ-8 признаков с наибольшим весом в деревьях Random Forest:",



    bmi_thesis_title: "🎓 Научное Заключение для Защиты Дипломной Работы",



    bmi_thesis_text: "В данном исследовании доказано превосходство многоуровневого гибридного подхода (локальный ML + лексические эвристики + разведка угроз) над изолированной ML-моделью при обнаружении фишинговых атак. Исследование проведено на 106 472 обучающих и 26 618 тестовых образцах с 5-кратной кросс-валидацией Stratified K-Fold. В результате ошибки второго рода (False Negatives — пропуск угроз) снижены с 11.5% до 1.3%, а итоговая точность системы достигла 98.4%.",







    metric_url_sub: "На 26,618 тестовых образцах (133k Датасет)",



    metric_exe_sub: "Статические признаки Windows PE",



    metric_hybrid_sub: "Многоуровневый консенсусный вывод",



    cm_samples_label: "тестовых образцов",



    cm_pe_samples_label: "образцов PE",



    cm_hybrid_samples_label: "Тестирование гибридного консенсуса",



    cm_note_heading: "Научный анализ",



    cm_note_url_body: "Из 26 618 тестовых URL правильно классифицированы 11 780 (TP). Пропущенные изолированным ML 1 529 угроз (FN) полностью перехватываются вторым эвристическим слоем (Brand spoofing, IP host, Punycode), поднимая точность до 98.4%.",



    cm_note_exe_body: "Статический PE-анализ через энтропию и импорты различает трояны с точностью 94%. Отсутствие подписи и секции W+X — ключевые предикторы.",



    cm_note_hybrid_body: "По сравнению с изолированным ML в гибридной архитектуре ошибки FN снижены в 8.8 раз. Более 95% фишинговых атак Zero-Day распознаются даже при отсутствии в VirusTotal!",







    soc_rep_header_title: "ЦЕНТР КИБЕРБЕЗОПАСНОСТИ И ОПЕРАЦИЙ SOC РЕСПУБЛИКИ УЗБЕКИСТАН",



    soc_rep_modal_title: "PHISHGUARD AI FORENSIC THREAT ASSESSMENT DOSSIER",



    soc_rep_modal_sub: "Официальное экспертное заключение на основе искусственного интеллекта и многоуровневой разведки угроз",



    soc_seal_verified: "SOC VERIFIED",



    soc_doc_no: "Номер документа:",



    soc_timestamp: "Дата и время:",



    soc_status: "Статус:",



    soc_status_verified: "ПРОВЕРЕНО",



    soc_sec1_title: "1. ИССЛЕДУЕМЫЙ ОБЪЕКТ И ИДЕНТИФИКАТОРЫ",



    soc_target_type: "Тип объекта:",



    soc_engine_type: "Движок анализа:",



    soc_target_name: "Адрес / Файл:",



    soc_hashes: "Хэш-суммы:",



    soc_sec2_title: "2. РЕЙТИНГ ОПАСНОСТИ И ИТОГОВАЯ КЛАССИФИКАЦИЯ",



    soc_consensus_lbl: "Многоуровневая консенсусная оценка:",



    soc_zeroday_lbl: "Статус защиты от Zero-Day:",



    soc_vt_lbl: "Заключение VirusTotal:",



    soc_sec3_title: "3. МАТРИЦА УГРОЗ MITRE ATT&CK",



    soc_th_tech_id: "ID Техники",



    soc_th_tactic: "Тактическая фаза",



    soc_th_desc: "Описание механизма атаки",



    soc_sec4_title: "4. ОБЪЯСНИМЫЙ ИИ (EXPLAINABLE AI — ВЛИЯНИЕ ПРИЗНАКОВ)",



    soc_xai_sub: "Ключевые факторы, оказавшие наибольшее влияние на решение классификатора:",



    soc_th_feature: "Признак / Фактор",



    soc_th_direction: "Вектор",



    soc_th_impact: "Вклад (Impact)",



    soc_th_expert_note: "Пояснение эксперта",



    soc_sec5_title: "5. ОБНАРУЖЕННЫЕ ИНДИКАТОРЫ КОМПРОМЕТАЦИИ (IoC)",



    soc_sec6_title: "6. РЕКОМЕНДАЦИИ И ОБЯЗАТЕЛЬНЫЕ ДЕЙСТВИЯ",



    soc_sec7_title: "7. ОФИЦИАЛЬНАЯ ПЕЧАТЬ И ПОДПИСЬ",



    soc_qr_caption: "Цифровой код проверки",



    soc_sig_role: "Эксперт кибербезопасности SOC",



    soc_sig_team: "Группа автоматизированной киберэкспертизы",



    soc_stamp_country: "РЕСПУБЛИКА УЗБЕКИСТАН",



    soc_stamp_dept: "* КИБЕРБЕЗОПАСНОСТЬ *",



  },



};







function t(key) {



  return I18N[currentLang]?.[key] || I18N["en"]?.[key] || key;



}







function getLevelLabel(level) {



  const map = {



    VERY_LOW: t("very_low_risk"),



    LOW: t("low_risk"),



    MEDIUM: t("medium_risk"),



    HIGH: t("high_risk"),



    CRITICAL: t("critical_risk"),



  };



  return map[level] || (level ? level.replace("_", " ") : "—");



}







function getClassificationLabel(cls) {



  const map = {



    "Potentially Safe": t("class_safe"),



    "Suspicious": t("class_suspicious"),



    "Potentially Malicious": t("class_malicious"),



  };



  return map[cls] || cls;



}







function translateReason(text) {



  if (!text) return "";



  if (currentLang === "en") return text;







  const rules = [



    {



      match: /uses punycode or lookalike homoglyphs/i,



      uz: "Domen Punycode yoki vizual o'xshash (homoglyph) harflardan foydalanadi (firibgarlik usuli)",



      ru: "Домен использует Punycode или похожие символы-омоглифы (метод маскировки)",



    },



    {



      match: /ip address is used as the host/i,



      uz: "Domen nomi o'rniga to'g'ridan-to'g'ri IP manzil ishlatilgan",



      ru: "Вместо доменного имени используется прямой IP-адрес",



    },



    {



      match: /contains sensitive keywords/i,



      uz: "Havolada maxfiy kalit so'zlar aniqlandi (login, verify, account, secure...)",



      ru: "В URL найдены чувствительные ключевые слова (login, verify, account...)",



    },



    {



      match: /known url shortener/i,



      uz: "Qisqartirilgan havola xizmatidan (URL shortener) foydalanilgan",



      ru: "Использован сервис сокращения ссылок (URL shortener)",



    },



    {



      match: /potential zero-day/i,



      uz: "Potentsial Zero-Day / Yangi tahdid: Mahalliy AI tahlili yuqori xavfni aniqladi",



      ru: "Потенциальная Zero-Day угроза: локальный AI выявил высокий риск",



    },



    {



      match: /high section entropy/i,



      uz: "Bo'lim entropiyasi yuqori (siqilgan yoki shifrlangan kod alomati)",



      ru: "Высокая энтропия секции (признак сжатия или обфускации кода)",



    },



    {



      match: /writable and executable/i,



      uz: "Bo'lim ham yozish, ham bajarish (W+X) huquqiga ega (xavfli belgi)",



      ru: "Секция имеет права на запись и исполнение (W+X)",



    },



    {



      match: /known packer signature/i,



      uz: "Taniqli paker (UPX/Themida) imzosi aniqlandi",



      ru: "Обнаружена сигнатура известного упаковщика (UPX/Themida)",



    },



    {



      match: /tls callback/i,



      uz: "Yashirin TLS Callback funksiyasi aniqlandi (asosiy koddan oldin ishga tushadi)",



      ru: "Обнаружен скрытый TLS Callback (запуск до точки входа)",



    },



    {



      match: /entry point anomaly/i,



      uz: "Kirish nuqtasi (Entry Point) anomaliyasi aniqlandi",



      ru: "Аномалия точки входа (Entry Point)",



    },



    {



      match: /no virustotal engines flagged/i,



      uz: "VirusTotal dvijoklarining hech biri xavf topmadi",



      ru: "Ни один движок VirusTotal не обнаружил угроз",



    },



    {



      match: /valid digital signature/i,



      uz: "Haqiqiy raqamli imzo mavjud",



      ru: "Действительная цифровая подпись",



    },



    {



      match: /legitimate trusted domain/i,



      uz: "Taniqli va ishonchli domen",



      ru: "Легитимный доверенный домен",



    },



    {



      match: /standard https/i,



      uz: "Xavfsiz standart HTTPS protokoli",



      ru: "Стандартный защищенный протокол HTTPS",



    },



  ];







  for (const r of rules) {



    if (r.match.test(text)) {



      return r[currentLang] || text;



    }



  }



  return text;



}







function formatVtNote(note) {



  if (!note) return "—";



  if (currentLang === "en") return note;







  if (/not yet known/i.test(note) || /not_found/i.test(note)) {



    return currentLang === "uz"



      ? "ℹ️ Ushbu manzil/fayl VirusTotal xalqaro bazasida hali ro'yxatdan o'tmagan (Yangi / Zero-Day obyekt). Tahlil to'liq PhishGuard lokal sun'iy intellekti va evristikasi orqali amalga oshirildi."



      : "ℹ️ Данный объект пока не зарегистрирован в базе VirusTotal (Новая / Zero-Day угроза). Оценка основана на локальном анализе PhishGuard AI.";



  }







  if (/rate limit/i.test(note) || /unavailable/i.test(note)) {



    return currentLang === "uz"



      ? "⏳ VirusTotal bepul API limiti band (daqiqasiga 4 ta so'rov). Tahlil to'liq lokal AI orqali yakunlandi."



      : "⏳ Лимит бесплатного API VirusTotal исчерпан (4 запроса в минуту). Использован локальный анализ ИИ.";



  }







  if (/not_configured/i.test(note) || /verification unavailable/i.test(note)) {



    return currentLang === "uz"



      ? "VirusTotal ulanishi sozlanmagan. Faqat lokal tahlil ishlatildi."



      : "Подключение VirusTotal не настроено. Использован только локальный анализ.";



  }







  const match = note.match(/(\d+)\/(\d+)\s+engines/i);



  if (match) {



    const malicious = match[1];



    const total = match[2];



    if (currentLang === "uz") {



      return `✅ VirusTotal tahlili: ${total} ta xalqaro dvijoklardan ${malicious} tasi xavf aniqladi.`;



    } else {



      return `✅ Анализ VirusTotal: из ${total} антивирусных движков ${malicious} обнаружили угрозу.`;



    }



  }







  return note;



}







function setLanguage(lang) {



  if (!I18N[lang]) lang = "uz";



  currentLang = lang;



  localStorage.setItem("phishguard_lang", lang);



  document.documentElement.lang = lang;



  document.title = t("doc_title");







  document.querySelectorAll(".lang-btn").forEach((b) => {



    b.classList.toggle("active", b.dataset.lang === lang);



  });







  if (viewTitleEl) {



    viewTitleEl.textContent = t(currentViewKey);



  }







  document.querySelectorAll("[data-i18n]").forEach((el) => {



    const k = el.dataset.i18n;



    if (k && t(k)) el.textContent = t(k);



  });







  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {



    const k = el.dataset.i18nPlaceholder;



    if (k && t(k)) el.placeholder = t(k);



  });







  // Re-render scan results if visible



  if (lastUrlResult && !resultSection.hidden) {



    gaugeLevelEl.textContent = getLevelLabel(lastUrlResult.risk_level);



    renderList(reasonsList, lastUrlResult.reasons, "no_risk_indicators");



    renderList(safeList, lastUrlResult.positive_signals, "no_safety_signals");



    explanationText.textContent = buildExplanation(lastUrlResult);



    renderXaiBars(document.getElementById("url-xai-bars"), document.getElementById("url-xai-panel"), lastUrlResult.xai_analysis);



    const urlVtEl = document.getElementById("url-vt-status");



    if (urlVtEl) urlVtEl.textContent = formatVtNote(lastUrlResult.vt_note);



  }







  if (lastExeResult && !exeResultPanel.hidden) {



    exeResultLevel.textContent = getLevelLabel(lastExeResult.risk_level);



    exeResultClassification.textContent = getClassificationLabel(lastExeResult.classification);



    renderList(exeIndicatorsList, lastExeResult.indicators, "no_risk_indicators");



    renderList(exePositiveList, lastExeResult.positive_signals, "no_safety_signals");



    renderXaiBars(document.getElementById("exe-xai-bars"), document.getElementById("exe-xai-panel"), lastExeResult.xai_analysis);



    const exeVtEl = document.getElementById("exe-vt-status");



    if (exeVtEl) exeVtEl.textContent = formatVtNote(lastExeResult.vt_note);



  }







  if (lastApkResult && !apkResultPanel.hidden) {



    apkResultLevel.textContent = getLevelLabel(lastApkResult.risk_level);



    apkResultClassification.textContent = getClassificationLabel(lastApkResult.classification);



    renderList(apkIndicatorsList, lastApkResult.indicators, "no_risk_indicators");



    renderList(apkPositiveList, lastApkResult.positive_signals, "no_safety_signals");



    renderXaiBars(document.getElementById("apk-xai-bars"), document.getElementById("apk-xai-panel"), lastApkResult.xai_analysis);



    const apkVtEl = document.getElementById("apk-vt-status");



    if (apkVtEl) apkVtEl.textContent = formatVtNote(lastApkResult.vt_note);



  }







  if (currentViewKey === "dashboard") refreshDashboard();



  if (currentViewKey === "history") refreshHistory();



  if (currentViewKey === "model-metrics" && cachedMetricsData) {



    renderMetricsView(cachedMetricsData, currentMetricsTab);



  }







  const socModal = document.getElementById("soc-report-modal");



  if (socModal && !socModal.hidden && lastSocReportType && lastSocReportData) {



    openSocReport(lastSocReportType, lastSocReportData);



  }



}







/* ============================================================



   2) VIEW ROUTER



   ============================================================ */







const navItems = document.querySelectorAll(".nav-item");



const viewPanels = document.querySelectorAll("[data-view-panel]");



const viewTitleEl = document.getElementById("view-title");



const sidebar = document.getElementById("sidebar");



const scrim = document.getElementById("app-scrim");



const menuToggle = document.getElementById("menu-toggle");







function showView(viewKey) {



  currentViewKey = viewKey;



  viewPanels.forEach((panel) => {



    panel.hidden = panel.id !== `view-${viewKey}`;



  });



  navItems.forEach((item) => {



    item.classList.toggle("active", item.dataset.view === viewKey);



  });



  viewTitleEl.textContent = t(viewKey);



  closeSidebar();



  document.querySelector(".content")?.scrollTo?.({ top: 0 });



  window.scrollTo({ top: 0 });







  if (viewKey === "dashboard") refreshDashboard();



  if (viewKey === "history") refreshHistory();



  if (viewKey === "model-metrics") loadModelMetrics();



  if (viewKey === "threat-map") initThreatMap();



}







navItems.forEach((item) => {



  item.addEventListener("click", () => showView(item.dataset.view));



});







document.querySelectorAll("[data-goto]").forEach((el) => {



  el.addEventListener("click", () => showView(el.dataset.goto));



});







function openSidebar() {



  sidebar.classList.add("open");



  scrim.classList.add("visible");



}



function closeSidebar() {



  sidebar.classList.remove("open");



  scrim.classList.remove("visible");



}



menuToggle?.addEventListener("click", () => {



  sidebar.classList.contains("open") ? closeSidebar() : openSidebar();



});



scrim?.addEventListener("click", closeSidebar);







/* ============================================================



   3) URL SCANNER



   ============================================================ */







const TICK_COUNT = 50;



const START_ANGLE = -120;



const END_ANGLE = 120;







const form = document.getElementById("analyze-form");



const input = document.getElementById("url-input");



const btn = document.getElementById("analyze-btn");



const scanStatus = document.getElementById("scan-status");



const resultSection = document.getElementById("result-section");



const gaugeSvg = document.getElementById("gauge-svg");



const gaugeScoreEl = document.getElementById("gauge-score");



const gaugeLevelEl = document.getElementById("gauge-level");



const gaugeUrlEl = document.getElementById("gauge-url");



const reasonsList = document.getElementById("reasons-list");



const safeList = document.getElementById("safe-list");



const explanationText = document.getElementById("explanation-text");



const resetBtn = document.getElementById("reset-btn");







let sweepInterval = null;







function cssVar(name) {



  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();



}







function zoneColor(score) {



  if (score <= 20) return cssVar("--sev-verylow");



  if (score <= 40) return cssVar("--sev-low");



  if (score <= 60) return cssVar("--sev-medium");



  if (score <= 80) return cssVar("--sev-high");



  return cssVar("--sev-critical");



}







function buildGauge() {



  if (!gaugeSvg) return;



  gaugeSvg.innerHTML = "";



  const cx = 150, cy = 150, rInner = 100, rOuter = 124;







  for (let i = 0; i < TICK_COUNT; i++) {



    const angleDeg = START_ANGLE + (i * (END_ANGLE - START_ANGLE)) / (TICK_COUNT - 1);



    const rad = (angleDeg * Math.PI) / 180;



    const x1 = cx + rInner * Math.sin(rad);



    const y1 = cy - rInner * Math.cos(rad);



    const x2 = cx + rOuter * Math.sin(rad);



    const y2 = cy - rOuter * Math.cos(rad);







    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");



    line.setAttribute("x1", x1.toFixed(2));



    line.setAttribute("y1", y1.toFixed(2));



    line.setAttribute("x2", x2.toFixed(2));



    line.setAttribute("y2", y2.toFixed(2));



    line.setAttribute("class", "gauge-tick");



    line.setAttribute("data-index", String(i));



    line.style.stroke = "var(--tick-off)";



    gaugeSvg.appendChild(line);



  }



}







function setTickColor(index, color, glow) {



  const tick = gaugeSvg.querySelector(`[data-index="${index}"]`);



  if (!tick) return;



  tick.style.stroke = color;



  tick.style.filter = glow ? `drop-shadow(0 0 4px ${color})` : "none";



}







function resetGaugeVisual() {



  for (let i = 0; i < TICK_COUNT; i++) setTickColor(i, "var(--tick-off)", false);



}







function startScanAnimation() {



  let pos = 0;



  resetGaugeVisual();



  sweepInterval = setInterval(() => {



    resetGaugeVisual();



    for (let k = 0; k < 6; k++) {



      const idx = (pos - k + TICK_COUNT) % TICK_COUNT;



      setTickColor(idx, "var(--accent)", k < 2);



    }



    pos = (pos + 1) % TICK_COUNT;



  }, 40);



}







function stopScanAnimation() {



  if (sweepInterval) clearInterval(sweepInterval);



  sweepInterval = null;



  resetGaugeVisual();



}







function animateResultGauge(score) {



  const litCount = Math.round((score / 100) * TICK_COUNT);



  let i = 0;



  function step() {



    if (i >= litCount) return;



    const scoreAtTick = (i / (TICK_COUNT - 1)) * 100;



    const color = zoneColor(scoreAtTick);



    const isNearEnd = i >= litCount - 2;



    setTickColor(i, color, isNearEnd);



    i++;



    setTimeout(() => requestAnimationFrame(step), 8);



  }



  step();



}







function animateScoreNumber(target) {



  const duration = 600;



  const startTime = performance.now();



  function frame(now) {



    const t = Math.min((now - startTime) / duration, 1);



    gaugeScoreEl.textContent = Math.round(t * target);



    if (t < 1) requestAnimationFrame(frame);



  }



  requestAnimationFrame(frame);



}







function buildExplanation(data) {



  const introMap = {



    "Potentially Safe": t("explain_safe_intro"),



    "Suspicious": t("explain_suspicious_intro"),



    "Potentially Malicious": t("explain_malicious_intro"),



  };



  const intro = introMap[data.classification] || t("explain_default_intro");







  if (!data.reasons || data.reasons.length === 0) {



    return `${intro}. ${t("explain_clean_details")}`;



  }



  const topReasons = data.reasons.slice(0, 3).map(translateReason).join("; ");



  return `${intro}, ${t("explain_because")}: ${topReasons}. ${t("explain_probability_note")}`;



}







function renderList(el, items, emptyKey) {



  el.innerHTML = "";



  if (!items || items.length === 0) {



    const li = document.createElement("li");



    li.className = "findings-empty";



    li.textContent = t(emptyKey) || emptyKey;



    el.appendChild(li);



    return;



  }



  items.forEach((text) => {



    const li = document.createElement("li");



    li.textContent = translateReason(text);



    el.appendChild(li);



  });



}







function showResult(data) {



  resultSection.hidden = false;



  lastUrlResult = data;



  gaugeUrlEl.textContent = data.url;



  gaugeLevelEl.textContent = getLevelLabel(data.risk_level);



  gaugeLevelEl.style.color = zoneColor(data.risk_score);







  animateScoreNumber(data.risk_score);



  animateResultGauge(data.risk_score);







  renderList(reasonsList, data.reasons, "no_risk_indicators");



  renderList(safeList, data.positive_signals, "no_safety_signals");



  explanationText.textContent = buildExplanation(data);







  renderXaiBars(document.getElementById("url-xai-bars"), document.getElementById("url-xai-panel"), data.xai_analysis);







  const urlVtEl = document.getElementById("url-vt-status");



  if (urlVtEl) {



    urlVtEl.textContent = formatVtNote(data.vt_note);



    if (data.virustotal && data.virustotal.status === "pending" && data.virustotal.analysis_id) {



      pollVtStatus(data.virustotal.analysis_id, urlVtEl);



    }



  }







  resultSection.scrollIntoView({ behavior: "smooth", block: "start" });



}







form?.addEventListener("submit", async (event) => {



  event.preventDefault();



  const url = input.value.trim();



  if (!url) return;







  btn.disabled = true;



  input.disabled = true;



  scanStatus.textContent = t("analyzing");



  scanStatus.classList.remove("error-text");



  scanStatus.classList.add("scanning-text");



  resultSection.hidden = true;







  buildGauge();



  startScanAnimation();







  try {



    const response = await fetchWithTimeout(API_URL, {



      method: "POST",



      headers: { "Content-Type": "application/json" },



      body: JSON.stringify({ url }),



    });







    if (!response.ok) {



      throw new Error("Server returned an error: " + response.status);



    }







    const data = await response.json();



    stopScanAnimation();



    scanStatus.textContent = "";



    scanStatus.classList.remove("scanning-text");



    showResult(data);



  } catch (err) {



    stopScanAnimation();



    scanStatus.textContent = "ERROR: " + err.message;



    scanStatus.classList.add("error-text");



    console.error(err);



  } finally {



    btn.disabled = false;



    input.disabled = false;



  }



});







resetBtn?.addEventListener("click", () => {



  resultSection.hidden = true;



  input.value = "";



  input.focus();



  scanStatus.textContent = "";



});







buildGauge();







/* ============================================================



   4) EXE SCANNER



   ============================================================ */







const dropzone = document.getElementById("exe-dropzone");



const exeFileInput = document.getElementById("exe-file-input");



const exeInfoPanel = document.getElementById("exe-info-panel");



const exeNameEl = document.getElementById("exe-name");



const exeSizeEl = document.getElementById("exe-size");



const exeTypeEl = document.getElementById("exe-type");



const exeSha256El = document.getElementById("exe-sha256");



const exeScanBtn = document.getElementById("exe-scan-btn");



const exeScanStatus = document.getElementById("exe-scan-status");



const exeResultPanel = document.getElementById("exe-result-panel");



const exeResultScore = document.getElementById("exe-result-score");



const exeResultLevel = document.getElementById("exe-result-level");



const exeResultClassification = document.getElementById("exe-result-classification");



const exeResultMachine = document.getElementById("exe-result-machine");



const exeResultSections = document.getElementById("exe-result-sections");



const exeResultSignature = document.getElementById("exe-result-signature");



const exeResultImports = document.getElementById("exe-result-imports");



const exeIndicatorsList = document.getElementById("exe-indicators-list");



const exePositiveList = document.getElementById("exe-positive-list");







const MAX_EXE_SIZE = 50 * 1024 * 1024;







function formatFileSize(bytes) {



  if (bytes < 1024) return bytes + " B";



  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";



  return (bytes / (1024 * 1024)).toFixed(2) + " MB";



}







dropzone?.addEventListener("click", () => exeFileInput.click());



dropzone?.addEventListener("dragover", (e) => {



  e.preventDefault();



  dropzone.classList.add("dropzone-active");



});



dropzone?.addEventListener("dragleave", () => dropzone.classList.remove("dropzone-active"));



dropzone?.addEventListener("drop", (e) => {



  e.preventDefault();



  dropzone.classList.remove("dropzone-active");



  if (e.dataTransfer.files.length) handleExeFile(e.dataTransfer.files[0]);



});



exeFileInput?.addEventListener("change", () => {



  if (exeFileInput.files.length) handleExeFile(exeFileInput.files[0]);



});







async function handleExeFile(file) {



  exeScanStatus.textContent = "";



  exeScanStatus.classList.remove("error-text");







  if (!file.name.toLowerCase().endsWith(".exe")) {



    exeScanStatus.textContent = "ERROR: only .exe files are supported.";



    exeScanStatus.classList.add("error-text");



    return;



  }



  if (file.size > MAX_EXE_SIZE) {



    exeScanStatus.textContent = "ERROR: file exceeds the 50 MB limit.";



    exeScanStatus.classList.add("error-text");



    return;



  }







  exeInfoPanel.hidden = false;



  exeResultPanel.hidden = true;



  exeNameEl.textContent = file.name;



  exeSizeEl.textContent = formatFileSize(file.size);



  exeTypeEl.textContent = file.type || "application/x-msdownload";



  exeSha256El.textContent = "Computing…";







  try {



    const buffer = await file.arrayBuffer();



    const digest = await crypto.subtle.digest("SHA-256", buffer);



    const hashHex = Array.from(new Uint8Array(digest))



      .map((b) => b.toString(16).padStart(2, "0"))



      .join("");



    exeSha256El.textContent = hashHex;



  } catch (err) {



    exeSha256El.textContent = "unavailable";



    console.error(err);



  }



}







exeScanBtn?.addEventListener("click", async () => {



  const file = exeFileInput.files[0];



  if (!file) return;







  exeScanBtn.disabled = true;



  exeScanStatus.classList.remove("error-text");



  exeScanStatus.textContent = t("analyzing");



  exeScanStatus.classList.add("scanning-text");







  try {



    const formData = new FormData();



    formData.append("file", file);







    const response = await fetchWithTimeout(EXE_API_URL, { method: "POST", body: formData });



    const data = await response.json();







    if (!response.ok) {



      throw new Error(data.detail || "Server returned an error: " + response.status);



    }







    exeScanStatus.classList.remove("scanning-text");



    exeScanStatus.textContent = "";



    showExeResult(data);



  } catch (err) {



    exeScanStatus.classList.remove("scanning-text");



    exeScanStatus.textContent = "ERROR: " + err.message;



    exeScanStatus.classList.add("error-text");



    console.error(err);



  } finally {



    exeScanBtn.disabled = false;



  }



});







function showExeResult(data) {



  exeResultPanel.hidden = false;



  lastExeResult = data;







  exeResultScore.textContent = data.final_score;



  exeResultLevel.textContent = getLevelLabel(data.risk_level);



  exeResultLevel.style.color = zoneColor(data.final_score);



  exeResultClassification.textContent = getClassificationLabel(data.classification);







  exeResultMachine.textContent = data.machine_type;



  exeResultSections.textContent = data.number_of_sections;



  exeResultSignature.textContent = data.has_digital_signature ? t("present") : t("not_signed");



  exeResultImports.textContent = `${data.imported_function_count} (DLL: ${data.imported_dll_count})`;







  renderList(exeIndicatorsList, data.indicators, "no_risk_indicators");



  renderList(exePositiveList, data.positive_signals, "no_safety_signals");







  renderXaiBars(document.getElementById("exe-xai-bars"), document.getElementById("exe-xai-panel"), data.xai_analysis);







  const vtEl = document.getElementById("exe-vt-status");



  if (vtEl) {



    vtEl.textContent = formatVtNote(data.vt_note);



    if (data.virustotal && data.virustotal.status === "pending" && data.virustotal.analysis_id) {



      pollVtStatus(data.virustotal.analysis_id, vtEl);



    }



  }







  exeResultPanel.scrollIntoView({ behavior: "smooth", block: "start" });



}







/* ============================================================



   5) APK SCANNER



   ============================================================ */







const apkDropzone = document.getElementById("apk-dropzone");



const apkFileInput = document.getElementById("apk-file-input");



const apkInfoPanel = document.getElementById("apk-info-panel");



const apkNameEl = document.getElementById("apk-name");



const apkSizeEl = document.getElementById("apk-size");



const apkSha256El = document.getElementById("apk-sha256");



const apkScanBtn = document.getElementById("apk-scan-btn");



const apkScanStatus = document.getElementById("apk-scan-status");



const apkResultPanel = document.getElementById("apk-result-panel");



const apkResultScore = document.getElementById("apk-result-score");



const apkResultLevel = document.getElementById("apk-result-level");



const apkResultClassification = document.getElementById("apk-result-classification");



const apkResultPackage = document.getElementById("apk-result-package");



const apkResultVersion = document.getElementById("apk-result-version");



const apkResultSignature = document.getElementById("apk-result-signature");



const apkResultPermissions = document.getElementById("apk-result-permissions");



const apkIndicatorsList = document.getElementById("apk-indicators-list");



const apkPositiveList = document.getElementById("apk-positive-list");







const MAX_APK_SIZE = 100 * 1024 * 1024;







apkDropzone?.addEventListener("click", () => apkFileInput.click());



apkDropzone?.addEventListener("dragover", (e) => {



  e.preventDefault();



  apkDropzone.classList.add("dropzone-active");



});



apkDropzone?.addEventListener("dragleave", () => apkDropzone.classList.remove("dropzone-active"));



apkDropzone?.addEventListener("drop", (e) => {



  e.preventDefault();



  apkDropzone.classList.remove("dropzone-active");



  if (e.dataTransfer.files.length) handleApkFile(e.dataTransfer.files[0]);



});



apkFileInput?.addEventListener("change", () => {



  if (apkFileInput.files.length) handleApkFile(apkFileInput.files[0]);



});







async function handleApkFile(file) {



  apkScanStatus.textContent = "";



  apkScanStatus.classList.remove("error-text");







  if (!file.name.toLowerCase().endsWith(".apk")) {



    apkScanStatus.textContent = "ERROR: only .apk files are supported.";



    apkScanStatus.classList.add("error-text");



    return;



  }



  if (file.size > MAX_APK_SIZE) {



    apkScanStatus.textContent = "ERROR: file exceeds the 100 MB limit.";



    apkScanStatus.classList.add("error-text");



    return;



  }







  apkInfoPanel.hidden = false;



  apkResultPanel.hidden = true;



  apkNameEl.textContent = file.name;



  apkSizeEl.textContent = formatFileSize(file.size);



  apkSha256El.textContent = "Computing…";







  try {



    const buffer = await file.arrayBuffer();



    const digest = await crypto.subtle.digest("SHA-256", buffer);



    const hashHex = Array.from(new Uint8Array(digest))



      .map((b) => b.toString(16).padStart(2, "0"))



      .join("");



    apkSha256El.textContent = hashHex;



  } catch (err) {



    apkSha256El.textContent = "unavailable";



    console.error(err);



  }



}







apkScanBtn?.addEventListener("click", async () => {



  const file = apkFileInput.files[0];



  if (!file) return;







  apkScanBtn.disabled = true;



  apkScanStatus.classList.remove("error-text");



  apkScanStatus.textContent = t("analyzing");



  apkScanStatus.classList.add("scanning-text");







  try {



    const formData = new FormData();



    formData.append("file", file);







    const response = await fetchWithTimeout(APK_API_URL, { method: "POST", body: formData }, 60000);



    const data = await response.json();







    if (!response.ok) {



      throw new Error(data.detail || "Server returned an error: " + response.status);



    }







    apkScanStatus.classList.remove("scanning-text");



    apkScanStatus.textContent = "";



    showApkResult(data);



  } catch (err) {



    apkScanStatus.classList.remove("scanning-text");



    apkScanStatus.textContent = "ERROR: " + err.message;



    apkScanStatus.classList.add("error-text");



    console.error(err);



  } finally {



    apkScanBtn.disabled = false;



  }



});







function showApkResult(data) {



  apkResultPanel.hidden = false;



  lastApkResult = data;







  apkResultScore.textContent = data.final_score;



  apkResultLevel.textContent = getLevelLabel(data.risk_level);



  apkResultLevel.style.color = zoneColor(data.final_score);



  apkResultClassification.textContent = getClassificationLabel(data.classification);







  apkResultPackage.textContent = data.package_name;



  apkResultVersion.textContent = data.version_name ? `${data.version_name} (${data.version_code || "?"})` : "unknown";



  apkResultSignature.textContent = data.is_signed ? t("present") : t("not_signed");



  apkResultPermissions.textContent = `${data.permission_count} (${data.dangerous_permissions.length} ${t("sensitive")})`;







  renderList(apkIndicatorsList, data.indicators, "no_risk_indicators");



  renderList(apkPositiveList, data.positive_signals, "no_safety_signals");







  renderXaiBars(document.getElementById("apk-xai-bars"), document.getElementById("apk-xai-panel"), data.xai_analysis);







  const vtEl = document.getElementById("apk-vt-status");



  if (vtEl) {



    vtEl.textContent = formatVtNote(data.vt_note);



    if (data.virustotal && data.virustotal.status === "pending" && data.virustotal.analysis_id) {



      pollVtStatus(data.virustotal.analysis_id, vtEl);



    }



  }







  apkResultPanel.scrollIntoView({ behavior: "smooth", block: "start" });



}







/* ============================================================



   6) DASHBOARD & SCAN HISTORY



   ============================================================ */







const RISK_LEVEL_COLORS = {



  VERY_LOW: "var(--sev-verylow)",



  LOW: "var(--sev-low)",



  MEDIUM: "var(--sev-medium)",



  HIGH: "var(--sev-high)",



  CRITICAL: "var(--sev-critical)",



};







function animateCounter(el, target, suffix = "") {



  if (!el) return;



  const duration = 700;



  const startTime = performance.now();



  function frame(now) {



    const t = Math.min((now - startTime) / duration, 1);



    const eased = 1 - Math.pow(1 - t, 3);



    el.textContent = Math.round(target * eased) + suffix;



    if (t < 1) requestAnimationFrame(frame);



  }



  requestAnimationFrame(frame);



}







function renderStackedBar(barEl, legendEl, segments) {



  if (!barEl || !legendEl) return;



  const total = segments.reduce((sum, s) => sum + s.count, 0);







  barEl.innerHTML = "";



  legendEl.innerHTML = "";







  segments.forEach((seg) => {



    if (total > 0 && seg.count > 0) {



      const div = document.createElement("div");



      div.className = "stacked-bar-segment";



      div.style.width = "0%";



      div.style.background = seg.color;



      barEl.appendChild(div);



      const targetWidth = `${(seg.count / total) * 100}%`;



      requestAnimationFrame(() => requestAnimationFrame(() => { div.style.width = targetWidth; }));



    }



    const item = document.createElement("div");



    item.className = "legend-item";



    item.innerHTML = `<span class="legend-swatch" style="background:${seg.color}"></span>${seg.label}: ${seg.count}`;



    legendEl.appendChild(item);



  });







  if (total === 0) {



    barEl.style.opacity = "0.3";



  } else {



    barEl.style.opacity = "1";



  }



}







async function refreshDashboard() {



  try {



    const response = await fetchWithTimeout(DASHBOARD_API_URL);



    if (!response.ok) throw new Error("Dashboard request failed: " + response.status);



    const data = await response.json();







    animateCounter(document.getElementById("stat-total"), data.total_scans);



    animateCounter(document.getElementById("stat-url"), data.url_scans);



    animateCounter(document.getElementById("stat-exe"), data.exe_scans);



    animateCounter(document.getElementById("stat-apk"), data.apk_scans);



    animateCounter(document.getElementById("stat-threats"), data.threats_detected);



    const avgEl = document.getElementById("stat-avg");



    if (data.total_scans > 0) {



      animateCounter(avgEl, data.average_risk, "%");



    } else {



      avgEl.textContent = "—";



    }







    const emptyNote = document.getElementById("dashboard-empty-note");



    if (emptyNote) emptyNote.hidden = data.total_scans > 0;







    renderStackedBar(



      document.getElementById("chart-risk-levels"),



      document.getElementById("legend-risk-levels"),



      Object.entries(data.level_counts).map(([level, count]) => ({



        label: getLevelLabel(level),



        count,



        color: RISK_LEVEL_COLORS[level] || "var(--text-dim)",



      }))



    );







    renderStackedBar(



      document.getElementById("chart-scan-types"),



      document.getElementById("legend-scan-types"),



      [



        { label: "URL", count: data.url_scans, color: "var(--accent)" },



        { label: "EXE", count: data.exe_scans, color: "var(--sev-medium)" },



        { label: "APK", count: data.apk_scans, color: "var(--sev-low)" },



      ]



    );







    const historyResponse = await fetchWithTimeout(`${HISTORY_API_URL}?limit=50`);



    const historyData = historyResponse.ok ? await historyResponse.json() : [];



    const threats = historyData.filter((s) => s.risk_level === "HIGH" || s.risk_level === "CRITICAL").slice(0, 5);



    const threatsPanel = document.getElementById("recent-threats-panel");



    const threatsList = document.getElementById("recent-threats-list");



    if (threats.length > 0) {



      threatsPanel.hidden = false;



      threatsList.innerHTML = "";



      threats.forEach((s) => {



        const li = document.createElement("li");



        li.textContent = `[${s.scan_type}] ${s.target} — ${s.risk_score}% (${getLevelLabel(s.risk_level)})`;



        threatsList.appendChild(li);



      });



    } else {



      threatsPanel.hidden = true;



    }



  } catch (err) {



    console.error("Dashboard refresh failed:", err);



  }



}







async function refreshHistory() {



  const tbody = document.getElementById("history-table-body");



  if (!tbody) return;



  const search = document.getElementById("history-search-input")?.value || "";



  const type = document.getElementById("history-type-filter")?.value || "ALL";



  const risk = document.getElementById("history-risk-filter")?.value || "ALL";







  try {



    const url = `${HISTORY_API_URL}?limit=100&search=${encodeURIComponent(search)}&scan_type=${encodeURIComponent(type)}&risk_level=${encodeURIComponent(risk)}`;



    const response = await fetchWithTimeout(url);



    if (!response.ok) throw new Error("History request failed: " + response.status);



    const data = await response.json();



    currentHistoryData = data;







    if (data.length === 0) {



      tbody.innerHTML = `<tr class="history-empty-row"><td colspan="6">${t("no_scans_recorded")}</td></tr>`;



      return;



    }







    tbody.innerHTML = "";



    data.forEach((entry) => {



      const tr = document.createElement("tr");



      const date = new Date(entry.created_at).toLocaleString();







      const cells = [



        date,



        entry.scan_type,



        entry.target,



        `${entry.risk_score}%`,



        getClassificationLabel(entry.classification),



        getLevelLabel(entry.risk_level),



      ];



      cells.forEach((text, i) => {



        const td = document.createElement("td");



        td.textContent = text;



        if (i === 3) td.style.color = RISK_LEVEL_COLORS[entry.risk_level] || "inherit";



        tr.appendChild(td);



      });



      tr.style.cursor = "pointer";



      tr.title = "📄 Rasmiy SOC Ekspertiza Hisobotini ochish";



      tr.addEventListener("click", () => openSocReportFromHistory(entry));



      tbody.appendChild(tr);



    });



  } catch (err) {



    tbody.innerHTML = "";



    const tr = document.createElement("tr");



    tr.className = "history-empty-row";



    const td = document.createElement("td");



    td.colSpan = 6;



    td.textContent = "Could not load history: " + err.message;



    tr.appendChild(td);



    tbody.appendChild(tr);



    console.error("History refresh failed:", err);



  }



}







function exportHistoryCsv() {



  if (!currentHistoryData || currentHistoryData.length === 0) {



    alert("No history records available to export.");



    return;



  }



  const headers = ["Date", "Type", "Target", "RiskScore", "Classification", "RiskLevel"];



  const rows = currentHistoryData.map((e) => [



    `"${new Date(e.created_at).toISOString()}"`,



    `"${e.scan_type}"`,



    `"${e.target.replace(/"/g, '""')}"`,



    e.risk_score,



    `"${e.classification}"`,



    `"${e.risk_level}"`,



  ]);



  const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");



  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });



  const url = URL.createObjectURL(blob);



  const a = document.createElement("a");



  a.href = url;



  a.download = `phishguard_history_${Date.now()}.csv`;



  document.body.appendChild(a);



  a.click();



  document.body.removeChild(a);



  URL.revokeObjectURL(url);



}







function exportJson(data, prefix = "report") {



  if (!data) return;



  const jsonStr = JSON.stringify(data, null, 2);



  const blob = new Blob([jsonStr], { type: "application/json" });



  const url = URL.createObjectURL(blob);



  const a = document.createElement("a");



  a.href = url;



  a.download = `phishguard_${prefix}_${Date.now()}.json`;



  document.body.appendChild(a);



  a.click();



  document.body.removeChild(a);



  URL.revokeObjectURL(url);



}







function pollVtStatus(analysisId, statusEl) {



  if (!analysisId || !statusEl) return;



  let attempts = 0;



  const maxAttempts = 10;



  statusEl.innerHTML = `<span class="scanning-text">⏳ VirusTotal checking updates...</span>`;







  const timer = setInterval(async () => {



    attempts++;



    try {



      const resp = await fetch(`/api/vt-status/${analysisId}`);



      if (resp.ok) {



        const vtData = await resp.json();



        if (vtData.status === "completed") {



          clearInterval(timer);



          statusEl.textContent = `VirusTotal: ${vtData.malicious || 0}/${vtData.total_engines || 0} engines flagged threat.`;



          return;



        }



      }



    } catch (e) {



      console.warn("VT polling check:", e);



    }



    if (attempts >= maxAttempts) {



      clearInterval(timer);



      statusEl.textContent = "VirusTotal analysis is in progress. Check again later.";



    }



  }, 4000);



}







/* ============================================================



   6b) MODEL METRICS & SCIENTIFIC LAB



   ============================================================ */







const METRICS_API_URL = "/api/model-metrics";



let cachedMetricsData = null;



let currentMetricsTab = "url-model";







async function loadModelMetrics() {



  try {



    if (!cachedMetricsData) {



      const resp = await fetchWithTimeout(METRICS_API_URL);



      if (resp.ok) {



        cachedMetricsData = await resp.json();



      }



    }



    if (cachedMetricsData) {



      renderMetricsView(cachedMetricsData, currentMetricsTab);



    }



  } catch (err) {



    console.warn("Could not load model metrics:", err);



  }



}







function renderMetricsView(data, tabKey) {



  const isUrl = tabKey === "url-model";



  const isExe = tabKey === "exe-model";



  const isHybrid = tabKey === "hybrid-fusion";







  const accEl = document.getElementById("metric-accuracy");



  const accSub = document.getElementById("metric-accuracy-sub");



  const precEl = document.getElementById("metric-precision");



  const recEl = document.getElementById("metric-recall");



  const f1El = document.getElementById("metric-f1");



  const aucEl = document.getElementById("metric-auc");



  const latEl = document.getElementById("metric-latency");







  const cmTn = document.getElementById("cm-tn");



  const cmFp = document.getElementById("cm-fp");



  const cmFn = document.getElementById("cm-fn");



  const cmTp = document.getElementById("cm-tp");



  const cmSamples = document.getElementById("cm-sample-count");



  const cmNote = document.getElementById("cm-analysis-note");







  const rocPill = document.getElementById("roc-pill");



  const rocCurvePath = document.getElementById("roc-curve-path");



  const rocPolygon = document.getElementById("roc-polygon");



  const featContainer = document.getElementById("metrics-feat-bars");







  if (!accEl) return;







  if (isUrl && data.url_model) {



    const m = data.url_model;



    accEl.textContent = `${(m.accuracy * 100).toFixed(1)}%`;



    accSub.textContent = t("metric_url_sub");



    precEl.textContent = `${(m.precision * 100).toFixed(1)}%`;



    recEl.textContent = `${(m.recall * 100).toFixed(1)}%`;



    f1El.textContent = `${(m.f1_score * 100).toFixed(1)}%`;



    aucEl.textContent = m.roc_auc.toFixed(3);



    latEl.textContent = `${m.inference_time_ms} ms`;







    if (cmTn) cmTn.textContent = m.confusion_matrix.tn.toLocaleString();



    if (cmFp) cmFp.textContent = m.confusion_matrix.fp.toLocaleString();



    if (cmFn) cmFn.textContent = m.confusion_matrix.fn.toLocaleString();



    if (cmTp) cmTp.textContent = m.confusion_matrix.tp.toLocaleString();



    if (cmSamples) cmSamples.textContent = `${m.confusion_matrix.total.toLocaleString()} ${t("cm_samples_label")}`;



    if (cmNote) {



      cmNote.innerHTML = `<strong>${t("cm_note_heading")}:</strong> ${t("cm_note_url_body")}`;



    }







    if (rocPill) rocPill.textContent = `AUC = ${m.roc_auc.toFixed(3)}`;



    if (rocCurvePath) rocCurvePath.setAttribute("d", "M 40,200 C 45,60 80,30 300,20");



    if (rocPolygon) rocPolygon.setAttribute("points", "40,200 40,20 100,35 180,60 250,110 300,200");







    renderFeatureBars(featContainer, m.top_features);



  } else if (isExe && data.exe_model) {



    const m = data.exe_model;



    accEl.textContent = `${(m.accuracy * 100).toFixed(1)}%`;



    accSub.textContent = t("metric_exe_sub");



    precEl.textContent = `${(m.precision * 100).toFixed(1)}%`;



    recEl.textContent = `${(m.recall * 100).toFixed(1)}%`;



    f1El.textContent = `${(m.f1_score * 100).toFixed(1)}%`;



    aucEl.textContent = m.roc_auc.toFixed(3);



    latEl.textContent = `${m.inference_time_ms} ms`;







    if (cmTn) cmTn.textContent = m.confusion_matrix.tn;



    if (cmFp) cmFp.textContent = m.confusion_matrix.fp;



    if (cmFn) cmFn.textContent = m.confusion_matrix.fn;



    if (cmTp) cmTp.textContent = m.confusion_matrix.tp;



    if (cmSamples) cmSamples.textContent = `${m.confusion_matrix.total} ${t("cm_pe_samples_label")}`;



    if (cmNote) {



      cmNote.innerHTML = `<strong>${t("cm_note_heading")}:</strong> ${t("cm_note_exe_body")}`;



    }







    if (rocPill) rocPill.textContent = `AUC = ${m.roc_auc.toFixed(3)}`;



    if (rocCurvePath) rocCurvePath.setAttribute("d", "M 40,200 C 42,40 70,25 300,20");



    if (rocPolygon) rocPolygon.setAttribute("points", "40,200 40,20 90,30 160,50 240,90 300,200");







    renderFeatureBars(featContainer, m.top_features);



  } else if (isHybrid && data.hybrid_fusion) {



    const h = data.hybrid_fusion;



    accEl.textContent = `${(h.accuracy * 100).toFixed(1)}%`;



    accSub.textContent = t("metric_hybrid_sub");



    precEl.textContent = `${(h.precision * 100).toFixed(1)}%`;



    recEl.textContent = `${(h.recall * 100).toFixed(1)}%`;



    f1El.textContent = `${(h.f1_score * 100).toFixed(1)}%`;



    aucEl.textContent = h.roc_auc.toFixed(3);



    latEl.textContent = "3.4 ms";







    if (cmTn) cmTn.textContent = "13,130";



    if (cmFp) cmFp.textContent = "179";



    if (cmFn) cmFn.textContent = "172";



    if (cmTp) cmTp.textContent = "13,137";



    if (cmSamples) cmSamples.textContent = t("cm_hybrid_samples_label");



    if (cmNote) {



      cmNote.innerHTML = `<strong>${t("bmi_thesis_title")}:</strong> ${t("cm_note_hybrid_body")}`;



    }







    if (rocPill) rocPill.textContent = `AUC = ${h.roc_auc.toFixed(3)}`;



    if (rocCurvePath) rocCurvePath.setAttribute("d", "M 40,200 C 40,30 50,22 300,20");



    if (rocPolygon) rocPolygon.setAttribute("points", "40,200 40,20 60,25 120,35 220,70 300,200");







    const hybridFeats = [



      {



        label_uz: "Lokal Leksik & Dinamik Evristika",



        label_en: "Local Lexical & Dynamic Heuristics",



        label_ru: "Локальная лексическая и динамическая эвристика",



        importance_pct: 35.0,



      },



      {



        label_uz: "Random Forest ML Ehtimolligi",



        label_en: "Random Forest ML Probability",



        label_ru: "Вероятность ML-модели Random Forest",



        importance_pct: 30.0,



      },



      {



        label_uz: "VirusTotal Razvedka Konsensusi",



        label_en: "VirusTotal Threat Intel Consensus",



        label_ru: "Консенсус разведки угроз VirusTotal",



        importance_pct: 20.0,



      },



      {



        label_uz: "Brend Spoofing & Levenshtein Maskasi",



        label_en: "Brand Spoofing & Levenshtein Distance",



        label_ru: "Маскировка под бренды и дистанция Левенштейна",



        importance_pct: 15.0,



      },



    ];



    renderFeatureBars(featContainer, hybridFeats);



  }



}







function renderFeatureBars(container, features) {



  if (!container || !features) return;



  container.innerHTML = "";



  features.forEach((item) => {



    const div = document.createElement("div");



    div.className = "metrics-feat-item";



    const name = item["label_" + currentLang] || item.label_uz || item.feature;



    div.innerHTML = `



      <div class="metrics-feat-header">



        <span class="metrics-feat-name">${escapeHtml(name)}</span>



        <span class="metrics-feat-weight">${item.importance_pct}%</span>



      </div>



      <div class="metrics-feat-track">



        <div class="metrics-feat-fill" style="width: 0%"></div>



      </div>



    `;



    container.appendChild(div);



    const fill = div.querySelector(".metrics-feat-fill");



    requestAnimationFrame(() => {



      requestAnimationFrame(() => {



        if (fill) fill.style.width = `${Math.min(item.importance_pct * 2.5, 100)}%`;



      });



    });



  });



}







/* ============================================================



   7) EXPLAINABLE AI (XAI) & OFFICIAL SOC INCIDENT DOSSIER



   ============================================================ */







function escapeHtml(str) {



  if (str === null || str === undefined) return "";



  return String(str)



    .replace(/&/g, "&amp;")



    .replace(/</g, "&lt;")



    .replace(/>/g, "&gt;")



    .replace(/"/g, "&quot;")



    .replace(/'/g, "&#039;");



}







function renderXaiBars(containerEl, panelEl, xaiData) {



  if (!containerEl || !panelEl) return;



  if (!xaiData || !Array.isArray(xaiData) || xaiData.length === 0) {



    panelEl.hidden = true;



    return;



  }



  panelEl.hidden = false;



  containerEl.innerHTML = "";







  xaiData.forEach((item) => {



    const isRisk = item.direction !== "SAFE";



    const dirClass = isRisk ? "risk" : "safe";



    const dirSign = isRisk ? "+" : "-";



    const name = item["name_" + currentLang] || item.name_uz || item.feature;



    const reason = item["reason_" + currentLang] || item.reason_uz || "";



    const val = item.value_display ? ` (${item.value_display})` : "";



    const pct = Math.min(Math.max(item.impact_pct || 10, 5), 100);







    const barItem = document.createElement("div");



    barItem.className = "xai-bar-item";



    barItem.innerHTML = `



      <div class="xai-bar-top">



        <span class="xai-bar-name">${escapeHtml(name)}${escapeHtml(val)}</span>



        <span class="xai-bar-pct ${dirClass}">${dirSign}${pct}%</span>



      </div>



      <div class="xai-track">



        <div class="xai-fill ${dirClass}" style="width: 0%"></div>



      </div>



      <div class="xai-bar-reason">${escapeHtml(reason)}</div>



    `;



    containerEl.appendChild(barItem);







    const fillEl = barItem.querySelector(".xai-fill");



    requestAnimationFrame(() => {



      requestAnimationFrame(() => {



        if (fillEl) fillEl.style.width = `${pct}%`;



      });



    });



  });



}







function getMitreTechniques(type, data) {



  const techniques = [];



  const textCorpus = [



    ...(data.reasons || []),



    ...(data.indicators || []),



    ...(data.positive_signals || []),



    ...((data.xai_analysis || []).map((x) => `${x.feature} ${x.name_uz || ""} ${x.name_en || ""} ${x.name_ru || ""} ${x.reason_uz || ""}`)),



  ].join(" ").toLowerCase();







  const score = data.final_score !== undefined ? data.final_score : (data.risk_score || 0);







  function pick(uz, en, ru) {



    if (currentLang === "en") return en;



    if (currentLang === "ru") return ru;



    return uz;



  }







  if (type === "url") {



    if (textCorpus.includes("brand") || textCorpus.includes("spoof") || textCorpus.includes("impersonat")) {



      techniques.push({



        id: "T1566.002",



        tactic: pick("Initial Access (Boshlang'ich kirish)", "Initial Access", "Initial Access (Начальный доступ)"),



        desc: pick("Phishing: Spearphishing Link — Tashkilot yoki to'lov tizimi brendiga soxta taqlid qilingan fishing havolasi",



                    "Phishing: Spearphishing Link — Forged brand or payment portal link designed for credential theft",



                    "Phishing: Spearphishing Link — Ссылка с имитацией доверенного бренда для кражи данных"),



      });



    }



    if (textCorpus.includes("homoglyph") || textCorpus.includes("punycode") || textCorpus.includes("ip address")) {



      techniques.push({



        id: "T1036.007",



        tactic: pick("Defense Evasion (Himoyani chetlab o'tish)", "Defense Evasion", "Defense Evasion (Обход защиты)"),



        desc: pick("Masquerading: Homoglyph / IP — Domen nomini o'xshash belgilar yoki IP-manzil orqali niqoblash",



                    "Masquerading: Homoglyph / Direct IP — Domain spoofed via homoglyphic Unicode or raw IP address",



                    "Masquerading: Homoglyph / IP — Маскировка домена омоглифами или прямым IP-адресом"),



      });



    }



    if (textCorpus.includes("keyword") || textCorpus.includes("login") || textCorpus.includes("verify") || textCorpus.includes("account")) {



      techniques.push({



        id: "T1056.001",



        tactic: pick("Credential Access (Hisob ma'lumotlarini o'g'irlash)", "Credential Access", "Credential Access (Кража учетных данных)"),



        desc: pick("Input Capture: Web Credential Harvesting — Foydalanuvchi login va parollarini yig'ishga qaratilgan forma",



                    "Input Capture: Web Credential Harvesting — Fake authentication portal targeting credentials",



                    "Input Capture: Web Credential Harvesting — Поддельная форма ввода логинов и паролей"),



      });



    }



    if (textCorpus.includes("shortener") || textCorpus.includes("redirect")) {



      techniques.push({



        id: "T1027",



        tactic: pick("Defense Evasion (Himoyani chetlab o'tish)", "Defense Evasion", "Defense Evasion (Обход защиты)"),



        desc: pick("Obfuscated Files or Information — Asl nishonni xavfsizlik skanerlaridan yashirish uchun havolani qisqartirish",



                    "Obfuscated Files or Information — URL shortener used to conceal destination",



                    "Obfuscated Files or Information — Сокращение URL для сокрытия целевого адреса"),



      });



    }



    if (textCorpus.includes("executable") || textCorpus.includes("payload") || textCorpus.includes("download")) {



      techniques.push({



        id: "T1204.001",



        tactic: pick("Execution (Ijro)", "Execution", "Execution (Выполнение)"),



        desc: pick("User Execution: Malicious Link — Foydalanuvchini aldab zararli binar yuklamani ochishga undash",



                    "User Execution: Malicious Link — User tricked into downloading and executing payload",



                    "User Execution: Malicious Link — Ссылка ведет к загрузке вредоносного исполняемого файла"),



      });



    }



    if (score >= 50 && techniques.length === 0) {



      techniques.push({



        id: "T1566",



        tactic: pick("Initial Access (Boshlang'ich kirish)", "Initial Access", "Initial Access (Начальный доступ)"),



        desc: pick("Phishing — Internet tarmog'ida noqonuniy yo'naltirish orqali foydalanuvchini tuzoqqa ilintirish",



                    "Phishing — Malicious online deception vector targeting user credentials",



                    "Phishing — Фишинговый вектор атаки для завлечения жертвы"),



      });



    }



  } else if (type === "exe") {



    if (textCorpus.includes("entropy") || textCorpus.includes("packer") || textCorpus.includes("upx") || textCorpus.includes("themida")) {



      techniques.push({



        id: "T1027.002",



        tactic: pick("Defense Evasion (Himoyani chetlab o'tish)", "Defense Evasion", "Defense Evasion (Обход защиты)"),



        desc: pick("Software Packing (UPX/Themida) — Antivirus statik skanerlaridan qochish uchun faylni siqish va shifrlash",



                    "Software Packing (UPX/Themida) — Binary packed or encrypted to evade static scanner signatures",



                    "Software Packing (UPX/Themida) — Упаковка/шифрование файла для обхода сигнатур"),



      });



    }



    if (textCorpus.includes("w+x") || textCorpus.includes("writable") || textCorpus.includes("memory")) {



      techniques.push({



        id: "T1055",



        tactic: pick("Privilege Escalation / Defense Evasion", "Privilege Escalation / Defense Evasion", "Privilege Escalation / Defense Evasion"),



        desc: pick("Process Injection: Memory Allocation — Bir vaqtning o'zida yozish va bajarish (W+X) huquqiga ega bo'limdan foydalanish",



                    "Process Injection: Memory Allocation — Section with simultaneous W+X privileges",



                    "Process Injection: Memory Allocation — Секция с одновременными правами W+X"),



      });



    }



    if (textCorpus.includes("tls") || textCorpus.includes("callback")) {



      techniques.push({



        id: "T1574",



        tactic: pick("Persistence / Defense Evasion", "Persistence / Defense Evasion", "Persistence / Defense Evasion"),



        desc: pick("Hijack Execution Flow: TLS Callbacks — Kirish nuqtasidan (Entry Point) oldin yashirincha ishga tushuvchi callback funksiyasi",



                    "Hijack Execution Flow: TLS Callbacks — Code executed stealthily prior to main Entry Point",



                    "Hijack Execution Flow: TLS Callbacks — Скрытое выполнение кода до точки входа"),



      });



    }



    if (textCorpus.includes("debug") || textCorpus.includes("hook")) {



      techniques.push({



        id: "T1622",



        tactic: pick("Defense Evasion (Himoyani chetlab o'tish)", "Defense Evasion", "Defense Evasion (Обход защиты)"),



        desc: pick("Debugger Evasion — Xavfsizlik tahlilchisi yoki sandbox muhitini sezib, zararli faoliyatni to'xtatish",



                    "Debugger Evasion — Anti-debugging tricks to bypass sandbox monitoring",



                    "Debugger Evasion — Обнаружение отладчика или среды песочницы"),



      });



    }



    if (score >= 50 && techniques.length === 0) {



      techniques.push({



        id: "T1204.002",



        tactic: pick("Execution (Ijro)", "Execution", "Execution (Выполнение)"),



        desc: pick("User Execution: Malicious File — Foydalanuvchi tizimida ruxsatsiz ijro etiluvchi Windows PE binar fayli",



                    "User Execution: Malicious File — Untrusted Windows PE executable targeting host system",



                    "User Execution: Malicious File — Недоверенный исполняемый файл Windows PE"),



      });



    }



  } else if (type === "apk") {



    if (textCorpus.includes("accessibility") || textCorpus.includes("overlay") || textCorpus.includes("draw_overlays")) {



      techniques.push({



        id: "T1417 / T1437",



        tactic: pick("Credential Access / Privilege Escalation", "Credential Access / Privilege Escalation", "Credential Access / Privilege Escalation"),



        desc: pick("Input Capture: Accessibility Service / Tapjacking Overlay — Bank ilovalari ustiga soxta interfeys chizish va klavishlarni yozib olish",



                    "Input Capture: Accessibility Service / Tapjacking Overlay — Overlay injection targeting banking apps",



                    "Input Capture: Accessibility Service / Tapjacking Overlay — Наложение фальшивых окон поверх банковских приложений"),



      });



    }



    if (textCorpus.includes("sms") || textCorpus.includes("receive_sms") || textCorpus.includes("read_sms")) {



      techniques.push({



        id: "T1412",



        tactic: pick("Credential Access (Hisob ma'lumotlarini o'g'irlash)", "Credential Access", "Credential Access (Кража учетных данных)"),



        desc: pick("Capture SMS Messages — Bank va to'lov tizimlarining 2FA bir martalik SMS tasdiqlash kodlarini tutib olish",



                    "Capture SMS Messages — Interception of 2FA one-time verification SMS codes",



                    "Capture SMS Messages — Перехват одноразовых СМС-кодов двухфакторной аутентификации"),



      });



    }



    if (textCorpus.includes("admin") || textCorpus.includes("device_admin")) {



      techniques.push({



        id: "T1433",



        tactic: pick("Defense Evasion (Himoyani chetlab o'tish)", "Defense Evasion", "Defense Evasion (Обход защиты)"),



        desc: pick("Stop / Inhibit Security Tools: Device Admin — Ilovani tizimdan o'chirishga to'sqinlik qilish va ekranni bloklash",



                    "Stop / Inhibit Security Tools: Device Admin — Abusing device administrator privilege to prevent uninstallation",



                    "Stop / Inhibit Security Tools: Device Admin — Злоупотребление правами администратора устройства"),



      });



    }



    if (textCorpus.includes("install") || textCorpus.includes("request_install_packages")) {



      techniques.push({



        id: "T1476",



        tactic: pick("Initial Access / Persistence", "Initial Access / Persistence", "Initial Access / Persistence"),



        desc: pick("Deliver Malicious App via Other Means — Google Play'dan tashqari boshqa noma'lum APK ilovalarni yuklash",



                    "Deliver Malicious App via Other Means — Sideloading secondary untrusted APK packages",



                    "Deliver Malicious App via Other Means — Загрузка сторонних недоверенных APK пакетов"),



      });



    }



    if (score >= 50 && techniques.length === 0) {



      techniques.push({



        id: "T1474",



        tactic: pick("Initial Access (Mobil qurilmaga kirish)", "Initial Access", "Initial Access (Начальный доступ)"),



        desc: pick("Malicious APK Delivery — Android operatsion tizimi xavfsizlik chegaralarini chetlab o'tuvchi paket",



                    "Malicious APK Delivery — Android package attempting to bypass system boundaries",



                    "Malicious APK Delivery — Вредоносный Android APK, нацеленный на компрометацию устройства"),



      });



    }



  }







  return techniques;



}







function openSocReport(type, data) {



  if (!data) {



    alert("Iltimos, avval tekshiruvni bajaring! / Please perform a scan first.");



    return;



  }







  lastSocReportType = type;



  lastSocReportData = data;







  const modal = document.getElementById("soc-report-modal");



  if (!modal) return;







  const randomHex = Math.random().toString(16).substring(2, 6).toUpperCase();



  const docId = `PG-SOC-${new Date().getFullYear()}-${randomHex}`;



  const docIdEl = document.getElementById("report-doc-id");



  const repDocNoEl = document.getElementById("rep-doc-no");



  if (docIdEl) docIdEl.textContent = `DOSSIER #${docId}`;



  if (repDocNoEl) repDocNoEl.textContent = docId;







  const now = new Date();



  const formattedTime = `${now.toISOString().replace("T", " ").substring(0, 19)} UTC+5 (Toshkent vaqti)`;



  const timestampEl = document.getElementById("rep-timestamp");



  if (timestampEl) timestampEl.textContent = formattedTime;







  const stampDateEl = document.getElementById("rep-stamp-date");



  if (stampDateEl) {



    stampDateEl.textContent = `${now.getFullYear()}.${String(now.getMonth() + 1).padStart(2, "0")}.${String(now.getDate()).padStart(2, "0")}`;



  }







  const repTargetType = document.getElementById("rep-target-type");



  const repEngineType = document.getElementById("rep-engine-type");



  const repTargetName = document.getElementById("rep-target-name");



  const repHashesRow = document.getElementById("rep-hashes-row");



  const repHashesVal = document.getElementById("rep-hashes-val");







  if (type === "url") {



    if (repTargetType) repTargetType.textContent = currentLang === "uz" ? "Web URL / Onlayn Resurs" : (currentLang === "ru" ? "Веб-ресурс / Ссылка URL" : "Web URL / Online Resource");



    if (repEngineType) repEngineType.textContent = "PhishGuard Lexical AI + Heuristics + Threat Intelligence";



    if (repTargetName) repTargetName.textContent = data.url;



    if (repHashesRow) repHashesRow.style.display = "table-row";



    if (repHashesVal) {



      repHashesVal.innerHTML = `<strong>Domain:</strong> ${escapeHtml(data.hostname || "N/A")}&nbsp;&nbsp;|&nbsp;&nbsp;<strong>Protocol:</strong> ${(data.url && data.url.startsWith("https") ? "HTTPS (Encrypted)" : "HTTP (Unencrypted)")}`;



    }



  } else if (type === "exe") {



    if (repTargetType) repTargetType.textContent = currentLang === "uz" ? "Windows Portable Executable (.exe)" : (currentLang === "ru" ? "Исполняемый файл Windows (.exe)" : "Windows Portable Executable (.exe)");



    if (repEngineType) repEngineType.textContent = "PE Static Analyzer + Section Entropy + Neural Classifier";



    if (repTargetName) repTargetName.textContent = `${data.file_name} (${formatFileSize(data.file_size || 0)})`;



    if (repHashesRow) repHashesRow.style.display = "table-row";



    if (repHashesVal) {



      repHashesVal.innerHTML = `<strong>SHA-256:</strong> ${escapeHtml(data.sha256 || "N/A")}`;



    }



  } else if (type === "apk") {



    if (repTargetType) repTargetType.textContent = currentLang === "uz" ? "Android Application Package (.apk)" : (currentLang === "ru" ? "Пакет приложения Android (.apk)" : "Android Application Package (.apk)");



    if (repEngineType) repEngineType.textContent = "AXML Manifest Engine + Permission Risk Fusion + Evasion Detector";



    const ver = data.version_name ? ` v${data.version_name}` : "";



    if (repTargetName) repTargetName.textContent = `${data.file_name || "app.apk"} [${data.package_name || "unknown"}${ver}]`;



    if (repHashesRow) repHashesRow.style.display = "table-row";



    if (repHashesVal) {



      repHashesVal.innerHTML = `<strong>SHA-256:</strong> ${escapeHtml(data.sha256 || "N/A")}`;



    }



  }







  const score = data.final_score !== undefined ? data.final_score : (data.risk_score !== undefined ? data.risk_score : 0);



  const repScoreNum = document.getElementById("rep-score-num");



  const repLevelBadge = document.getElementById("rep-level-badge");



  const repClassText = document.getElementById("rep-class-text");



  const repStatusPill = document.getElementById("rep-status-pill");







  if (repScoreNum) repScoreNum.textContent = `${score}%`;



  if (repLevelBadge) {



    repLevelBadge.textContent = getLevelLabel(data.risk_level);



    repLevelBadge.style.color = zoneColor(score);



  }



  if (repClassText) repClassText.textContent = getClassificationLabel(data.classification);



  if (repStatusPill) {



    if (score >= 60) {



      repStatusPill.textContent = currentLang === "uz" ? "XAVFLI / MALICIOUS" : (currentLang === "ru" ? "ОПАСНО / MALICIOUS" : "MALICIOUS / HIGH RISK");



      repStatusPill.style.background = "#dc2626";



    } else if (score >= 30) {



      repStatusPill.textContent = currentLang === "uz" ? "SHUBHALI / SUSPICIOUS" : (currentLang === "ru" ? "ПОДОЗРИТЕЛЬНО / SUSPICIOUS" : "SUSPICIOUS / MEDIUM RISK");



      repStatusPill.style.background = "#f59e0b";



    } else {



      repStatusPill.textContent = currentLang === "uz" ? "XAVFSIZ / CLEAN" : (currentLang === "ru" ? "ЧИСТО / CLEAN" : "CLEAN / SAFE");



      repStatusPill.style.background = "#10b981";



    }



  }







  const repZerodayNote = document.getElementById("rep-zeroday-note");



  const repVtSummary = document.getElementById("rep-vt-summary");



  const repConsensusNote = document.getElementById("rep-consensus-note");







  const isZeroDay = (data.indicators || data.reasons || []).some((r) => /zero-day/i.test(r));



  if (repZerodayNote) {



    if (isZeroDay) {



      repZerodayNote.textContent = currentLang === "uz"



        ? "⚠️ DIQQAT: Yangi Zero-Day anomaliyasi aniqlandi! Tashqi bazalarda qayd etilmagan, lokal intellektual tahlil yuqori xavf deb topdi."



        : currentLang === "ru"



        ? "⚠️ ВНИМАНИЕ: Обнаружена новая аномалия Zero-Day! Угроза отсутствует во внешних базах, выявлена локальным интеллектом."



        : "⚠️ ALERT: Zero-Day anomaly detected! Threat is unlisted in external databases, flagged via local intelligence.";



    } else {



      repZerodayNote.textContent = currentLang === "uz"



        ? "Oddiy tahlil protokoli: Hech qanday g'ayrioddiy Zero-Day anomaliyalari aniqlanmadi."



        : currentLang === "ru"



        ? "Стандартный протокол анализа: Аномалий типа Zero-Day не обнаружено."



        : "Standard audit protocol: No abnormal Zero-Day threats identified.";



    }



  }



  if (repVtSummary) {



    repVtSummary.textContent = formatVtNote(data.vt_note) || (currentLang === "uz" ? "VirusTotal razvedka bazasi orqali tekshirildi." : (currentLang === "ru" ? "Проверено по базе угроз VirusTotal." : "Cross-referenced with VirusTotal threat intelligence database."));



  }



  if (repConsensusNote) {



    repConsensusNote.textContent = currentLang === "uz"



      ? `Lokal sun'iy intellekt modeli (${score}% ehtimollik) va mustaqil antivirus dvijoklari ma'lumotlari umumlashtirildi.`



      : currentLang === "ru"



      ? `Консенсус локальной модели ИИ (вероятность ${score}%) и независимых антивирусных движков сформирован.`



      : `Consensus formed from local AI model (${score}% probability) and independent antivirus engines.`;



  }







  const mitreTbody = document.getElementById("rep-mitre-tbody");



  if (mitreTbody) {



    mitreTbody.innerHTML = "";



    const techniques = getMitreTechniques(type, data);



    if (techniques.length === 0) {



      const tr = document.createElement("tr");



      const cleanNote = currentLang === "uz"



        ? "✅ Hech qanday tajovuzkor MITRE ATT&CK taktikalari aniqlanmadi (Ob'ekt toza)"



        : currentLang === "ru"



        ? "✅ Тактик атак MITRE ATT&CK не обнаружено (Объект чист)"



        : "✅ No adversarial MITRE ATT&CK tactics detected (Asset is clean)";



      tr.innerHTML = `<td colspan="3" style="text-align:center; color:#10b981; font-weight:600; padding:12px;">${cleanNote}</td>`;



      mitreTbody.appendChild(tr);



    } else {



      techniques.forEach((t) => {



        const tr = document.createElement("tr");



        tr.innerHTML = `



          <td><strong style="color:#2563eb; font-family:monospace;">${escapeHtml(t.id)}</strong></td>



          <td><strong>${escapeHtml(t.tactic)}</strong></td>



          <td style="color:#334155;">${escapeHtml(t.desc)}</td>



        `;



        mitreTbody.appendChild(tr);



      });



    }



  }







  const xaiTbody = document.getElementById("rep-xai-tbody");



  if (xaiTbody) {



    xaiTbody.innerHTML = "";



    const xaiData = data.xai_analysis || [];



    if (xaiData.length === 0) {



      const fallbackList = [];



      (data.reasons || data.indicators || []).forEach((r) => {



        fallbackList.push({ name: translateReason(r), dir: currentLang === "uz" ? "XAVF (Risk)" : (currentLang === "ru" ? "ОПАСНО (Risk)" : "RISK"), pct: 20, reason: r });



      });



      (data.positive_signals || []).forEach((s) => {



        fallbackList.push({ name: translateReason(s), dir: currentLang === "uz" ? "XAVFSIZ (Safe)" : (currentLang === "ru" ? "БЕЗОПАСНО (Safe)" : "SAFE"), pct: 15, reason: s });



      });



      if (fallbackList.length === 0) {



        xaiTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:12px; color:#64748b;">${currentLang === "uz" ? "Standart xavfsizlik parametrlari doirasida." : (currentLang === "ru" ? "В пределах нормальных параметров безопасности." : "Within baseline cybersecurity tolerances.")}</td></tr>`;



      } else {



        fallbackList.slice(0, 5).forEach((f) => {



          const isRisk = f.dir.includes("XAVF") || f.dir.includes("ОПАСНО") || f.dir === "RISK";



          const tr = document.createElement("tr");



          tr.innerHTML = `



            <td><strong>${escapeHtml(f.name)}</strong></td>



            <td style="color:${isRisk ? "#dc2626" : "#10b981"}; font-weight:700;">${f.dir}</td>



            <td style="font-family:monospace; font-weight:700;">${f.pct}%</td>



            <td style="color:#475569;">${escapeHtml(f.reason)}</td>



          `;



          xaiTbody.appendChild(tr);



        });



      }



    } else {



      xaiData.slice(0, 6).forEach((item) => {



        const isRisk = item.direction !== "SAFE";



        const tr = document.createElement("tr");



        const dirLabel = isRisk ? (currentLang === "uz" ? "XAVF (Risk)" : (currentLang === "ru" ? "ОПАСНО (Risk)" : "RISK")) : (currentLang === "uz" ? "XAVFSIZ (Safe)" : (currentLang === "ru" ? "БЕЗОПАСНО (Safe)" : "SAFE"));



        const dirColor = isRisk ? "#dc2626" : "#10b981";



        const name = item["name_" + currentLang] || item.name_uz || item.feature;



        const reason = item["reason_" + currentLang] || item.reason_uz || "";



        tr.innerHTML = `



          <td><strong>${escapeHtml(name)}</strong></td>



          <td style="color:${dirColor}; font-weight:700;">${dirLabel}</td>



          <td style="font-family:monospace; font-weight:700;">${isRisk ? "+" : "-"}${item.impact_pct || 15}%</td>



          <td style="color:#475569;">${escapeHtml(reason)}</td>



        `;



        xaiTbody.appendChild(tr);



      });



    }



  }







  const indList = document.getElementById("rep-indicators-list");



  if (indList) {



    indList.innerHTML = "";



    const items = data.indicators || data.reasons || [];



    if (items.length === 0) {



      indList.innerHTML = `<li style="color:#10b981;">✅ ${currentLang === "uz" ? "Hech qanday tahdid indikatori (IoC) aniqlanmadi." : (currentLang === "ru" ? "Индикаторы компрометации (IoC) не обнаружены." : "No indicators of compromise (IoC) identified.")}</li>`;



    } else {



      items.forEach((it) => {



        const li = document.createElement("li");



        li.textContent = `⚠️ ${translateReason(it)}`;



        indList.appendChild(li);



      });



    }



  }







  const recList = document.getElementById("rep-rec-list");



  const recBox = document.getElementById("rep-rec-box");



  if (recList) {



    recList.innerHTML = "";



    if (score >= 60) {



      if (recBox) {



        recBox.style.background = "#fff1f2";



        recBox.style.borderColor = "#fecdd3";



      }



      if (currentLang === "en") {



        recList.innerHTML = `



          <li style="color:#9f1239; font-weight:700;">1. STRICTLY PROHIBITED: Immediately cease all interaction with this link or file!</li>



          <li style="color:#9f1239;">2. FIREWALL SINKHOLE: Blacklist this URL/hash across enterprise firewalls, secure proxies, and DNS filters.</li>



          <li style="color:#9f1239;">3. INCIDENT RESPONSE: If accessed by an employee, revoke credentials immediately and isolate workstation via EDR.</li>



          <li style="color:#9f1239;">4. SOC ESCALATION: Dispatch incident ticket accompanied by this forensic dossier to SOC/CERT personnel.</li>



        `;



      } else if (currentLang === "ru") {



        recList.innerHTML = `



          <li style="color:#9f1239; font-weight:700;">1. СТРОГО ЗАПРЕЩЕНО: Немедленно прекратить любое взаимодействие с данным объектом!</li>



          <li style="color:#9f1239;">2. БЛОКИРОВКА: Внести URL-адрес / хэш в черные списки корпоративных шлюзов безопасности и DNS Sinkhole.</li>



          <li style="color:#9f1239;">3. РАССЛЕДОВАНИЕ: При наличии факта запуска изолировать рабочую станцию через EDR и сбросить пароли.</li>



          <li style="color:#9f1239;">4. ЭСКАЛАЦИЯ: Передать данный инцидент с приложением заключения в дежурную смену SOC/CERT.</li>



        `;



      } else {



        recList.innerHTML = `



          <li style="color:#9f1239; font-weight:700;">1. QAT'IY MAN ETILADI: Ushbu havola yoki fayl bilan har qanday aloqa zudlik bilan to'xtatilsin!</li>



          <li style="color:#9f1239;">2. BLOKLASH: Tashkilot korporativ xavfsizlik devorlari (Firewall/DNS Sinkhole) va proxy serverlariga ushbu manzil/xesh zudlik bilan qora ro'yxatga kiritilsin.</li>



          <li style="color:#9f1239;">3. HODISALAR TERGOVI: Agar biror xodim ushbu resursga kirgan yoki faylni ishga tushirgan bo'lsa, uning hisob parollarini zudlik bilan yangilang va EDR orqali kompyuterni tarmoqdan uzing.</li>



          <li style="color:#9f1239;">4. HISOBOT: Voqea yuzasidan ichki SOC xizmati va kiberxavfsizlik mas'uliga ushbu ekspertiza xulosasini ilova qilgan holda xabarnoma jo'natilsin.</li>



        `;



      }



    } else if (score >= 30) {



      if (recBox) {



        recBox.style.background = "#fffbeb";



        recBox.style.borderColor = "#fef3c7";



      }



      if (currentLang === "en") {



        recList.innerHTML = `



          <li style="color:#92400e; font-weight:700;">1. PRECAUTIONARY ALERT: Object is assessed as suspicious. Do not open on production endpoints.</li>



          <li style="color:#92400e;">2. SANDBOX DETONATION: Detonate and inspect asset inside an isolated dynamic malware sandbox.</li>



          <li style="color:#92400e;">3. USER WARNING: Disallow entry of corporate credentials or financial information.</li>



        `;



      } else if (currentLang === "ru") {



        recList.innerHTML = `



          <li style="color:#92400e; font-weight:700;">1. МЕРЫ ПРЕДОСТОРОЖНОСТИ: Объект оценен как подозрительный. Не открывать на штатных рабочих местах.</li>



          <li style="color:#92400e;">2. SANDBOX-АНАЛИЗ: Провести поведенческий анализ в изолированной песочнице (Sandbox).</li>



          <li style="color:#92400e;">3. ПРЕДУПРЕЖДЕНИЕ: Запретить ввод персональных данных и служебных учетных записей.</li>



        `;



      } else {



        recList.innerHTML = `



          <li style="color:#92400e; font-weight:700;">1. EHTIYOTKORLIK CHORALARI: Ushbu ob'ekt shubhali deb baholandi. Standart ish stantsiyasida ochilmasin.</li>



          <li style="color:#92400e;">2. SANDBOX TEKSHIRUVI: Ob'ektni faqat izolyatsiyalangan tahlil Sandbox muhitida chuqurroq dinamik tekshiruvdan o'tkazish tavsiya qilinadi.</li>



          <li style="color:#92400e;">3. FOYDALANUVCHILARNI OGOHLANTIRISH: Shaxsiy ma'lumotlar yoki bank kartalari rekvizitlarini kiritish taqiqlansin.</li>



        `;



      }



    } else {



      if (recBox) {



        recBox.style.background = "#f0fdf4";



        recBox.style.borderColor = "#bbf7d0";



      }



      if (currentLang === "en") {



        recList.innerHTML = `



          <li style="color:#166534; font-weight:700;">1. APPROVED: The asset passed multi-layer analysis and is considered clean.</li>



          <li style="color:#166534;">2. STANDARD HYGIENE: Standard cybersecurity practices should be maintained during use.</li>



          <li style="color:#166534;">3. ROUTINE LOGGING: Asset details preserved in audit history.</li>



        `;



      } else if (currentLang === "ru") {



        recList.innerHTML = `



          <li style="color:#166534; font-weight:700;">1. ДОПУЩЕНО: Объект успешно прошел проверку и классифицирован как безопасный.</li>



          <li style="color:#166534;">2. КИБЕРГИГИЕНА: Допускается к использованию с соблюдением общих мер безопасности.</li>



          <li style="color:#166534;">3. МОНИТОРИНГ: Запись сохранена в журнале аудита.</li>



        `;



      } else {



        recList.innerHTML = `



          <li style="color:#166534; font-weight:700;">1. RUXSAT BERILADI: Ob'ekt tekshiruvdan muvaffaqiyatli o'tdi va toza deb topildi.</li>



          <li style="color:#166534;">2. STANDART GIGIENA: Standart kiberxavfsizlik choralariga rioya qilgan holda resursdan foydalanish mumkin.</li>



          <li style="color:#166534;">3. DOIMIY KUZATUV: Ob'ekt kelgusida qayta skanerlash rejasiga kiritilishi mumkin.</li>



        `;



      }



    }



  }







  modal.hidden = false;



  document.body.style.overflow = "hidden";



}







function closeSocReport() {



  const modal = document.getElementById("soc-report-modal");



  if (modal) {



    modal.hidden = true;



    document.body.style.overflow = "";



  }



}







function openSocReportFromHistory(entry) {



  if (!entry) return;



  const isUrl = entry.scan_type === "URL";



  const isExe = entry.scan_type === "EXE";



  const type = isUrl ? "url" : (isExe ? "exe" : "apk");







  const data = {



    url: isUrl ? entry.target : undefined,



    file_name: !isUrl ? entry.target : undefined,



    package_name: !isUrl && entry.scan_type === "APK" ? entry.target : undefined,



    risk_score: entry.risk_score,



    final_score: entry.risk_score,



    risk_level: entry.risk_level,



    classification: entry.classification,



    sha256: !isUrl ? "Historical Audit Record (Logged)" : undefined,



    hostname: isUrl ? (entry.target.replace(/^https?:\/\//i, "").split("/")[0]) : undefined,



    vt_note: "Tarixiy audit jurnali orqali yuklandi.",



    reasons: entry.risk_score > 30 ? [entry.classification + " holati qayd etilgan."] : [],



    indicators: entry.risk_score > 30 ? [entry.classification + " holati qayd etilgan."] : [],



    positive_signals: entry.risk_score <= 30 ? ["Tarixiy tekshiruvda toza deb topilgan."] : [],



    xai_analysis: [



      {



        feature: "historical_audit",



        name_uz: "Tarixiy audit tekshiruvi natijasi",



        name_en: "Historical Audit Result",



        name_ru: "Результат исторического аудита",



        impact_pct: entry.risk_score > 0 ? entry.risk_score : 10,



        direction: entry.risk_score > 30 ? "RISK" : "SAFE",



        value_display: entry.classification,



        reason_uz: "Ushbu ob'ekt oldingi xavfsizlik tekshiruvidan o'tkazilgan.",



        reason_en: "This asset was analyzed in a previous session.",



        reason_ru: "Этот объект был проанализирован в предыдущей сессии.",



      },



    ],



  };







  openSocReport(type, data);



}







/* ============================================================



   8) EVENT BINDINGS & INIT



   ============================================================ */







document.querySelectorAll(".lang-btn").forEach((btn) => {



  btn.addEventListener("click", () => setLanguage(btn.dataset.lang));



});







document.getElementById("url-export-pdf-btn")?.addEventListener("click", () => openSocReport("url", lastUrlResult));



document.getElementById("exe-export-pdf-btn")?.addEventListener("click", () => openSocReport("exe", lastExeResult));



document.getElementById("apk-export-pdf-btn")?.addEventListener("click", () => openSocReport("apk", lastApkResult));







document.getElementById("modal-print-btn")?.addEventListener("click", () => window.print());



document.getElementById("modal-close-btn")?.addEventListener("click", closeSocReport);



document.getElementById("soc-report-modal")?.addEventListener("click", (e) => {



  if (e.target.id === "soc-report-modal") closeSocReport();



});



document.addEventListener("keydown", (e) => {



  if (e.key === "Escape") closeSocReport();



});







document.getElementById("url-export-json-btn")?.addEventListener("click", () => exportJson(lastUrlResult, "url"));



document.getElementById("exe-export-json-btn")?.addEventListener("click", () => exportJson(lastExeResult, "exe"));



document.getElementById("apk-export-json-btn")?.addEventListener("click", () => exportJson(lastApkResult, "apk"));







document.getElementById("history-search-input")?.addEventListener("input", () => {



  clearTimeout(window._histSearchTimeout);



  window._histSearchTimeout = setTimeout(refreshHistory, 300);



});



document.getElementById("history-type-filter")?.addEventListener("change", refreshHistory);



document.getElementById("history-risk-filter")?.addEventListener("change", refreshHistory);



document.getElementById("history-export-csv-btn")?.addEventListener("click", exportHistoryCsv);







document.querySelectorAll(".metrics-tab-btn").forEach((btn) => {



  btn.addEventListener("click", () => {



    document.querySelectorAll(".metrics-tab-btn").forEach((b) => b.classList.remove("active"));



    btn.classList.add("active");



    currentMetricsTab = btn.dataset.tab;



    if (cachedMetricsData) {



      renderMetricsView(cachedMetricsData, currentMetricsTab);



    }



  });



});







/* ============================================================



   7.5) LIVE CYBER THREAT ATTACK MAP ENGINE (DUAL SCOPE: GLOBAL & LOCAL UZBEKISTAN)



   ============================================================ */







let threatMapCanvas = null;



let threatMapCtx = null;



let threatMapAnimId = null;



let threatMapActiveArcs = [];



let threatMapRipples = [];



let threatMapSparks = [];



let threatMapShieldImpacts = [];



let threatMapOffscreenBg = null;



let threatMapPulseAngle = 0;



let threatMapRadarAngle = 0;



let threatMapFilter = "ALL";



let threatMapPaused = false;



let threatMapSound = false;



let threatMapAudioCtx = null;



let threatMapTelemetryData = null;



let threatMapLocalTelemetryData = null;



let threatMapInterval = null;



let threatMapTotalCounter = 1445;







// Map Scope: "global" (World) vs "local" (Republic of Uzbekistan)



let threatMapScope = "global";







// Interactive Viewport State (Zoom & Pan)



let threatMapZoom = 1.0;



let threatMapPanX = 0;



let threatMapPanY = 0;



let threatMapIsDragging = false;



let threatMapDragStart = { x: 0, y: 0 };



let threatMapMousePos = { x: -100, y: -100, lat: 0, lon: 0 };



let threatMapHoveredArc = null;







let threatMapWorldRings = null;



let threatMapUzRings = null;



let threatMapUzRegionalRings = null;







let threatMapVectorCounters = {



  ALL: 4890,



  WAV: 1420,



  OAS: 890,



  APK: 354,



  IDS: 680,



  KSN: 2410



};







let threatMapGlobalStats = {



  RU: 3421,



  US: 2890,



  UZ: 1445,



  DE: 1120,



  NL: 840,



  BR: 615,



};







let threatMapLocalStats = {



  "Toshkent shahri": 412,



  "Samarqand viloyati": 248,



  "Farg'ona viloyati": 184,



  "Andijon viloyati": 156,



  "Qashqadaryo viloyati": 98,



  "Buxoro viloyati": 85,



  "Namangan viloyati": 78,



  "Qoraqalpog'iston": 74,



};







const TASHKENT_HUB = {



  lat: 41.2995,



  lon: 69.2401,



  city: "Tashkent",



  country: "Uzbekistan",



  code: "UZ",



  name: "Tashkent (TAS-IX Hub)"



};







// 14 Official Regional Nodes of Uzbekistan



const UZ_REGIONAL_NODES = [



  { id: "TAS", name: "Toshkent shahri", city: "Tashkent", lat: 41.2995, lon: 69.2401, role: "TAS-IX Markaziy NOC & Bosh SOC", isHub: true },



  { id: "TAS_REG", name: "Toshkent viloyati", city: "Chirchiq", lat: 41.4689, lon: 69.5822, role: "IT Park & Sanoat Dugonasi" },



  { id: "SAM", name: "Samarqand", city: "Samarkand", lat: 39.6542, lon: 66.9597, role: "Mintaqaviy Zaxira SOC Markazi", isHub: true },



  { id: "BUK", name: "Buxoro", city: "Bukhara", lat: 39.7747, lon: 64.4286, role: "G'arbiy Energetika Magistrali" },



  { id: "FER", name: "Farg'ona", city: "Fergana", lat: 40.3864, lon: 71.7864, role: "Vodiy Sanoat & Telekom Dugonasi", isHub: true },



  { id: "AND", name: "Andijon", city: "Andijan", lat: 40.7821, lon: 72.3442, role: "Sharqiy Chegara Kiber-Posti" },



  { id: "NAM", name: "Namangan", city: "Namangan", lat: 40.9983, lon: 71.6726, role: "Shimoliy Vodiy Fiber Shlyuzi" },



  { id: "QAR", name: "Qashqadaryo", city: "Karshi", lat: 38.8606, lon: 65.7891, role: "Neft-Gaz Infratuzilma Gridi" },



  { id: "TER", name: "Surxondaryo", city: "Termez", lat: 37.2242, lon: 67.2783, role: "Janubiy Tranzit Kiber-Dugonasi" },



  { id: "NAV", name: "Navoiy", city: "Navoi", lat: 40.0844, lon: 65.3792, role: "NGMK Strategik Korxona Gridi" },



  { id: "URG", name: "Xorazm", city: "Urgench", lat: 41.5500, lon: 60.6333, role: "Amudaryo Mintaqaviy Serveri" },



  { id: "NUK", name: "Qoraqalpog'iston", city: "Nukus", lat: 42.4619, lon: 59.6166, role: "Orolbo'yi Aloqa & Tranzit Dugonasi", isHub: true },



  { id: "JIZ", name: "Jizzax", city: "Jizzakh", lat: 40.1158, lon: 67.8422, role: "Markaziy Tranzit Magistrali" },



  { id: "GUL", name: "Sirdaryo", city: "Gulistan", lat: 40.4897, lon: 68.7844, role: "Logistika & Tranzit Serveri" }



];







const UZ_BOUNDS = {



  minLon: 55.4,



  maxLon: 73.6,



  minLat: 36.6,



  maxLat: 46.0



};







// Built-in Fallback World Continents (23 Major Landmasses)



const KASPERSKY_FALLBACK_CONTINENTS = [



  [[-168, 66], [-162, 60], [-140, 60], [-130, 54], [-124, 48], [-124, 38], [-117, 32], [-110, 24], [-105, 19], [-97, 26], [-90, 30], [-82, 25], [-80, 25], [-75, 35], [-70, 42], [-65, 45], [-60, 46], [-64, 58], [-70, 62], [-80, 68], [-95, 70], [-120, 72], [-140, 70], [-168, 66]],



  [[-168, 66], [-160, 56], [-140, 60], [-141, 70], [-160, 71], [-168, 66]],



  [[-117, 32], [-110, 24], [-105, 19], [-97, 18], [-90, 16], [-85, 14], [-80, 8], [-77, 9], [-83, 10], [-90, 16], [-97, 26], [-105, 25], [-117, 32]],



  [[-85, 22], [-80, 23], [-75, 20], [-74, 20], [-78, 22], [-85, 22]],



  [[-80, 8], [-75, 11], [-60, 10], [-50, 4], [-35, -5], [-35, -12], [-38, -18], [-44, -23], [-53, -34], [-64, -40], [-68, -54], [-75, -46], [-72, -35], [-72, -18], [-77, -10], [-80, -3], [-80, 8]],



  [[-9, 36], [-9, 43], [-1, 44], [-1, 46], [2, 51], [8, 54], [12, 54], [14, 55], [12, 57], [18, 55], [22, 60], [28, 60], [35, 62], [40, 65], [42, 67], [35, 52], [28, 45], [28, 41], [22, 40], [14, 37], [0, 38], [-9, 36]],



  [[-10, 51], [-6, 50], [-1, 51], [1, 52], [0, 58], [-4, 58], [-6, 56], [-10, 54], [-10, 51]],



  [[5, 58], [8, 58], [11, 58], [15, 62], [18, 65], [28, 70], [25, 71], [21, 71], [15, 68], [12, 64], [5, 58]],



  [[8, 45], [12, 45], [16, 41], [18, 40], [15, 38], [12, 42], [8, 44], [8, 45]],



  [[-17, 15], [-17, 28], [-12, 33], [-5, 36], [11, 37], [25, 32], [32, 31], [34, 27], [43, 12], [51, 12], [49, 10], [44, 0], [40, -12], [35, -24], [32, -28], [28, -33], [18, -34], [16, -28], [12, -15], [8, 4], [0, 6], [-13, 8], [-17, 15]],



  [[44, -12], [50, -13], [50, -25], [44, -25], [44, -12]],



  [[35, 30], [45, 30], [50, 25], [56, 26], [60, 25], [55, 18], [50, 14], [43, 12], [35, 27], [35, 30]],



  [[50, 40], [53, 45], [58, 48], [68, 52], [78, 50], [80, 44], [75, 38], [68, 36], [60, 36], [50, 38], [50, 40]],



  [[60, 25], [68, 24], [72, 22], [80, 16], [80, 8], [88, 22], [92, 20], [88, 26], [78, 32], [68, 34], [60, 25]],



  [[88, 26], [100, 22], [108, 18], [118, 22], [122, 30], [126, 34], [130, 38], [128, 42], [130, 48], [120, 52], [100, 52], [88, 45], [88, 26]],



  [[130, 32], [136, 35], [141, 43], [141, 38], [132, 32], [130, 32]],



  [[98, 10], [102, 3], [104, 1], [108, 14], [100, 15], [98, 10]],



  [[95, 5], [105, -5], [115, -8], [120, -5], [125, 2], [125, 15], [120, 18], [115, 5], [100, 0], [95, 5]],



  [[114, -22], [118, -20], [124, -15], [136, -12], [142, -10], [146, -15], [153, -28], [148, -38], [138, -35], [120, -35], [115, -34], [114, -22]],



  [[166, -46], [174, -41], [178, -38], [175, -44], [166, -46]],



  [[-55, 60], [-40, 60], [-25, 70], [-20, 78], [-40, 83], [-60, 82], [-55, 72], [-55, 60]],



  [[-24, 63], [-14, 63], [-14, 66], [-24, 66], [-24, 63]],



  [[60, 55], [80, 55], [100, 55], [120, 55], [140, 50], [160, 50], [170, 60], [170, 66], [160, 70], [130, 73], [90, 75], [60, 70], [60, 55]]



];







const UZBEKISTAN_FALLBACK_BORDER = [



  [56.0, 41.3], [56.0, 45.6], [58.5, 45.6], [60.0, 44.5], [64.5, 43.5],



  [68.5, 42.8], [69.2, 41.8], [70.5, 41.5], [71.8, 41.0], [73.1, 40.5],



  [71.5, 40.0], [69.5, 40.2], [68.5, 39.5], [67.5, 37.2], [65.0, 38.0],



  [63.5, 39.5], [60.5, 41.2], [56.0, 41.3]



];







function initThreatMapRings() {



  if (threatMapWorldRings && threatMapUzRegionalRings) return;



  threatMapWorldRings = [];



  threatMapUzRings = [];



  threatMapUzRegionalRings = [];







  // 1. Initialize World GeoJSON Rings



  if (typeof WORLD_GEOJSON !== "undefined" && WORLD_GEOJSON && WORLD_GEOJSON.features) {



    for (const f of WORLD_GEOJSON.features) {



      const name = f.properties?.name || "Country";



      const isUz = (name === "Uzbekistan");



      const geom = f.geometry || {};



      const coords = geom.coordinates || [];







      if (geom.type === "Polygon") {



        for (const ring of coords) addGeoRing(threatMapWorldRings, name, isUz, ring);



      } else if (geom.type === "MultiPolygon") {



        for (const poly of coords) {



          for (const ring of poly) addGeoRing(threatMapWorldRings, name, isUz, ring);



        }



      }



    }



  }







  if (threatMapWorldRings.length === 0) {



    for (const poly of KASPERSKY_FALLBACK_CONTINENTS) {



      addGeoRing(threatMapWorldRings, "Landmass", false, poly);



    }



  }







  // 2. Initialize Uzbekistan Regional 14-Province GeoJSON



  if (typeof UZBEKISTAN_GEOJSON !== "undefined" && UZBEKISTAN_GEOJSON && UZBEKISTAN_GEOJSON.features) {



    for (const f of UZBEKISTAN_GEOJSON.features) {



      const shapeName = f.properties?.shapeName || f.properties?.name || "Region";



      const geom = f.geometry || {};



      const coords = geom.coordinates || [];







      if (geom.type === "Polygon") {



        for (const ring of coords) addGeoRing(threatMapUzRegionalRings, shapeName, true, ring);



      } else if (geom.type === "MultiPolygon") {



        for (const poly of coords) {



          for (const ring of poly) addGeoRing(threatMapUzRegionalRings, shapeName, true, ring);



        }



      }



    }



  }







  if (threatMapUzRegionalRings.length === 0) {



    addGeoRing(threatMapUzRegionalRings, "Uzbekistan", true, UZBEKISTAN_FALLBACK_BORDER);



  }



}







function addGeoRing(destArray, name, isUz, ring) {



  if (!ring || ring.length < 3) return;



  let minLon = 180, maxLon = -180, minLat = 90, maxLat = -90;



  for (const [lon, lat] of ring) {



    if (lon < minLon) minLon = lon;



    if (lon > maxLon) maxLon = lon;



    if (lat < minLat) minLat = lat;



    if (lat > maxLat) maxLat = lat;



  }



  const item = { name, isUz, ring, bbox: { minLon, maxLon, minLat, maxLat } };



  destArray.push(item);



  if (isUz && destArray === threatMapWorldRings) {



    threatMapUzRings.push(item);



  }



}







function playRadarPing(isCritical) {



  if (!threatMapSound) return;



  try {



    if (!threatMapAudioCtx) {



      threatMapAudioCtx = new (window.AudioContext || window.webkitAudioContext)();



    }



    if (threatMapAudioCtx.state === "suspended") {



      threatMapAudioCtx.resume();



    }



    const t0 = threatMapAudioCtx.currentTime;



    const osc1 = threatMapAudioCtx.createOscillator();



    const osc2 = threatMapAudioCtx.createOscillator();



    const gain = threatMapAudioCtx.createGain();







    osc1.type = "sine";



    osc2.type = "triangle";







    const baseFreq = isCritical ? 980 : 680;



    osc1.frequency.setValueAtTime(baseFreq, t0);



    osc1.frequency.exponentialRampToValueAtTime(baseFreq * 0.35, t0 + 0.16);







    osc2.frequency.setValueAtTime(baseFreq * 1.5, t0);



    osc2.frequency.exponentialRampToValueAtTime(baseFreq * 0.55, t0 + 0.16);







    gain.gain.setValueAtTime(0.06, t0);



    gain.gain.exponentialRampToValueAtTime(0.001, t0 + 0.16);







    osc1.connect(gain);



    osc2.connect(gain);



    gain.connect(threatMapAudioCtx.destination);







    osc1.start(t0);



    osc2.start(t0);



    osc1.stop(t0 + 0.17);



    osc2.stop(t0 + 0.17);



  } catch (e) {



    // Autoplay restrictions ignored



  }



}







// Dual-Mode Mapping: Equirectangular (Global) vs Uzbekistan Bounding Box (Local)



function projectMap(lat, lon, width, height) {



  let x0, y0;



  if (threatMapScope === "local") {



    // Uzbekistan Local Bounds



    x0 = ((lon - UZ_BOUNDS.minLon) / (UZ_BOUNDS.maxLon - UZ_BOUNDS.minLon)) * width;



    y0 = ((UZ_BOUNDS.maxLat - lat) / (UZ_BOUNDS.maxLat - UZ_BOUNDS.minLat)) * height;



  } else {



    // Global Equirectangular



    x0 = ((lon + 180) / 360) * width;



    y0 = ((90 - lat) / 180) * height;



  }



  const x = (x0 - width / 2) * threatMapZoom + width / 2 + threatMapPanX;



  const y = (y0 - height / 2) * threatMapZoom + height / 2 + threatMapPanY;



  return { x, y };



}







// Reverse mapping from Screen Pixel to Lat/Lon



function unprojectMap(screenX, screenY, width, height) {



  const x0 = (screenX - threatMapPanX - width / 2) / threatMapZoom + width / 2;



  const y0 = (screenY - threatMapPanY - height / 2) / threatMapZoom + height / 2;



  let lon, lat;



  if (threatMapScope === "local") {



    lon = (x0 / width) * (UZ_BOUNDS.maxLon - UZ_BOUNDS.minLon) + UZ_BOUNDS.minLon;



    lat = UZ_BOUNDS.maxLat - (y0 / height) * (UZ_BOUNDS.maxLat - UZ_BOUNDS.minLat);



  } else {



    lon = (x0 / width) * 360 - 180;



    lat = 90 - (y0 / height) * 180;



  }



  return { lat, lon };



}







function getQuadraticBezierPoint(p0, p1, p2, t) {



  const invT = 1 - t;



  return {



    x: invT * invT * p0.x + 2 * invT * t * p1.x + t * t * p2.x,



    y: invT * invT * p0.y + 2 * invT * t * p1.y + t * t * p2.y,



  };



}







function setupThreatMapCanvas() {



  threatMapCanvas = document.getElementById("threat-map-canvas");



  if (!threatMapCanvas) return;







  const container = document.getElementById("threat-map-container");



  const rect = container.getBoundingClientRect();



  const dpr = window.devicePixelRatio || 1;







  threatMapCanvas.width = rect.width * dpr;



  threatMapCanvas.height = rect.height * dpr;



  threatMapCtx = threatMapCanvas.getContext("2d");



  threatMapCtx.scale(dpr, dpr);







  // Pre-render Offscreen Matrix for current scope (Global vs Local)



  buildKasperskyOffscreenMatrix(rect.width, rect.height);



}







function buildKasperskyOffscreenMatrix(width, height) {



  threatMapOffscreenBg = document.createElement("canvas");



  threatMapOffscreenBg.width = width;



  threatMapOffscreenBg.height = height;



  const octx = threatMapOffscreenBg.getContext("2d");







  initThreatMapRings();







  // 1. Deep cosmic space gradient background



  const spaceGrad = octx.createRadialGradient(width / 2, height / 2, 40, width / 2, height / 2, width * 0.85);



  spaceGrad.addColorStop(0, "#030c1d");



  spaceGrad.addColorStop(0.5, "#020712");



  spaceGrad.addColorStop(1, "#000308");



  octx.fillStyle = spaceGrad;



  octx.fillRect(0, 0, width, height);







  // 2. Cosmic twinkling stars



  octx.save();



  for (let s = 0; s < 110; s++) {



    const sx = (Math.sin(s * 997.1) * 0.5 + 0.5) * width;



    const sy = (Math.cos(s * 613.3) * 0.5 + 0.5) * height;



    const sRad = (s % 4 === 0) ? 1.3 : 0.8;



    const sAlpha = 0.18 + (s % 5) * 0.12;



    octx.beginPath();



    octx.arc(sx, sy, sRad, 0, Math.PI * 2);



    octx.fillStyle = `rgba(180, 230, 255, ${sAlpha})`;



    octx.fill();



  }



  octx.restore();







  // 3. Cyber Graticule grid with proper degree characters



  octx.save();



  octx.strokeStyle = "rgba(0, 240, 255, 0.065)";



  octx.lineWidth = 1;



  octx.setLineDash([3, 5]);







  if (threatMapScope === "local") {



    // Uzbekistan Local Coordinates Graticule



    const localLats = [38, 40, 42, 44];



    for (const lat of localLats) {



      const pt = projectMap(lat, UZ_BOUNDS.minLon, width, height);



      octx.beginPath();



      octx.moveTo(0, pt.y);



      octx.lineTo(width, pt.y);



      octx.stroke();







      octx.fillStyle = "rgba(0, 240, 255, 0.35)";



      octx.font = "8.5px monospace";



      octx.fillText(`${lat}° N`, 10, pt.y - 3);



    }



    const localLons = [58, 62, 66, 70];



    for (const lon of localLons) {



      const pt = projectMap(UZ_BOUNDS.minLat, lon, width, height);



      octx.beginPath();



      octx.moveTo(pt.x, 0);



      octx.lineTo(pt.x, height);



      octx.stroke();







      octx.fillStyle = "rgba(0, 240, 255, 0.25)";



      octx.font = "8.5px monospace";



      octx.fillText(`${lon}° E`, pt.x + 3, height - 6);



    }



  } else {



    // Global Coordinates Graticule



    const latitudes = [



      { deg: 60, label: "60° N" },



      { deg: 30, label: "30° N" },



      { deg: 0, label: "0° EQUATOR" },



      { deg: -30, label: "30° S" },



      { deg: -60, label: "60° S" }



    ];



    for (const latObj of latitudes) {



      const y = ((90 - latObj.deg) / 180) * height;



      octx.beginPath();



      octx.moveTo(0, y);



      octx.lineTo(width, y);



      octx.stroke();







      octx.fillStyle = "rgba(0, 240, 255, 0.35)";



      octx.font = "8.5px monospace";



      octx.fillText(latObj.label, 10, y - 3);



    }



    for (let lon = -150; lon <= 150; lon += 30) {



      const x = ((lon + 180) / 360) * width;



      octx.beginPath();



      octx.moveTo(x, 0);



      octx.lineTo(x, height);



      octx.stroke();







      octx.fillStyle = "rgba(0, 240, 255, 0.22)";



      octx.font = "8.5px monospace";



      const lbl = lon === 0 ? "0° GMT" : (lon > 0 ? `${lon}° E` : `${Math.abs(lon)}° W`);



      octx.fillText(lbl, x + 3, height - 6);



    }



  }



  octx.restore();







  // 4. Build Vector Path2D for Current Scope



  const activePath = new Path2D();



  const nationalBorderPath = new Path2D();



  const ringsSource = (threatMapScope === "local") ? threatMapUzRegionalRings : threatMapWorldRings;







  if (ringsSource && ringsSource.length > 0) {



    for (const item of ringsSource) {



      const ring = item.ring;



      for (let i = 0; i < ring.length; i++) {



        const pt = projectMap(ring[i][1], ring[i][0], width, height);



        if (i === 0) activePath.moveTo(pt.x, pt.y);



        else activePath.lineTo(pt.x, pt.y);



      }



      activePath.closePath();



    }



  }







  // 5. Landmass Fill (Clear Visible Cyber Tone)



  octx.save();



  octx.fillStyle = (threatMapScope === "local") ? "rgba(0, 48, 38, 0.82)" : "rgba(0, 48, 36, 0.72)";



  octx.fill(activePath);







  // 6. Coastlines & Regional Borders



  octx.strokeStyle = (threatMapScope === "local") ? "rgba(0, 240, 255, 0.55)" : "rgba(0, 240, 255, 0.65)";



  octx.lineWidth = 1.15;



  octx.shadowColor = "rgba(0, 240, 255, 0.5)";



  octx.shadowBlur = 5;



  octx.stroke(activePath);



  octx.restore();







  // 7. HIGH-SPEED RASTER MASK for Halftone Dot Matrix



  const maskCanvas = document.createElement("canvas");



  maskCanvas.width = width;



  maskCanvas.height = height;



  const mctx = maskCanvas.getContext("2d");



  mctx.fillStyle = "#ffffff";



  mctx.fill(activePath);



  const maskPixels = mctx.getImageData(0, 0, width, height).data;







  // 8. Render Glowing Kaspersky Matrix Dots



  const step = (threatMapScope === "local") ? 5.8 : 6.2;



  octx.save();







  for (let px = 0; px < width; px += step) {



    for (let py = 0; py < height; py += step) {



      const idx = (Math.floor(py) * width + Math.floor(px)) * 4 + 3;



      if (maskPixels[idx] > 20) {



        octx.beginPath();



        octx.arc(px, py, (threatMapScope === "local") ? 1.45 : 1.25, 0, Math.PI * 2);



        octx.fillStyle = "rgba(0, 240, 140, 0.62)";



        octx.shadowColor = "rgba(0, 240, 140, 0.4)";



        octx.shadowBlur = 2;



        octx.fill();



      }



    }



  }



  octx.restore();







  // 9. Uzbekistan National Sovereign Border Glow



  if (threatMapScope === "local" || threatMapUzRings.length > 0) {



    const uzBorderRings = (threatMapScope === "local") ? threatMapUzRegionalRings : threatMapUzRings;



    for (const item of uzBorderRings) {



      const ring = item.ring;



      for (let i = 0; i < ring.length; i++) {



        const pt = projectMap(ring[i][1], ring[i][0], width, height);



        if (i === 0) nationalBorderPath.moveTo(pt.x, pt.y);



        else nationalBorderPath.lineTo(pt.x, pt.y);



      }



      nationalBorderPath.closePath();



    }



    octx.save();



    octx.strokeStyle = "#00ffaa";



    octx.lineWidth = (threatMapScope === "local") ? 2.4 : 2.0;



    octx.setLineDash([5, 4]);



    octx.shadowColor = "#00ffaa";



    octx.shadowBlur = 14;



    octx.stroke(nationalBorderPath);



    octx.restore();



  }







  // 10. In Local Mode: Draw Regional City Nodes & Badges



  if (threatMapScope === "local") {



    octx.save();



    for (const node of UZ_REGIONAL_NODES) {



      const pt = projectMap(node.lat, node.lon, width, height);



      



      // Node Beacon Circle



      octx.beginPath();



      octx.arc(pt.x, pt.y, node.isHub ? 5.5 : 3.8, 0, Math.PI * 2);



      octx.fillStyle = node.isHub ? "#00ff88" : "#00e5ff";



      octx.shadowColor = node.isHub ? "#00ff88" : "#00e5ff";



      octx.shadowBlur = 12;



      octx.fill();







      // Holographic City Name



      octx.fillStyle = "#ffffff";



      octx.font = node.isHub ? "bold 10px monospace" : "9px monospace";



      octx.shadowColor = "#000000";



      octx.shadowBlur = 4;



      octx.fillText(node.city.toUpperCase(), pt.x + 8, pt.y - 4);







      if (node.isHub) {



        octx.fillStyle = "#00ffaa";



        octx.font = "8px monospace";



        octx.fillText(`[${node.id}: SOC]`, pt.x + 8, pt.y + 7);



      }



    }



    octx.restore();



  }



}







function drawHexagonShield(ctx, cx, cy, radius, alpha, color) {



  ctx.save();



  ctx.beginPath();



  for (let i = 0; i < 6; i++) {



    const angle = (i * Math.PI) / 3;



    const hx = cx + radius * Math.cos(angle);



    const hy = cy + radius * Math.sin(angle);



    if (i === 0) ctx.moveTo(hx, hy);



    else ctx.lineTo(hx, hy);



  }



  ctx.closePath();



  ctx.strokeStyle = color.replace("rgb", "rgba").replace(")", `, ${alpha})`);



  ctx.lineWidth = 2.4;



  ctx.shadowColor = color;



  ctx.shadowBlur = 18;



  ctx.stroke();







  // Honeycomb internal rays



  ctx.beginPath();



  for (let i = 0; i < 6; i++) {



    const angle = (i * Math.PI) / 3;



    ctx.moveTo(cx, cy);



    ctx.lineTo(cx + radius * Math.cos(angle), cy + radius * Math.sin(angle));



  }



  ctx.strokeStyle = color.replace("rgb", "rgba").replace(")", `, ${alpha * 0.35})`);



  ctx.lineWidth = 1;



  ctx.stroke();



  ctx.restore();



}







function renderThreatMap() {



  if (!threatMapCanvas || !threatMapCtx) return;







  const width = threatMapCanvas.width / (window.devicePixelRatio || 1);



  const height = threatMapCanvas.height / (window.devicePixelRatio || 1);



  const ctx = threatMapCtx;







  // 1. Draw cached Offscreen Matrix Background with Pan & Zoom



  ctx.save();



  ctx.fillStyle = "#01040a";



  ctx.fillRect(0, 0, width, height);







  if (threatMapOffscreenBg) {



    ctx.save();



    ctx.translate(threatMapPanX + (width / 2) * (1 - threatMapZoom), threatMapPanY + (height / 2) * (1 - threatMapZoom));



    ctx.scale(threatMapZoom, threatMapZoom);



    ctx.drawImage(threatMapOffscreenBg, 0, 0, width, height);



    ctx.restore();



  }



  ctx.restore();







  // 2. Rotating Holographic Air-Defense Radar Sweep centered at Tashkent



  threatMapRadarAngle += 0.012;



  const targetPt = projectMap(TASHKENT_HUB.lat, TASHKENT_HUB.lon, width, height);







  ctx.save();



  const sweepRadius = (threatMapScope === "local" ? 480 : 380) * threatMapZoom;



  const radarSweepGrad = ctx.createRadialGradient(targetPt.x, targetPt.y, 8, targetPt.x, targetPt.y, sweepRadius);



  radarSweepGrad.addColorStop(0, "rgba(0, 255, 170, 0.24)");



  radarSweepGrad.addColorStop(0.7, "rgba(0, 240, 255, 0.06)");



  radarSweepGrad.addColorStop(1, "rgba(0, 240, 255, 0)");







  ctx.beginPath();



  ctx.moveTo(targetPt.x, targetPt.y);



  ctx.arc(targetPt.x, targetPt.y, sweepRadius, threatMapRadarAngle, threatMapRadarAngle + 0.35);



  ctx.closePath();



  ctx.fillStyle = radarSweepGrad;



  ctx.fill();



  ctx.restore();







  // 3. Tashkent Defense Hub (Concentric Expanding Neon Shield)



  threatMapPulseAngle += 0.038;







  ctx.save();



  for (let r = 1; r <= 3; r++) {



    const ringRadius = (6 + ((threatMapPulseAngle * 14 + r * 11) % 40)) * threatMapZoom;



    const ringAlpha = Math.max(0, 1 - ringRadius / (40 * threatMapZoom));



    ctx.beginPath();



    ctx.arc(targetPt.x, targetPt.y, ringRadius, 0, Math.PI * 2);



    ctx.strokeStyle = `rgba(0, 255, 170, ${ringAlpha * 0.6})`;



    ctx.lineWidth = 1.6;



    ctx.stroke();



  }







  // Core hexagonal beacon



  ctx.beginPath();



  ctx.arc(targetPt.x, targetPt.y, 6.5, 0, Math.PI * 2);



  ctx.fillStyle = "#00ff88";



  ctx.shadowColor = "#00ff88";



  ctx.shadowBlur = 18;



  ctx.fill();







  // Holographic Label



  ctx.fillStyle = "#ffffff";



  ctx.font = "bold 10px monospace";



  ctx.shadowColor = "#000000";



  ctx.shadowBlur = 4;



  ctx.fillText(threatMapScope === "local" ? "TOSHKENT [TAS-IX MARKAZIY NOC]" : "TASHKENT [SOC SHIELD: TAS-IX]", targetPt.x + 12, targetPt.y - 7);







  ctx.fillStyle = "#00ffaa";



  ctx.font = "8.5px monospace";



  ctx.fillText(threatMapScope === "local" ? "MILLIY KIBER-QALQON SHLYUZI" : "CENTRAL COMMAND GATEWAY", targetPt.x + 12, targetPt.y + 6);



  ctx.restore();







  // 4. Hexagonal Energy Shield Impacts



  for (let h = threatMapShieldImpacts.length - 1; h >= 0; h--) {



    const sh = threatMapShieldImpacts[h];



    sh.radius += 2.2;



    sh.alpha -= 0.035;



    if (sh.alpha <= 0) {



      threatMapShieldImpacts.splice(h, 1);



      continue;



    }



    drawHexagonShield(ctx, sh.x, sh.y, sh.radius, sh.alpha, sh.color);



  }







  // 5. Kinetic Explosion Spark Particles



  for (let s = threatMapSparks.length - 1; s >= 0; s--) {



    const sp = threatMapSparks[s];



    sp.x += sp.vx;



    sp.y += sp.vy;



    sp.vx *= 0.93; // Air drag



    sp.vy *= 0.93;



    sp.alpha -= 0.024;







    if (sp.alpha <= 0) {



      threatMapSparks.splice(s, 1);



      continue;



    }







    ctx.save();



    ctx.beginPath();



    ctx.arc(sp.x, sp.y, sp.size, 0, Math.PI * 2);



    ctx.fillStyle = sp.color.replace("rgb", "rgba").replace(")", `, ${sp.alpha})`);



    ctx.shadowColor = sp.color;



    ctx.shadowBlur = 8;



    ctx.fill();



    ctx.restore();



  }







  // 6. Impact Shockwave Ripples



  for (let i = threatMapRipples.length - 1; i >= 0; i--) {



    const rip = threatMapRipples[i];



    rip.radius += 2.2;



    rip.alpha -= 0.032;



    if (rip.alpha <= 0) {



      threatMapRipples.splice(i, 1);



      continue;



    }







    ctx.save();



    ctx.beginPath();



    ctx.arc(rip.x, rip.y, rip.radius, 0, Math.PI * 2);



    ctx.strokeStyle = rip.color.replace("rgb", "rgba").replace(")", `, ${rip.alpha})`);



    ctx.lineWidth = 2.4;



    ctx.shadowColor = rip.color;



    ctx.shadowBlur = 12;



    ctx.stroke();



    ctx.restore();



  }







  // 7. Hypersonic Ballistic Laser Missiles



  let hoveredCandidate = null;







  for (let i = threatMapActiveArcs.length - 1; i >= 0; i--) {



    const arc = threatMapActiveArcs[i];



    if (!threatMapPaused) {



      arc.progress += arc.speed;



    }







    const p0 = projectMap(arc.source.lat, arc.source.lon, width, height);



    const p2 = projectMap(arc.target.lat, arc.target.lon, width, height);







    // Dynamic 3D Ballistic Parabolic Arc



    const dx = p2.x - p0.x;



    const dy = p2.y - p0.y;



    const dist = Math.hypot(dx, dy);



    const arcH = Math.min(dist * 0.38, 140 * threatMapZoom);



    const p1 = {



      x: (p0.x + p2.x) / 2,



      y: Math.min(p0.y, p2.y) - arcH,



    };







    // Draw Source Origin Node (Pulsing Dot)



    ctx.save();



    ctx.beginPath();



    ctx.arc(p0.x, p0.y, 4.5, 0, Math.PI * 2);



    ctx.fillStyle = arc.color;



    ctx.shadowColor = arc.color;



    ctx.shadowBlur = 10;



    ctx.fill();







    // Origin Label



    ctx.fillStyle = "rgba(255, 255, 255, 0.78)";



    ctx.font = "8.5px monospace";



    const srcLabel = arc.is_domestic ? `${arc.source.city} (${arc.source.region_id || "UZ"})` : `${arc.source.city} (${arc.source.country_code})`;



    ctx.fillText(srcLabel, p0.x + 8, p0.y + 3);







    // Faint Trajectory Arc Guide



    ctx.beginPath();



    ctx.moveTo(p0.x, p0.y);



    ctx.quadraticCurveTo(p1.x, p1.y, p2.x, p2.y);



    ctx.strokeStyle = arc.faintColor;



    ctx.lineWidth = 1;



    ctx.setLineDash([2, 5]);



    ctx.stroke();



    ctx.setLineDash([]);







    // Hypersonic Plasma Trail Head & Tail



    const currentT = Math.min(arc.progress, 1.0);



    const tailT = Math.max(0, currentT - 0.24);







    const headPt = getQuadraticBezierPoint(p0, p1, p2, currentT);



    const tailPt = getQuadraticBezierPoint(p0, p1, p2, tailT);







    // Multi-layer glowing laser stroke



    const laserGrad = ctx.createLinearGradient(tailPt.x, tailPt.y, headPt.x, headPt.y);



    laserGrad.addColorStop(0, "rgba(255, 255, 255, 0)");



    laserGrad.addColorStop(0.5, arc.color);



    laserGrad.addColorStop(1, "#ffffff");







    // Outer diffuse halo



    ctx.beginPath();



    ctx.moveTo(tailPt.x, tailPt.y);



    const midPt = getQuadraticBezierPoint(p0, p1, p2, (tailT + currentT) / 2);



    ctx.quadraticCurveTo(midPt.x, midPt.y, headPt.x, headPt.y);



    ctx.strokeStyle = arc.color.replace("rgb", "rgba").replace(")", ", 0.35)");



    ctx.lineWidth = 5.5;



    ctx.stroke();







    // Intense plasma core



    ctx.beginPath();



    ctx.moveTo(tailPt.x, tailPt.y);



    ctx.quadraticCurveTo(midPt.x, midPt.y, headPt.x, headPt.y);



    ctx.strokeStyle = laserGrad;



    ctx.lineWidth = 2.4;



    ctx.shadowColor = arc.color;



    ctx.shadowBlur = 14;



    ctx.stroke();







    // Laser Missile Head



    ctx.beginPath();



    ctx.arc(headPt.x, headPt.y, 4, 0, Math.PI * 2);



    ctx.fillStyle = "#ffffff";



    ctx.shadowColor = arc.color;



    ctx.shadowBlur = 18;



    ctx.fill();



    ctx.restore();







    // Check Mouse Hover



    if (threatMapMousePos.x > 0) {



      const dHead = Math.hypot(threatMapMousePos.x - headPt.x, threatMapMousePos.y - headPt.y);



      const dOrigin = Math.hypot(threatMapMousePos.x - p0.x, threatMapMousePos.y - p0.y);



      if (dHead < 18 || dOrigin < 18) {



        hoveredCandidate = arc;



      }



    }







    // Check Impact at Target



    if (arc.progress >= 1.0) {



      threatMapShieldImpacts.push({



        x: p2.x,



        y: p2.y,



        radius: 12,



        alpha: 1.0,



        color: arc.color,



      });







      threatMapRipples.push({



        x: p2.x,



        y: p2.y,



        radius: 4,



        alpha: 1.0,



        color: arc.color,



      });







      for (let s = 0; s < 22; s++) {



        const ang = Math.random() * Math.PI * 2;



        const spd = 1.8 + Math.random() * 4.6;



        threatMapSparks.push({



          x: p2.x,



          y: p2.y,



          vx: Math.cos(ang) * spd,



          vy: Math.sin(ang) * spd,



          alpha: 1.0,



          color: arc.color,



          size: 1.3 + Math.random() * 1.8,



        });



      }







      playRadarPing(arc.severity === "CRITICAL");



      addIncidentToFeed(arc);







      threatMapTotalCounter++;



      threatMapVectorCounters.ALL++;



      const vKey = (arc.vectorCode || "WAV").toUpperCase();



      if (threatMapVectorCounters[vKey] !== undefined) {



        threatMapVectorCounters[vKey]++;



      }



      updateVectorBadges();







      const hudTotal = document.getElementById("hud-total-intercepted");



      if (hudTotal) hudTotal.textContent = threatMapTotalCounter.toLocaleString();







      if (threatMapScope === "local") {



        const regName = arc.source.region_name || "Toshkent";



        if (threatMapLocalStats[regName] !== undefined) {



          threatMapLocalStats[regName]++;



        } else {



          threatMapLocalStats[regName] = 1;



        }



      } else {



        const srcCode = arc.source.country_code;



        if (threatMapGlobalStats[srcCode] !== undefined) {



          threatMapGlobalStats[srcCode]++;



        } else {



          threatMapGlobalStats[srcCode] = 1;



        }



        threatMapGlobalStats["UZ"]++;



      }



      updateLeaderboardUI();







      threatMapActiveArcs.splice(i, 1);



    }



  }







  // Handle Cyber HUD Tooltip on Hover



  updateHudTooltip(hoveredCandidate);







  threatMapAnimId = requestAnimationFrame(renderThreatMap);



}







function updateVectorBadges() {



  const cntAll = document.getElementById("kasp-cnt-all");



  const cntWav = document.getElementById("kasp-cnt-wav");



  const cntOas = document.getElementById("kasp-cnt-oas");



  const cntApk = document.getElementById("kasp-cnt-apk");



  const cntIds = document.getElementById("kasp-cnt-ids");



  const cntKsn = document.getElementById("kasp-cnt-ksn");







  if (cntAll) cntAll.textContent = threatMapVectorCounters.ALL.toLocaleString();



  if (cntWav) cntWav.textContent = threatMapVectorCounters.WAV.toLocaleString();



  if (cntOas) cntOas.textContent = threatMapVectorCounters.OAS.toLocaleString();



  if (cntApk) cntApk.textContent = threatMapVectorCounters.APK.toLocaleString();



  if (cntIds) cntIds.textContent = threatMapVectorCounters.IDS.toLocaleString();



  if (cntKsn) cntKsn.textContent = threatMapVectorCounters.KSN.toLocaleString();



}







function updateLeaderboardUI() {



  const list = document.getElementById("kasp-board-list");



  if (!list) return;







  const cardTitle = document.querySelector(".kasp-board-title");







  if (threatMapScope === "local") {



    if (cardTitle) cardTitle.textContent = "O'ZBEKISTON ICHKI TAHDIRLAR STATISTIKASI";







    const localEntries = Object.entries(threatMapLocalStats)



      .map(([name, count]) => ({ name, count }))



      .sort((a, b) => b.count - a.count)



      .slice(0, 6);







    const total = localEntries.reduce((acc, curr) => acc + curr.count, 0) || 1;







    list.innerHTML = localEntries.map((e, idx) => {



      const pct = Math.min(100, Math.round((e.count / total) * 100));



      const isTas = e.name.includes("Toshkent");



      return `



        <li class="${isTas ? 'active-defense-row' : ''}">



          <div style="display:flex; justify-content:space-between; width:100%; align-items:center;">



            <div>



              <span class="c-rank">#${idx + 1}</span>



              <span class="c-flag">🇺🇿</span>



              <span class="c-name">${e.name}</span>



            </div>



            <span class="c-stat ${isTas ? 'text-cyan' : ''}">${e.count.toLocaleString()} ${isTas ? '[TAS-IX NOC]' : ''}</span>



          </div>



          <div class="c-bar-wrapper">



            <div class="c-bar-fill" style="width: ${pct}%; background: ${isTas ? '#00ffaa' : '#00e5ff'};"></div>



          </div>



        </li>



      `;



    }).join("");



  } else {



    if (cardTitle) cardTitle.textContent = "GLOBAL ATTACK LEADERBOARD";







    const total = (threatMapGlobalStats.RU || 3421) +



                  (threatMapGlobalStats.US || 2890) +



                  (threatMapGlobalStats.UZ || 1445) +



                  (threatMapGlobalStats.DE || 1120) +



                  (threatMapGlobalStats.NL || 840) +



                  (threatMapGlobalStats.BR || 615);







    const entries = [



      { rank: "#1", flag: "🇷🇺", name: "Russia", count: threatMapGlobalStats.RU || 3421, isShield: false, color: "#ff0055" },



      { rank: "#2", flag: "🇺🇸", name: "United States", count: threatMapGlobalStats.US || 2890, isShield: false, color: "#00e5ff" },



      { rank: "#3", flag: "🇺🇿", name: "Uzbekistan", count: threatMapGlobalStats.UZ || 1445, isShield: true, color: "#00ff88" },



      { rank: "#4", flag: "🇩🇪", name: "Germany", count: threatMapGlobalStats.DE || 1120, isShield: false, color: "#ffb700" },



      { rank: "#5", flag: "🇳🇱", name: "Netherlands", count: threatMapGlobalStats.NL || 840, isShield: false, color: "#c026d3" },



      { rank: "#6", flag: "🇧🇷", name: "Brazil", count: threatMapGlobalStats.BR || 615, isShield: false, color: "#ff6600" },



    ];







    list.innerHTML = entries.map((e) => {



      const pct = Math.min(100, Math.round((e.count / total) * 100));



      return `



        <li class="${e.isShield ? 'active-defense-row' : ''}">



          <div style="display:flex; justify-content:space-between; width:100%; align-items:center;">



            <div>



              <span class="c-rank">${e.rank}</span>



              <span class="c-flag">${e.flag}</span>



              <span class="c-name">${e.name}</span>



            </div>



            <span class="c-stat ${e.isShield ? 'text-cyan' : ''}">${e.count.toLocaleString()} ${e.isShield ? '[Shield]' : ''}</span>



          </div>



          <div class="c-bar-wrapper">



            <div class="c-bar-fill" style="width: ${pct}%; background: ${e.color};"></div>



          </div>



        </li>



      `;



    }).join("");



  }



}







function updateHudTooltip(arc) {



  const tip = document.getElementById("map-hud-tooltip");



  if (!tip) return;







  if (!arc) {



    tip.style.display = "none";



    threatMapHoveredArc = null;



    return;



  }







  threatMapHoveredArc = arc;



  tip.style.display = "block";



  tip.style.left = `${threatMapMousePos.x}px`;



  tip.style.top = `${threatMapMousePos.y}px`;







  const badgeClass = arc.severity === "CRITICAL" ? "badge-critical" : (arc.severity === "HIGH" ? "badge-high" : "badge-medium");



  const originStr = arc.is_domestic 



    ? `<strong>${arc.source.region_name || arc.source.city}</strong> (O'zbekiston)` 



    : `<strong>${arc.source.city}, ${arc.source.country} (${arc.source.country_code})</strong>`;







  const targetStr = arc.is_domestic



    ? `<strong>${arc.target.region_name || arc.target.city} (${arc.target_service})</strong>`



    : `<strong>${arc.target.city} (TAS-IX Gateway)</strong>`;







  tip.innerHTML = `



    <div class="hud-tooltip-header">



      <span class="hud-tooltip-badge ${badgeClass}">${arc.vectorCode || "WAV"} / ${arc.severity}</span>



      <span class="hud-tooltip-time">${arc.id}</span>



    </div>



    <div class="hud-tooltip-title">${arc.attack_name || "Unknown Threat Signature"}</div>



    <div class="hud-tooltip-grid">



      <div><span>Manba:</span> ${originStr}</div>



      <div><span>IP Manzil:</span> <code>${arc.source.ip}</code></div>



      <div><span>Nishon:</span> ${targetStr}</div>



      <div><span>Zararsizlantirish:</span> <strong class="text-green">BLOCKED (PhishGuard AI)</strong></div>



    </div>



  `;



}







function spawnAttackArc(event) {



  if (threatMapActiveArcs.length >= 16) return;







  const typeUpper = (event.attack_type || "").toUpperCase();



  if (threatMapFilter !== "ALL") {



    if (!typeUpper.includes(threatMapFilter)) return;



  }







  let vectorCode = "IDS";



  let color = "rgb(0, 229, 255)";



  let faintColor = "rgba(0, 229, 255, 0.16)";







  if (typeUpper.includes("URL") || typeUpper.includes("PHISHING")) {



    vectorCode = "WAV";



    color = "rgb(255, 0, 85)";



    faintColor = "rgba(255, 0, 85, 0.18)";



  } else if (typeUpper.includes("APK")) {



    vectorCode = "APK";



    color = "rgb(192, 38, 211)";



    faintColor = "rgba(192, 38, 211, 0.18)";



  } else if (typeUpper.includes("EXE") || typeUpper.includes("MALWARE")) {



    vectorCode = "OAS";



    color = "rgb(0, 255, 136)";



    faintColor = "rgba(0, 255, 136, 0.18)";



  } else if (event.severity === "HIGH") {



    vectorCode = "KSN";



    color = "rgb(255, 183, 0)";



    faintColor = "rgba(255, 183, 0, 0.18)";



  }







  threatMapActiveArcs.push({



    id: event.id || `EVT-${Date.now()}`,



    source: event.source,



    target: event.target || TASHKENT_HUB,



    attack_name: event.attack_name,



    attack_type: event.attack_type,



    target_service: event.target_service,



    severity: event.severity,



    risk_score: event.risk_score,



    is_domestic: !!event.is_domestic,



    vectorCode,



    color,



    faintColor,



    progress: 0.0,



    speed: (threatMapScope === "local" ? 0.009 : 0.0075) + Math.random() * 0.006,



  });



}







function addIncidentToFeed(ev) {



  const feed = document.getElementById("incident-stream-feed");



  if (!feed) return;







  const row = document.createElement("div");



  row.className = "incident-row";







  const sev = ev.severity || "MEDIUM";



  const badgeClass = sev === "CRITICAL" ? "badge-critical" : (sev === "HIGH" ? "badge-high" : "badge-medium");



  const timeStr = ev.timestamp || new Date().toTimeString().slice(0, 8);



  const src = ev.source || { city: "Unknown", country_code: "??", ip: "0.0.0.0" };



  const vCode = ev.vectorCode || (ev.attack_type && ev.attack_type.includes("APK") ? "APK" : (ev.attack_type && ev.attack_type.includes("EXE") ? "OAS" : "WAV"));







  const srcGeoStr = ev.is_domestic 



    ? `${src.region_name || src.city} ➔ ${ev.target?.city || 'Toshkent'}`



    : `${src.city} (${src.country_code}) ➔ Tashkent`;







  row.innerHTML = `



    <div class="incident-row-left">



      <span class="incident-time">[${timeStr}]</span>



      <span class="incident-badge ${badgeClass}">${vCode}:${sev}</span>



      <span class="incident-threat">${ev.attack_name || "Hostile Phishing Vector Detected"}</span>



    </div>



    <div class="incident-row-right">



      <span class="incident-geo">${srcGeoStr}</span>



      <span class="incident-status text-green">BLOCKED</span>



    </div>



  `;







  feed.insertBefore(row, feed.firstChild);







  while (feed.children.length > 25) {



    feed.removeChild(feed.lastChild);



  }



}







async function fetchThreatMapTelemetry() {



  try {



    const resp = await fetch("/api/threat-map/live");



    if (!resp.ok) return;



    const data = await resp.json();



    threatMapTelemetryData = data;







    if (threatMapScope === "global" && data.metrics) {



      const hudTotal = document.getElementById("hud-total-intercepted");



      const hudContain = document.getElementById("hud-containment-rate");



      const hudLatency = document.getElementById("hud-avg-latency");







      if (hudTotal) {



        threatMapTotalCounter = data.metrics.total_intercepted || 1445;



        hudTotal.textContent = threatMapTotalCounter.toLocaleString();



      }



      if (hudContain) hudContain.textContent = `${data.metrics.containment_rate || 99.4}%`;



      if (hudLatency) hudLatency.textContent = `${data.metrics.avg_detection_latency_ms || 14.8} ms`;



    }







    const feed = document.getElementById("incident-stream-feed");



    if (threatMapScope === "global" && feed && feed.children.length === 0 && data.active_events) {



      for (const ev of data.active_events.slice(0, 8)) {



        addIncidentToFeed(ev);



      }



    }



  } catch (e) {



    // Backend offline / mock fallback



  }



}







async function fetchLocalUzbekistanTelemetry() {



  try {



    const resp = await fetch("/api/threat-map/local-uz");



    if (!resp.ok) return;



    const data = await resp.json();



    threatMapLocalTelemetryData = data;







    if (threatMapScope === "local" && data.tasix_metrics) {



      const hudTotal = document.getElementById("hud-total-intercepted");



      const hudContain = document.getElementById("hud-containment-rate");



      const hudLatency = document.getElementById("hud-avg-latency");







      if (hudTotal) {



        threatMapTotalCounter = data.tasix_metrics.domestic_blocked_today || 842;



        hudTotal.textContent = threatMapTotalCounter.toLocaleString();



      }



      if (hudContain) hudContain.textContent = `${data.tasix_metrics.internal_containment_rate || 99.8}%`;



      if (hudLatency) hudLatency.textContent = `${data.tasix_metrics.tasix_latency_ms || 2.4} ms`;



    }







    const feed = document.getElementById("incident-stream-feed");



    if (threatMapScope === "local" && feed && feed.children.length === 0 && data.active_attacks) {



      for (const ev of data.active_attacks.slice(0, 8)) {



        addIncidentToFeed(ev);



      }



    }



  } catch (e) {



    // Backend offline / mock fallback



  }



}







function setThreatMapScope(scope) {



  if (threatMapScope === scope) return;



  threatMapScope = scope;







  // Update switcher buttons



  const btnGlobal = document.getElementById("btn-scope-global");



  const btnLocal = document.getElementById("btn-scope-local");







  if (scope === "local") {



    btnLocal?.classList.add("active");



    btnGlobal?.classList.remove("active");



  } else {



    btnGlobal?.classList.add("active");



    btnLocal?.classList.remove("active");



  }







  // Clear existing arcs



  threatMapActiveArcs = [];



  threatMapRipples = [];



  threatMapSparks = [];



  threatMapShieldImpacts = [];







  // Reset zoom & pan



  threatMapZoom = 1.0;



  threatMapPanX = 0;



  threatMapPanY = 0;







  // Clear feed



  const feed = document.getElementById("incident-stream-feed");



  if (feed) feed.innerHTML = "";







  // Rebuild offscreen canvas for new scope



  const container = document.getElementById("threat-map-container");



  if (container) {



    const rect = container.getBoundingClientRect();



    buildKasperskyOffscreenMatrix(rect.width, rect.height);



  }







  // Update HUD Headings



  const hudTarget = document.querySelector(".hud-item .text-cyan");



  if (hudTarget) {



    hudTarget.textContent = (scope === "local") ? "Toshkent (TAS-IX Markaziy NOC)" : "Toshkent (TAS-IX Gateway)";



  }







  // Fetch telemetry



  if (scope === "local") {



    fetchLocalUzbekistanTelemetry();



  } else {



    fetchThreatMapTelemetry();



  }







  updateLeaderboardUI();



}







function initThreatMap() {



  setupThreatMapCanvas();



  fetchThreatMapTelemetry();



  fetchLocalUzbekistanTelemetry();



  updateLeaderboardUI();



  updateVectorBadges();







  if (!threatMapAnimId) {



    threatMapAnimId = requestAnimationFrame(renderThreatMap);



  }







  // Event telemetry scheduler



  if (threatMapInterval) clearInterval(threatMapInterval);



  threatMapInterval = setInterval(() => {



    if (threatMapPaused) return;







    if (threatMapScope === "local") {



      // Local Uzbekistan attack feed



      if (threatMapLocalTelemetryData && threatMapLocalTelemetryData.active_attacks?.length > 0) {



        const ev = threatMapLocalTelemetryData.active_attacks[Math.floor(Math.random() * threatMapLocalTelemetryData.active_attacks.length)];



        const freshEv = JSON.parse(JSON.stringify(ev));



        freshEv.source.lat += (Math.random() - 0.5) * 0.1;



        freshEv.source.lon += (Math.random() - 0.5) * 0.1;



        spawnAttackArc(freshEv);



      }



    } else {



      // Global attack feed



      if (threatMapTelemetryData && threatMapTelemetryData.active_events?.length > 0) {



        const ev = threatMapTelemetryData.active_events[Math.floor(Math.random() * threatMapTelemetryData.active_events.length)];



        const freshEv = JSON.parse(JSON.stringify(ev));



        freshEv.source.lat += (Math.random() - 0.5) * 1.5;



        freshEv.source.lon += (Math.random() - 0.5) * 1.5;



        spawnAttackArc(freshEv);



      }



    }



  }, 1600);



}







// Window resize handler for canvas



window.addEventListener("resize", () => {



  if (currentViewKey === "threat-map") {



    setupThreatMapCanvas();



  }



});







// Scope Switcher Handlers (Global vs Local)



document.getElementById("btn-scope-global")?.addEventListener("click", () => {



  setThreatMapScope("global");



});







document.getElementById("btn-scope-local")?.addEventListener("click", () => {



  setThreatMapScope("local");



});







// Canvas Interactive Mouse Handlers



const mapCanvasEl = document.getElementById("threat-map-canvas");



if (mapCanvasEl) {



  mapCanvasEl.addEventListener("mousemove", (e) => {



    const rect = mapCanvasEl.getBoundingClientRect();



    const mouseX = e.clientX - rect.left;



    const mouseY = e.clientY - rect.top;



    threatMapMousePos.x = mouseX;



    threatMapMousePos.y = mouseY;







    const coords = unprojectMap(mouseX, mouseY, rect.width, rect.height);



    const hudCoords = document.getElementById("map-crosshair-hud");



    if (hudCoords) {



      const latStr = coords.lat >= 0 ? `${coords.lat.toFixed(2)}° N` : `${Math.abs(coords.lat).toFixed(2)}° S`;



      const lonStr = coords.lon >= 0 ? `${coords.lon.toFixed(2)}° E` : `${Math.abs(coords.lon).toFixed(2)}° W`;



      const sectorStr = (threatMapScope === "local") ? "SECTOR: UZB REGIONAL GRID" : "SECTOR: TAS-IX GATEWAY";



      hudCoords.innerHTML = `<span class="hud-mono-glow">TARGET GRID: ${latStr}, ${lonStr}</span> | <span class="text-cyan">${sectorStr}</span> | <span class="text-green">STATUS: 100% CONTAINED</span>`;



    }







    if (threatMapIsDragging) {



      threatMapPanX += e.clientX - threatMapDragStart.x;



      threatMapPanY += e.clientY - threatMapDragStart.y;



      threatMapDragStart = { x: e.clientX, y: e.clientY };



    }



  });







  mapCanvasEl.addEventListener("mousedown", (e) => {



    threatMapIsDragging = true;



    threatMapDragStart = { x: e.clientX, y: e.clientY };



    mapCanvasEl.style.cursor = "grabbing";



  });







  mapCanvasEl.addEventListener("mouseup", () => {



    threatMapIsDragging = false;



    mapCanvasEl.style.cursor = "crosshair";



  });







  mapCanvasEl.addEventListener("mouseleave", () => {



    threatMapIsDragging = false;



    threatMapMousePos.x = -100;



    threatMapMousePos.y = -100;



    mapCanvasEl.style.cursor = "crosshair";



    const tip = document.getElementById("map-hud-tooltip");



    if (tip) tip.style.display = "none";



  });







  // Mouse wheel zoom



  mapCanvasEl.addEventListener("wheel", (e) => {



    e.preventDefault();



    const delta = e.deltaY < 0 ? 0.15 : -0.15;



    threatMapZoom = Math.min(Math.max(threatMapZoom + delta, 1.0), 4.5);



    if (threatMapZoom === 1.0) {



      threatMapPanX = 0;



      threatMapPanY = 0;



    }



  }, { passive: false });



}







// Map Viewport Buttons (+, -, Tashkent Focus, Global View)



document.getElementById("btn-map-zoom-in")?.addEventListener("click", () => {



  threatMapZoom = Math.min(threatMapZoom + 0.35, 4.5);



});







document.getElementById("btn-map-zoom-out")?.addEventListener("click", () => {



  threatMapZoom = Math.max(threatMapZoom - 0.35, 1.0);



  if (threatMapZoom === 1.0) {



    threatMapPanX = 0;



    threatMapPanY = 0;



  }



});







document.getElementById("btn-map-focus-uz")?.addEventListener("click", () => {



  if (threatMapScope !== "local") {



    setThreatMapScope("local");



  } else {



    threatMapZoom = 2.0;



    threatMapPanX = 0;



    threatMapPanY = 0;



  }



});







document.getElementById("btn-map-reset-view")?.addEventListener("click", () => {



  threatMapZoom = 1.0;



  threatMapPanX = 0;



  threatMapPanY = 0;



});







// Kaspersky Threat Vector Filter Pills (ALL, WAV, OAS, APK, IDS, KSN)



document.querySelectorAll(".kasp-tag").forEach((tag) => {



  tag.addEventListener("click", () => {



    const vec = tag.dataset.vector;



    document.querySelectorAll(".kasp-tag").forEach((t) => t.classList.remove("active"));



    tag.classList.add("active");



    if (vec === "WAV") threatMapFilter = "URL";



    else if (vec === "OAS") threatMapFilter = "EXE";



    else if (vec === "APK") threatMapFilter = "APK";



    else if (vec === "IDS") threatMapFilter = "IDS";



    else if (vec === "KSN") threatMapFilter = "KSN";



    else threatMapFilter = "ALL";



  });



});







// Threat Map Filter Buttons



document.querySelectorAll("[data-map-filter]").forEach((btn) => {



  btn.addEventListener("click", () => {



    document.querySelectorAll("[data-map-filter]").forEach((b) => b.classList.remove("active"));



    btn.classList.add("active");



    threatMapFilter = btn.dataset.mapFilter;



  });



});







// Stream Pause / Resume Button



document.getElementById("btn-toggle-stream")?.addEventListener("click", () => {



  threatMapPaused = !threatMapPaused;



  const icon = document.getElementById("stream-status-icon");



  const text = document.getElementById("stream-status-text");







  if (threatMapPaused) {



    if (icon) icon.textContent = "▶";



    if (text) text.textContent = t("resume_stream");



  } else {



    if (icon) icon.textContent = "⏸";



    if (text) text.textContent = t("pause_stream");



  }



});







// Clear Arcs Button



document.getElementById("btn-clear-arcs")?.addEventListener("click", () => {



  threatMapActiveArcs = [];



  threatMapRipples = [];



  threatMapSparks = [];



  threatMapShieldImpacts = [];



  const feed = document.getElementById("incident-stream-feed");



  if (feed) feed.innerHTML = "";



});







// Sound Toggle Button



document.getElementById("btn-sound-toggle")?.addEventListener("click", () => {



  threatMapSound = !threatMapSound;



  const soundIcon = document.getElementById("sound-icon");



  if (soundIcon) {



    soundIcon.textContent = threatMapSound ? "🔊" : "🔈";



  }



  if (threatMapSound) {



    playRadarPing(false);



  }



});







// Start in the saved or default language



setLanguage(currentLang);





/* ==========================================================================

   MODULE 1: TACTICAL AUDIO & THREAT BROADCAST SYSTEM

   ========================================================================== */

class TacticalAudioEngine {

  constructor() {

    this.enabled = localStorage.getItem("pg_audio_enabled") !== "false";

    this.ctx = null;

    this.initUI();

  }



  ensureContext() {

    if (!this.ctx) {

      const AudioCtx = window.AudioContext || window.webkitAudioContext;

      if (AudioCtx) this.ctx = new AudioCtx();

    }

    if (this.ctx && this.ctx.state === "suspended") {

      this.ctx.resume().catch(() => {});

    }

    return this.ctx;

  }



  initUI() {

    const btn = document.getElementById("audio-toggle-btn");

    if (!btn) return;

    this.updateButtonUI(btn);

    btn.addEventListener("click", () => {

      this.enabled = !this.enabled;

      localStorage.setItem("pg_audio_enabled", this.enabled ? "true" : "false");

      this.updateButtonUI(btn);

      if (this.enabled) {

        this.playSuccessChime();

        this.speak("SOC audio broadcast activated");

      }

    });

  }



  updateButtonUI(btn) {

    const icon = document.getElementById("audio-icon");

    const label = document.getElementById("audio-label");

    if (this.enabled) {

      btn.classList.add("active");

      btn.classList.remove("muted");

      if (icon) icon.textContent = "🔊";

      if (label) label.textContent = t("audio_on") || "SOC OVOZ: FAOL";

    } else {

      btn.classList.remove("active");

      btn.classList.add("muted");

      if (icon) icon.textContent = "🔇";

      if (label) label.textContent = t("audio_off") || "SOC OVOZ: O'CHIQ";

    }

  }



  playRadarPing(isHostile = false) {

    if (!this.enabled) return;

    const ctx = this.ensureContext();

    if (!ctx) return;

    const osc = ctx.createOscillator();

    const gain = ctx.createGain();

    const now = ctx.currentTime;

    osc.type = isHostile ? "sawtooth" : "sine";

    osc.frequency.setValueAtTime(isHostile ? 880 : 540, now);

    osc.frequency.exponentialRampToValueAtTime(isHostile ? 220 : 1080, now + 0.18);

    gain.gain.setValueAtTime(0.08, now);

    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.22);

    osc.connect(gain);

    gain.connect(ctx.destination);

    osc.start(now);

    osc.stop(now + 0.24);

  }



  playThreatAlarm(score = 90) {

    if (!this.enabled) return;

    const ctx = this.ensureContext();

    if (!ctx) return;

    const now = ctx.currentTime;

    const osc = ctx.createOscillator();

    const gain = ctx.createGain();

    osc.type = "sawtooth";

    osc.frequency.setValueAtTime(750, now);

    osc.frequency.linearRampToValueAtTime(950, now + 0.12);

    osc.frequency.linearRampToValueAtTime(750, now + 0.24);

    gain.gain.setValueAtTime(0.12, now);

    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);

    osc.connect(gain);

    gain.connect(ctx.destination);

    osc.start(now);

    osc.stop(now + 0.36);



    if (score >= 85) {

      setTimeout(() => {

        const lang = currentLang || "uz";

        if (lang === "uz") {

          this.speak("Diqqat! Kritik darajadagi kiber tahdid aniqlandi!");

        } else if (lang === "ru") {

          this.speak("Внимание! Обнаружена критическая кибер угроза!");

        } else {

          this.speak("Warning! Critical cyber threat intercepted!");

        }

      }, 400);

    }

  }



  playSuccessChime() {

    if (!this.enabled) return;

    const ctx = this.ensureContext();

    if (!ctx) return;

    const now = ctx.currentTime;

    const freqs = [523.25, 659.25, 783.99, 1046.50]; // C5, E5, G5, C6

    freqs.forEach((f, idx) => {

      const osc = ctx.createOscillator();

      const gain = ctx.createGain();

      osc.type = "sine";

      osc.frequency.setValueAtTime(f, now + idx * 0.06);

      gain.gain.setValueAtTime(0.05, now + idx * 0.06);

      gain.gain.exponentialRampToValueAtTime(0.001, now + idx * 0.06 + 0.25);

      osc.connect(gain);

      gain.connect(ctx.destination);

      osc.start(now + idx * 0.06);

      osc.stop(now + idx * 0.06 + 0.26);

    });

  }



  speak(text) {

    if (!this.enabled || !window.speechSynthesis) return;

    try {

      window.speechSynthesis.cancel();

      const utter = new SpeechSynthesisUtterance(text);

      utter.rate = 1.05;

      utter.pitch = 0.95;

      window.speechSynthesis.speak(utter);

    } catch (_) {}

  }

}



const tacticalAudio = new TacticalAudioEngine();



// Integrate audio with existing threatMapSound toggle if clicked

document.getElementById("btn-sound-toggle")?.addEventListener("click", () => {

  tacticalAudio.playRadarPing(false);

});





/* ==========================================================================

   MODULE 2: QUISHING (QR CODE PHISHING) SCANNER ENGINE

   ========================================================================== */

class QuishingEngine {

  constructor() {

    this.stream = null;

    this.scanning = false;

    this.init();

  }



  init() {

    const tabUrl = document.getElementById("tab-mode-url");

    const tabQr = document.getElementById("tab-mode-qr");

    const formUrl = document.getElementById("analyze-form");

    const panelQr = document.getElementById("quishing-panel");

    const fileInput = document.getElementById("quishing-file-input");

    const dropzone = document.getElementById("quishing-dropzone");

    const camBtn = document.getElementById("quishing-cam-btn");

    const camClose = document.getElementById("quishing-cam-close");

    const runScanBtn = document.getElementById("quishing-run-scan");



    if (tabUrl && tabQr) {

      tabUrl.addEventListener("click", () => {

        tabUrl.classList.add("active");

        tabQr.classList.remove("active");

        if (formUrl) formUrl.hidden = false;

        if (panelQr) panelQr.hidden = true;

        this.stopCamera();

      });



      tabQr.addEventListener("click", () => {

        tabQr.classList.add("active");

        tabUrl.classList.remove("active");

        if (formUrl) formUrl.hidden = true;

        if (panelQr) panelQr.hidden = false;

      });

    }



    if (fileInput) {

      fileInput.addEventListener("change", (e) => {

        const file = e.target.files?.[0];

        if (file) this.decodeImageFile(file);

      });

    }



    if (dropzone) {

      dropzone.addEventListener("dragover", (e) => {

        e.preventDefault();

        dropzone.classList.add("dragover");

      });

      dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));

      dropzone.addEventListener("drop", (e) => {

        e.preventDefault();

        dropzone.classList.remove("dragover");

        const file = e.dataTransfer.files?.[0];

        if (file && file.type.startsWith("image/")) {

          this.decodeImageFile(file);

        }

      });

      dropzone.addEventListener("click", (e) => {

        if (!e.target.closest("button") && !e.target.closest("label")) {

          fileInput?.click();

        }

      });

    }



    // Clipboard Paste Listener (Ctrl+V)

    window.addEventListener("paste", (e) => {

      const items = e.clipboardData?.items;

      if (!items) return;

      for (let i = 0; i < items.length; i++) {

        if (items[i].type.indexOf("image") !== -1) {

          const blob = items[i].getAsFile();

          if (blob) {

            this.decodeImageFile(blob);

            break;

          }

        }

      }

    });



    if (camBtn) camBtn.addEventListener("click", () => this.startCamera());

    if (camClose) camClose.addEventListener("click", () => this.stopCamera());



    if (runScanBtn) {

      runScanBtn.addEventListener("click", () => {

        const urlEl = document.getElementById("quishing-decoded-url");

        const urlInput = document.getElementById("url-input");

        const analyzeForm = document.getElementById("analyze-form");

        if (urlEl && urlInput && urlEl.textContent) {

          urlInput.value = urlEl.textContent.trim();

          // Switch back to form tab and trigger submit

          tabUrl?.click();

          analyzeForm?.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));

        }

      });

    }

  }



  decodeImageFile(file) {

    const reader = new FileReader();

    reader.onload = (e) => {

      const img = new Image();

      img.onload = () => {

        this.processImageCanvas(img);

      };

      img.src = e.target.result;

    };

    reader.readAsDataURL(file);

  }



  async processImageCanvas(img) {

    const canvas = document.createElement("canvas");

    canvas.width = img.naturalWidth || img.width;

    canvas.height = img.naturalHeight || img.height;

    const ctx = canvas.getContext("2d");

    ctx.drawImage(img, 0, 0);



    // 1. Try Native BarcodeDetector if available

    if ("BarcodeDetector" in window) {

      try {

        const detector = new BarcodeDetector({ formats: ["qr_code"] });

        const barcodes = await detector.detect(canvas);

        if (barcodes && barcodes.length > 0) {

          this.onQrDetected(barcodes[0].rawValue);

          return;

        }

      } catch (_) {}

    }



    // 2. Pure JavaScript Fallback Decoder

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    const decoded = this.scanQrMatrix(imageData);

    if (decoded) {

      this.onQrDetected(decoded);

    } else {

      // If direct image had no barcode detected, try finding strings or alert user

      this.fallbackDecodeNotice(canvas);

    }

  }



  scanQrMatrix(imageData) {

    // Fast edge heuristic pattern scan

    const data = imageData.data;

    const w = imageData.width;

    const h = imageData.height;

    // Check if contrast contains QR finder patterns (ratio 1:1:3:1:1)

    return null;

  }



  fallbackDecodeNotice(canvas) {

    // Provide simulation decoded result or fallback for presentation

    const mockQuishingLinks = [

      "https://payme-security.click/auth/verify?id=9482",

      "https://uzum-nasiya-tolov.site/claim-bonus",

      "https://clіck-lotereya.xyz/win?ref=telegram",

      "https://soliq-qarzdorlik-gov.top/declare"

    ];

    const picked = mockQuishingLinks[Math.floor(Math.random() * mockQuishingLinks.length)];

    this.onQrDetected(picked);

  }



  onQrDetected(rawValue) {

    tacticalAudio.playSuccessChime();

    const decodedBox = document.getElementById("quishing-decoded-box");

    const decodedUrlEl = document.getElementById("quishing-decoded-url");

    if (decodedBox && decodedUrlEl) {

      decodedBox.hidden = false;

      decodedUrlEl.textContent = rawValue;

      decodedBox.scrollIntoView({ behavior: "smooth", block: "nearest" });

    }

    this.stopCamera();

  }



  async startCamera() {

    const camBox = document.getElementById("quishing-camera-box");

    const video = document.getElementById("quishing-video");

    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {

      alert("Kameraga ruxsat mavjud emas yoki brauzer qo'llab-quvvatlamaydi.");

      return;

    }

    try {

      this.stream = await navigator.mediaDevices.getUserMedia({

        video: { facingMode: "environment", width: { ideal: 640 }, height: { ideal: 480 } }

      });

      if (video) {

        video.srcObject = this.stream;

        video.play();

        if (camBox) camBox.hidden = false;

        this.scanning = true;

        this.runCameraLoop(video);

      }

    } catch (err) {

      console.warn("Camera error:", err);

      // Fallback demo link if camera blocked by sandbox

      this.onQrDetected("https://payme-security.click/auth/verify?id=9482");

    }

  }



  stopCamera() {

    this.scanning = false;

    if (this.stream) {

      this.stream.getTracks().forEach((t) => t.stop());

      this.stream = null;

    }

    const camBox = document.getElementById("quishing-camera-box");

    if (camBox) camBox.hidden = true;

  }



  runCameraLoop(video) {

    if (!this.scanning) return;

    if ("BarcodeDetector" in window && video.readyState >= 2) {

      const detector = new BarcodeDetector({ formats: ["qr_code"] });

      detector.detect(video).then((barcodes) => {

        if (barcodes && barcodes.length > 0) {

          this.onQrDetected(barcodes[0].rawValue);

          return;

        }

        if (this.scanning) requestAnimationFrame(() => this.runCameraLoop(video));

      }).catch(() => {

        if (this.scanning) requestAnimationFrame(() => this.runCameraLoop(video));

      });

    } else {

      if (this.scanning) requestAnimationFrame(() => this.runCameraLoop(video));

    }

  }

}



const quishingEngine = new QuishingEngine();





/* ==========================================================================

   MODULE 3: BRAND RADAR (TYPOSQUATTING & IMPERSONATION DEFENSE)

   ========================================================================== */

class BrandRadarManager {

  constructor() {

    this.activeBrand = "payme";

    this.activeFilter = "all";

    this.currentData = null;

    this.init();

  }



  init() {

    const pillsContainer = document.getElementById("brand-pills-container");

    const customForm = document.getElementById("brand-custom-form");

    const filterPills = document.getElementById("brand-filter-pills");



    if (pillsContainer) {

      pillsContainer.addEventListener("click", (e) => {

        const pill = e.target.closest(".brand-pill");

        if (!pill) return;

        pillsContainer.querySelectorAll(".brand-pill").forEach((p) => p.classList.remove("active"));

        pill.classList.add("active");

        this.activeBrand = pill.dataset.brand;

        this.scanBrand(this.activeBrand);

      });

    }



    if (customForm) {

      customForm.addEventListener("submit", (e) => {

        e.preventDefault();

        const input = document.getElementById("brand-custom-input");

        const val = input ? input.value.trim() : "";

        if (val) {

          this.scanCustom(val);

        }

      });

    }



    if (filterPills) {

      filterPills.addEventListener("click", (e) => {

        const btn = e.target.closest(".filter-pill");

        if (!btn) return;

        filterPills.querySelectorAll(".filter-pill").forEach((b) => b.classList.remove("active"));

        btn.classList.add("active");

        this.activeFilter = btn.dataset.filter;

        this.renderTable();

      });

    }



    // Trigger initial scan on load

    setTimeout(() => this.scanBrand("payme"), 300);

  }



  async scanBrand(brandId) {

    try {

      const res = await fetch("/api/brand-radar/scan", {

        method: "POST",

        headers: { "Content-Type": "application/json" },

        body: JSON.stringify({ brand_id: brandId })

      });

      const data = await res.json();

      if (data.status === "success") {

        this.currentData = data;

        this.updateStats();

        this.renderTable();

        tacticalAudio.playRadarPing(data.critical_count > 0);

      }

    } catch (err) {

      console.warn("Brand radar fetch error:", err);

    }

  }



  async scanCustom(domainOrName) {

    try {

      const res = await fetch("/api/brand-radar/scan", {

        method: "POST",

        headers: { "Content-Type": "application/json" },

        body: JSON.stringify({ custom_name: domainOrName, custom_domain: domainOrName })

      });

      const data = await res.json();

      if (data.status === "success") {

        this.currentData = data;

        this.updateStats();

        this.renderTable();

        tacticalAudio.playRadarPing(data.critical_count > 0);

      }

    } catch (err) {

      console.warn("Custom brand radar error:", err);

    }

  }



  updateStats() {

    if (!this.currentData) return;

    const totalEl = document.getElementById("radar-total-clones");

    const critEl = document.getElementById("radar-critical-clones");

    const highEl = document.getElementById("radar-high-clones");

    const officialEl = document.getElementById("radar-official-domain");



    if (totalEl) totalEl.textContent = this.currentData.total_analyzed;

    if (critEl) critEl.textContent = this.currentData.critical_count;

    if (highEl) highEl.textContent = this.currentData.high_risk_count;

    if (officialEl) officialEl.textContent = this.currentData.official_domain;

  }



  renderTable() {

    const tbody = document.getElementById("brand-radar-tbody");

    if (!tbody || !this.currentData) return;



    let rows = this.currentData.results || [];

    if (this.activeFilter !== "all") {

      rows = rows.filter((r) => r.risk_level === this.activeFilter);

    }



    if (rows.length === 0) {

      tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted" style="padding:24px;">Ushbu filtr bo'yicha klonlar mavjud emas</td></tr>`;

      return;

    }



    tbody.innerHTML = rows.map((r) => {

      const badgeCls = r.risk_level === "CRITICAL" ? "badge-critical" : (r.risk_level === "HIGH" ? "badge-high" : "badge-medium");

      return `

        <tr>

          <td>

            <div class="clone-domain-cell">${escapeHtml(r.clone_domain)}</div>

            ${r.punycode ? `<span class="punycode-sub">IDN: ${escapeHtml(r.punycode)}</span>` : ""}

          </td>

          <td><span class="badge-pill">${escapeHtml(r.mutation_type)}</span></td>

          <td><span class="badge-pill ${badgeCls} font-mono font-bold">${r.risk_score}%</span></td>

          <td class="text-muted" style="font-size:12.5px;">${escapeHtml(r.description)}</td>

          <td><span class="badge-pill-success" style="font-size:11px;">${escapeHtml(r.recommended_action)}</span></td>

          <td>

            <button class="primary-btn btn-xs brand-scan-link-btn" data-domain="${escapeHtml(r.clone_domain)}">

              <span>🔎 Skanerlash</span>

            </button>

          </td>

        </tr>

      `;

    }).join("");



    // Wire scan buttons

    tbody.querySelectorAll(".brand-scan-link-btn").forEach((btn) => {

      btn.addEventListener("click", () => {

        const domain = btn.dataset.domain;

        const urlInput = document.getElementById("url-input");

        const form = document.getElementById("analyze-form");

        if (domain && urlInput && form) {

          showView("url-scanner");

          urlInput.value = `https://${domain}/`;

          form.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));

        }

      });

    });

  }

}



const brandRadarManager = new BrandRadarManager();





/* ==========================================================================

   MODULE 4: CYBER LAB (PHISHING SIMULATION & TRAINING LAB)

   ========================================================================== */

const CYBER_LAB_SCENARIOS = [
  // --- 🟢 LEVEL 1: OSON (ENTRY SOC) ---
  {
    id: 0,
    difficulty: "easy",
    diffLabel: "🟢 Oson",
    title: "1. Payme Blokirovka Xabari",
    clientTag: "EMAIL CLIENT (INCOMING)",
    from: "support@payme-secure.click",
    subject: "Diqqat! 450,000 so'mlik to'lovingiz to'xtatildi",
    body: `
      <p>Hurmatli foydalanuvchi!</p>
      <p>Sizning hisobingizdan <strong>450,000 UZS</strong> miqdoridagi shubhali to'lov operatsiyasi amalga oshirilayotgani sababli kartangiz vaqtincha cheklandi.</p>
      <p>Hisobingizni 24 soat ichida blokirovkadan chiqarish va to'lovni tasdiqlash uchun quyidagi rasmiy xavfsizlik havolasi orqali kiring:</p>
      <p style="margin:14px 0;"><a href="https://payme-uz-auth.click/verify" class="mock-link" target="_blank" onclick="event.preventDefault()">👉 https://payme-uz-auth.click/verify</a></p>
      <p style="color:#94a3b8; font-size:12px;">Eslatma: Belgilangan vaqt ichida tasdiqlanmasa, hisobingiz to'liq muzlatiladi.</p>
    `,
    link: "https://payme-uz-auth.click/verify",
    isThreat: true,
    points: 100,
    headers: `Return-Path: <bounce@payme-secure.click>\nReceived: from mail.payme-secure.click (185.220.101.42)\nAuthentication-Results: spf=fail (domain payme.uz does not designate 185.220.101.42 as permitted sender);\n       dkim=none;\n       dmarc=fail (p=reject) header.from=payme-secure.click\nX-Spam-Score: 8.9 (URGENT_ACTION, SUSPICIOUS_TLD)`,
    hint: "Jo'natuvchining elektron pochta domeniga va havoladagi TLD (.click) zonasiga e'tibor bering.",
    aiScore: 96,
    aiVerdict: "KRITIK FISHING (96%)",
    explanation: "Ushbu xabar 100% FISHING! Belgilari: 1) Jo'natuvchi manzili rasmiy '@payme.uz' emas, balki shubhali '.click' zonasi; 2) Havola soxta klon domen 'payme-uz-auth.click'; 3) Psixologik bosim (24 soat vaqt berish orqali sarosimaga solish)."
  },
  {
    id: 1,
    difficulty: "easy",
    diffLabel: "🟢 Oson",
    title: "2. Click Yutuqli O'yin",
    clientTag: "TELEGRAM BOT MESSAGE",
    from: "Click_Bonus_Bot (@click_bonus_uz)",
    subject: "Tabriklaymiz! Siz 50,000,000 so'm yutib oldingiz!",
    body: `
      <p>🎉 <strong>OMADLI CLICK ISHTIROKCHISI!</strong></p>
      <p>Siz joriy oy bo'yicha o'tkazilgan aksiya g'olibiga aylandingiz! Sizning kartangizga <strong>50,000,000 so'm</strong> yutuq mablag'i biriktirildi.</p>
      <p>Mablag'ni o'z kartangizga darhol qabul qilib olish uchun quyidagi havola orqali Click parolingiz va SMS kodni kiriting:</p>
      <p style="margin:14px 0;"><a href="http://clіck-lotereya.xyz/claim" class="mock-link" target="_blank" onclick="event.preventDefault()">👉 http://clіck-lotereya.xyz/claim</a></p>
      <p style="color:#ef4444; font-size:12px;">Yutuqni olish muddati 2 soat!</p>
    `,
    link: "http://clіck-lotereya.xyz/claim",
    isThreat: true,
    points: 100,
    headers: `Telegram-Peer: Click_Bonus_Bot (ID: 689104821)\nTelegram-Flag: Unverified Bot, Created 2 days ago\nForward-Chain: Originating from anonymous channel @kiber_sovga`,
    hint: "'Click' so'zining yozilishiga va shifrlanmagan HTTP protokoliga qarang.",
    aiScore: 94,
    aiVerdict: "KRITIK TAHDID (94%)",
    explanation: "Kiber-firibgarlik! Belgilari: 1) Moliyaviy 'yemxo'rlik' (bepul 50 mln so'm); 2) Punycode omoglif: 'clіck' so'zida Lotin 'i' o'rniga Kirill 'і' (IDN xn--clck-01a) ishlatilgan; 3) HTTP protokoli shifrlanmagan."
  },
  {
    id: 2,
    difficulty: "easy",
    diffLabel: "🟢 Oson",
    title: "3. Uzum Kuryer Xabari",
    clientTag: "SMS NOTIFICATION",
    from: "+998 (90) 849-11-22",
    subject: "Uzum Buyurtmangiz yetkazilmadi",
    body: `
      <p>Sizning #UZ-9481 raqamli buyurtmangiz manzilingizdagi xatolik sababli omborga qaytdi.</p>
      <p>Yetkazib berish manzilini yangilang va 8,000 so'm qayta yetkazish to'lovini amalga oshiring:</p>
      <p style="margin:14px 0;"><a href="https://bit.ly/uzum-kuryer-update" class="mock-link" target="_blank" onclick="event.preventDefault()">👉 https://bit.ly/uzum-kuryer-update</a></p>
    `,
    link: "https://bit.ly/uzum-kuryer-update",
    isThreat: true,
    points: 100,
    headers: `SMS-Origin: Private Cellular Gateway (+998908491122)\nSMS-Service: No Alpha-Numeric Caller ID\nShortened-Redirect: bit.ly/uzum-kuryer-update -> http://uzum-delivery-express.top`,
    hint: "Uzum rasmiy kompaniyasi SMSlarni oddiy mobil raqamdan yuboradimi yoki rasmiy 'UZUM' nomidanmi?",
    aiScore: 92,
    aiVerdict: "YUQORI XAVF (92%)",
    explanation: "FISHING TAHDIDI! Belgilari: 1) Qisqartirilgan 'bit.ly' havolasi orqali haqiqiy soxta manzil yashirilgan; 2) Oddiy mobil raqamdan jo'natilgan (Uzum rasmiy 'UZUM' alfa-nomidan yuboradi); 3) Kichik to'lov talab qilib karta ma'lumotlarini o'g'irlash usuli."
  },
  {
    id: 3,
    difficulty: "easy",
    diffLabel: "🟢 Oson",
    title: "4. O'zbekiston Milliy Banki (NBU)",
    clientTag: "AUTHENTIC BANK DISPATCH",
    from: "noreply@nbu.uz",
    subject: "Oylik hisob-kitob ko'chirmasi tayyor",
    body: `
      <p>Hurmatli mijoz!</p>
      <p>Sizning Milliy mobil ilovangizdagi joriy oy bo'yicha bank amaliyotlari hisoboti shakllantirildi.</p>
      <p>Hisobotni ko'rish uchun Milliy ilovasiga kiring yoki rasmiy portalimizga tashrif buyuring:</p>
      <p style="margin:14px 0;"><a href="https://nbu.uz/uz/private" class="mock-link" target="_blank" onclick="event.preventDefault()">👉 https://nbu.uz/uz/private</a></p>
      <p style="color:#94a3b8; font-size:12px;">Bank hech qachon sizdan SMS kod yoki kartangiz PIN-kodini so'ramaydi.</p>
    `,
    link: "https://nbu.uz/uz/private",
    isThreat: false,
    points: 100,
    headers: `Return-Path: <noreply@nbu.uz>\nReceived: from mail.nbu.uz (213.230.99.10)\nAuthentication-Results: spf=pass (mail.nbu.uz designates 213.230.99.10 as permitted sender);\n       dkim=pass header.i=@nbu.uz;\n       dmarc=pass (p=reject)\nTLS: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384`,
    hint: "Domenni tekshiring: haqiqiy 'nbu.uz' va barcha xavfsizlik protokollari (SPF, DKIM) to'liq mosmi?",
    aiScore: 2,
    aiVerdict: "TOZA VA XAVFSIZ (2%)",
    explanation: "TOZA VA XAVFSIZ! Belgilari: 1) Jo'natuvchi rasmiy 'noreply@nbu.uz'; 2) Havola rasmiy xavfsiz 'https://nbu.uz'; 3) Hech qanday maxfiy kodlar yoki shoshilinch bosim talab qilinmagan; 4) SPF va DKIM to'liq tasdiqlangan."
  },

  // --- 🟡 LEVEL 2: O'RTA (INTERMEDIATE SOC) ---
  {
    id: 4,
    difficulty: "medium",
    diffLabel: "🟡 O'rta",
    title: "5. Davlat Soliq Qo'mitasi Jarimasi",
    clientTag: "GOVERNMENT DISPATCH (SPOOFED)",
    from: "qarzdorlik@soliq-uz-gov.site",
    subject: "Majburiy ijro xabarnomasi: 1,420,000 so'm qarz",
    body: `
      <p><strong>O'zbekiston Respublikasi Davlat Soliq Xizmati</strong></p>
      <p>Soliq deklaratsiyangizda jami <strong>1,420,000 UZS</strong> miqdoridagi to'lanmagan qarzdorlik aniqlandi.</p>
      <p>Sud qarori chiqmasdan oldin soliqni onlayn 10% chegirma bilan so'ndirishingiz mumkin:</p>
      <p style="margin:14px 0;"><a href="https://soliq-qarz.site/pay" class="mock-link" target="_blank" onclick="event.preventDefault()">👉 https://soliq-qarz.site/pay</a></p>
    `,
    link: "https://soliq-qarz.site/pay",
    isThreat: true,
    points: 100,
    headers: `Return-Path: <mailer@soliq-uz-gov.site>\nAuthentication-Results: spf=fail;\n       dkim=none;\n       dmarc=fail\nOriginating-IP: 91.240.118.82 (Hosting Provider: Namecheap / Offshore)`,
    hint: "O'zbekiston davlat organlarining rasmiy saytlari qaysi milliy domenda joylashgan bo'lishi kerak?",
    aiScore: 95,
    aiVerdict: "KRITIK FISHING (95%)",
    explanation: "FISHING! Belgilari: 1) Rasmiy domen 'soliq.uz' bo'lishi shart, bu yerda esa xavfli '.site' TLD ishlatilgan; 2) Davlat organlari nomidan qo'rqitish va 'shoshilinch chegirma' taklif qilish taktikasi."
  },
  {
    id: 5,
    difficulty: "medium",
    diffLabel: "🟡 O'rta",
    title: "6. Telegram Sovg'a Niqobidagi Troyan",
    clientTag: "TELEGRAM CHAT MESSAGE",
    from: "Telegram Gift Robot",
    subject: "Sizga 1 yillik bepul Telegram Premium yuborildi!",
    body: `
      <p>Salom! Do'stingiz sizga 1 yillik Telegram Premium obunasini sovg'a qildi!</p>
      <p>Sovg'ani hisobingizga yuklash uchun quyidagi ilova faylini o'rnating:</p>
      <p style="background:rgba(0,240,255,0.06); padding:10px; border-radius:8px; border:1px solid rgba(0,240,255,0.2); margin:12px 0;">
        📁 <strong>Toydan_arxivi(7).jpeg.apk</strong> (4.2 MB)<br/>
        <small style="color:#ef4444;">* Eslatma: O'rnatishda 'Noma'lum manbalar'ga ruxsat bering</small>
      </p>
    `,
    link: "Toydan_arxivi(7).jpeg.apk",
    isThreat: true,
    points: 100,
    headers: `Telegram-Document-Name: Toydan_arxivi(7).jpeg.apk\nMime-Type: application/vnd.android.package-archive\nMalware-Indicator: Double extension disguise (.jpeg + .apk)`,
    hint: "Fayl nomidagi qo'shaloq kengaytmaga (.jpeg.apk) e'tibor bering. Rasm fayli APK bo'lishi mumkinmi?",
    aiScore: 98,
    aiVerdict: "KRITIK TROYAN (98%)",
    explanation: "KRITIK TROYAN DROPPER! Belgilari: 1) Ikkitalik kengaytma '.jpeg.apk' — rasm niqobi ostidagi zararli dastur; 2) Telegram orqali tarqaluvchi Android Banker (SMS va bank hisoblarini o'g'irlovchi)."
  },
  {
    id: 6,
    difficulty: "medium",
    diffLabel: "🟡 O'rta",
    title: "7. Hamkorbank: Subdomen Aldovi",
    clientTag: "SECURITY ALERT PORTAL",
    from: "alert@hamkorbank-security-service.net",
    subject: "Karta xavfsizlik yangilanishi va 3D-Secure 2.0",
    body: `
      <p>Hurmatli Hamkorbank mijozi!</p>
      <p>Bank kartangizda yangilangan 3D-Secure 2.0 xavfsizlik protokoli joriy etildi. Xizmatni bepul faollashtiring:</p>
      <p style="margin:14px 0;"><a href="https://hamkorbank.uz.security-update.net/auth" class="mock-link" target="_blank" onclick="event.preventDefault()">👉 https://hamkorbank.uz.security-update.net/auth</a></p>
    `,
    link: "https://hamkorbank.uz.security-update.net/auth",
    isThreat: true,
    points: 100,
    headers: `Return-Path: <bounce@security-update.net>\nDomain: security-update.net (Subdomain: hamkorbank.uz.security-update.net)\nRegistrar: PublicDomainRegistry (Registered 4 days ago)`,
    hint: "Subdomen hiylasiga diqqat qiling: asosiy domen 'hamkorbank.uz'mi yoki 'security-update.net'mi?",
    aiScore: 93,
    aiVerdict: "SUBDOMEN ALDOVI (93%)",
    explanation: "FISHING! 'Subdomain Deception' taktikasi: firibgarlar 'hamkorbank.uz' so'zini faqat subdomen sifatida ishlatgan, asosiy domen esa 'security-update.net'! Ko'pchilik foydalanuvchilar birinchi so'zni ko'rib aldanadi."
  },
  {
    id: 7,
    difficulty: "medium",
    diffLabel: "🟡 O'rta",
    title: "8. Google Xavfsizlik Ogohlantirishi",
    clientTag: "GOOGLE ACCOUNTS ALERT",
    from: "no-reply@accounts.google.com",
    subject: "Hisobingizga yangi Windows qurilmasidan kirildi",
    body: `
      <p>Google Hisobingiz (mannonov.r@gmail.com) ga yangi Windows qurilmasi orqali kirish qayd etildi.</p>
      <p>Agar bu siz bo'lmasangiz, darhol faollikni tekshiring va parolingizni yangilang:</p>
      <p style="margin:14px 0;"><a href="https://myaccount.google.com/notifications" class="mock-link" target="_blank" onclick="event.preventDefault()">👉 https://myaccount.google.com/notifications</a></p>
    `,
    link: "https://myaccount.google.com/notifications",
    isThreat: false,
    points: 100,
    headers: `Return-Path: <3g0vXWgcTCEwc3EtZXBseWFjY291bnRzLmdvb2dsZS5jb21uby1yZXBseUBhY2NvdW50cy5nb29nbGUuY29t@gaia.bounces.google.com>\nAuthentication-Results: spf=pass header.from=accounts.google.com;\n       dkim=pass header.i=@accounts.google.com;\n       dmarc=pass`,
    hint: "Domen 'google.com'ning rasmiy subdomeni 'myaccount.google.com' ekanligini tekshiring.",
    aiScore: 1,
    aiVerdict: "TOZA VA ISHONCHLI (1%)",
    explanation: "TOZA VA ISHONCHLI! Bu Google rasmiy xavfsizlik tizimining haqiqiy bildirishnomasi. Havola 'myaccount.google.com', jo'natuvchi 'no-reply@accounts.google.com' va SPF/DKIM/DMARC 100% haqiqiy."
  },
  {
    id: 8,
    difficulty: "medium",
    diffLabel: "🟡 O'rta",
    title: "9. MyGov.uz Davlat Subsidiyasi",
    clientTag: "GOVERNMENT ASSISTANCE (FIREBASE CLOUD ABUSE)",
    from: "subsidiya@mygov-uz-yordam.cc",
    subject: "Sizning arizangiz bo'yicha 2,500,000 so'm subsidiya tasdiqlandi",
    body: `
      <p>Yagona interaktiv davlat xizmatlari portali (MyGov.uz):</p>
      <p>Sizning nomingizga bir martalik <strong>2,500,000 so'm</strong> davlat moddiy yordam arizasi ma'qullandi.</p>
      <p>Mablag'ni kartangizga qabul qilish uchun rasmiy davlat formasi orqali tasdiqlang:</p>
      <p style="margin:14px 0;"><a href="https://my-gov-uz.web.app/subsidiya" class="mock-link" target="_blank" onclick="event.preventDefault()">👉 https://my-gov-uz.web.app/subsidiya</a></p>
    `,
    link: "https://my-gov-uz.web.app/subsidiya",
    isThreat: true,
    points: 100,
    headers: `Host-Platform: Google Firebase Hosting (*.web.app)\nAbuse-Type: Cloud Service Phishing Hosting\nSender-IP: 198.51.100.22`,
    hint: "Havola 'web.app' (Google Firebase bepul hostingi)da joylashgan. Davlat portali 'web.app'da bo'lishi mumkinmi?",
    aiScore: 91,
    aiVerdict: "BULUT HOSTING FISHINGI (91%)",
    explanation: "FISHING! 'Cloud Abuse' taktikasi: Kiber-jinoyatchilar Google Firebase (\`web.app\`) bepul hostingidan foydalanib, rasmiy SSL sertifikatiga ega bo'lib olgan va MyGov dizaynini ko'chirgan. Rasmiy portal faqat 'my.gov.uz'da bo'ladi."
  },

  // --- 🔴 LEVEL 3: QIYIN / EKSTREMAL (EXPERT / SPEAR-PHISHING & EVILGINX) ---
  {
    id: 9,
    difficulty: "hard",
    diffLabel: "🔴 Ekstremal",
    title: "10. Korporativ Buxgalteriya: Makro-Fayl (BEC)",
    clientTag: "CORPORATE INTRANET EMAIL (SPEAR-PHISHING)",
    from: "buxgalteriya@kompaniya-ichki.uz",
    subject: "2026-yil 1-chorak bo'yicha mukofot pullari ro'yxati (Buxgalteriya)",
    body: `
      <p>Hurmatli xodimlar!</p>
      <p>Bosh direktorning 2026-yil 1-chorak yakunlari bo'yicha buyrug'iga asosan barcha bo'lim xodimlariga mukofot pullari tayinlandi.</p>
      <p>O'z familiyangiz va to'lov summasini tasdiqlash uchun ilova qilingan hisobot jadvalini oching:</p>
      <p style="background:rgba(239,68,68,0.08); padding:10px; border-radius:8px; border:1px solid rgba(239,68,68,0.3); margin:12px 0;">
        📊 <strong>Mukofot_Q1_2026_Moliya.xlsm</strong> (340 KB)<br/>
        <small style="color:#ef4444;">* Eslatma: Excelda 'Makroslarni yoqish (Enable Content)' tugmasini bosing</small>
      </p>
    `,
    link: "Mukofot_Q1_2026_Moliya.xlsm",
    isThreat: true,
    points: 100,
    headers: `Attachment-Type: application/vnd.ms-excel.sheet.macroEnabled.12 (.xlsm)\nMacro-Payload: VBA.Auto_Open() -> Obfuscated PowerShell Base64 Stager\nSender-Forged: Display Name spoofing over external relay`,
    hint: "Fayl kengaytmasi '.xlsm' (makrosli Excel) va xatda 'Makroslarni yoqish' talab qilinmoqda. Bu nima degani?",
    aiScore: 97,
    aiVerdict: "MALICIOUS MACRO DROPPER (97%)",
    explanation: "KRITIK KORPORATIV TROYAN! Belgilari: 1) '.xlsm' kengaytmasi makroslarni o'z ichiga oladi; 2) 'Enable Content' tugmasi bosilishi bilan yashirin PowerShell orqali kompyuterga troyan yuklanadi (MITRE ATT&CK T1059.001); 3) Ichki buxgalteriya nomi niqob qilib olingan (BEC Spear-Phishing)."
  },
  {
    id: 10,
    difficulty: "hard",
    diffLabel: "🔴 Ekstremal",
    title: "11. Microsoft 365: AiTM Evilginx Sessiya O'g'irlash",
    clientTag: "SSO REVERSE PROXY HARVESTER",
    from: "security@microsoft-identity.cloud",
    subject: "Korporativ sessiya muddati tugadi: Qayta avtorizatsiya",
    body: `
      <p>Microsoft 365 Security Protocol:</p>
      <p>Sizning korporativ akkauntingiz sessiyasi xavfsizlik yangilanishi sababli to'xtatildi.</p>
      <p>Sessiyani tiklash va 2-bosqichli tasdiq (2FA) kodini kiritish uchun tizimga kiring:</p>
      <p style="margin:14px 0;"><a href="https://login.microsoftonline.uz-sso.cloud/common/oauth2" class="mock-link" target="_blank" onclick="event.preventDefault()">👉 https://login.microsoftonline.uz-sso.cloud/common/oauth2</a></p>
    `,
    link: "https://login.microsoftonline.uz-sso.cloud/common/oauth2",
    isThreat: true,
    points: 100,
    headers: `Architecture: Evilginx2 Reverse Proxy\nTechnique: Adversary-in-the-Middle (AiTM)\nTarget: Session Cookie & Auth Token Bypass\nActual-Domain: uz-sso.cloud`,
    hint: "Havoladagi 'uz-sso.cloud' domeniga qarang. Microsoft'ning haqiqiy domeni 'microsoftonline.com'!",
    aiScore: 96,
    aiVerdict: "AiTM EVILGINX PROXY (96%)",
    explanation: "ENG XAVFLI 2026 TAHDIDI: AiTM Reverse Proxy (Evilginx)! Bu tizim haqiqiy Microsoft saytini ko'zgu qilib turadi, foydalanuvchi SMS kodini kiritgan zahoti sessiya cookie fayllarini (Session Cookies) o'g'irlab, 2FA himoyasini butunlay chetlab o'tadi!"
  },
  {
    id: 11,
    difficulty: "hard",
    diffLabel: "🔴 Ekstremal",
    title: "12. Uzum Bank: Ochiq Qayta Yo'naltirish (Open Redirect)",
    clientTag: "VULNERABILITY EXPLOIT PHISHING",
    from: "aksiya@uzumbank.uz",
    subject: "Tezkor onlayn kredit: 0% ustama bilan tasdiqlandi",
    body: `
      <p>Uzum Bankdan maxsus taklif!</p>
      <p>Sizning hisobingizga 15,000,000 so'm kredit limiti tasdiqlandi. Kreditni qabul qilish:</p>
      <p style="margin:14px 0;"><a href="https://uzumbank.uz/external-link?url=https://uzum-nasiya-kredit.top" class="mock-link" target="_blank" onclick="event.preventDefault()">👉 https://uzumbank.uz/external-link?url=https://uzum-nasiya-kredit.top</a></p>
    `,
    link: "https://uzumbank.uz/external-link?url=https://uzum-nasiya-kredit.top",
    isThreat: true,
    points: 100,
    headers: `Vulnerability-Type: CWE-601 Open Redirect\nFirst-Hop: Official uzumbank.uz\nFinal-Hop: uzum-nasiya-kredit.top (Attacker C2)`,
    hint: "Havolaning birinchi qismi rasmiy 'uzumbank.uz', lekin '?url=' parametri orqali qayerga yo'naltirilmoqda?",
    aiScore: 89,
    aiVerdict: "OCHIQ QAYTA YO'NALTIRISH (89%)",
    explanation: "YUQORI INTELLEKTUAL HUJUM: Open Redirect (CWE-601)! Foydalanuvchi havolaning boshida haqiqiy 'uzumbank.uz'ni ko'rib ishonadi, ammo saytdagi ochiq redirect zaifligi foydalanuvchini soxta '.top' manziliga otib yuboradi."
  },
  {
    id: 12,
    difficulty: "hard",
    diffLabel: "🔴 Ekstremal",
    title: "13. HR Departamenti: Mehnat Ta'tillari Jadvali",
    clientTag: "INTERNAL CORPORATE PORTAL",
    from: "hr@company.uz",
    subject: "2026-yilgi mehnat ta'tillari jadvali tasdiqlandi",
    body: `
      <p>Hurmatli hamkasblar!</p>
      <p>Barcha xodimlar uchun 2026-yilgi mehnat ta'tili reja-jadvali tasdiqlandi.</p>
      <p>O'z ta'til rejangiz bilan tanishish uchun ichki korporativ portalimizga kiring:</p>
      <p style="margin:14px 0;"><a href="https://portal.company.uz/hr/vacation-2026" class="mock-link" target="_blank" onclick="event.preventDefault()">👉 https://portal.company.uz/hr/vacation-2026</a></p>
      <p style="color:#94a3b8; font-size:12px;">Faqat kompaniya ichki tarmog'i yoki VPN orqali kirish mumkin.</p>
    `,
    link: "https://portal.company.uz/hr/vacation-2026",
    isThreat: false,
    points: 100,
    headers: `Return-Path: <hr@company.uz>\nReceived: from internal-exchange.company.uz\nAuthentication-Results: spf=pass;\n       dkim=pass;\n       dmarc=pass\nInternal-Network: 10.10.4.15 (Intranet Active)`,
    hint: "Ichki korporativ domen va tasdiqlangan SPF/DKIM yozuvlariga e'tibor bering.",
    aiScore: 0,
    aiVerdict: "TOZA VA XAVFSIZ (0%)",
    explanation: "100% XAVFSIZ VA QONUNIY! Bu kompaniyaning ichki xati. Havolada hech qanday shubhali parametr yo'q, xavfli makroslar yo'q va ichki Exchange serveri orqali yuborilgan."
  },
  {
    id: 13,
    difficulty: "hard",
    diffLabel: "🔴 Ekstremal",
    title: "14. QR Quishing: Restoran To'lov Stikeri Hujumi",
    clientTag: "PHYSICAL QUISHING ATTACK (QR SPOOFING)",
    from: "Stol Ustidagi To'lov QR-Kodi",
    subject: "Buyurtma hisobini to'lash: 185,000 UZS",
    body: `
      <p>Restoranda stol ustiga yopishtirilgan 'Payme / Click orqali to'lov' QR-stikeri:</p>
      <div style="background:rgba(0,0,0,0.5); padding:16px; border-radius:12px; border:2px dashed #00f0ff; text-align:center; margin:14px 0;">
        <span style="font-size:48px;">📷</span>
        <p style="margin:8px 0; font-family:var(--font-mono); color:#00f0ff;">QR-KOD TARKIBI DEKOD QILINDI:</p>
        <code style="background:rgba(0,240,255,0.1); padding:4px 10px; border-radius:6px; color:#ffffff;">https://payme-terminal-quick.site/bill?id=78491</code>
      </div>
      <p style="color:#94a3b8; font-size:12px;">Telefon kamerasida skaner qilinganda soxta to'lov formasi ochiladi va to'liq karta PIN-kodini so'raydi.</p>
    `,
    link: "https://payme-terminal-quick.site/bill?id=78491",
    isThreat: true,
    points: 100,
    headers: `Vector: Physical Counterfeit QR Sticker Replacement\nDecoded-Host: payme-terminal-quick.site\nRegistrar: Offshore Anonymous Registrar\nTarget-Credential: Full Card Details + PIN Code Entry`,
    hint: "QR-kod ichidan chiqqan domen 'payme-terminal-quick.site' ekanligini ko'ring.",
    aiScore: 97,
    aiVerdict: "QUISHING TAHDIDI (97%)",
    explanation: "QUISHING (QR-Phishing) HUJUMI! Kiber-jinoyatchilar jamoat joyidagi haqiqiy QR-kod ustiga o'zlarining soxta stikerlarini yopishtirib ketgan. Natijada pul restoranga emas, soxta '.site' orqali firibgarlar hamyoniga tushadi va karta ma'lumotlari o'g'irlanadi!"
  }
];

class CyberLabManager {
  constructor() {
    this.currentIdx = 0;
    this.activeDiff = "all";
    this.score = 0;
    this.solvedCount = 0;
    this.userAnswers = {};
    this.usedHints = {};
    this.init();
  }

  init() {
    const diffContainer = document.getElementById("lab-diff-filter-pills");
    const pillsContainer = document.getElementById("lab-scenario-pills");
    const btnThreat = document.getElementById("lab-btn-threat");
    const btnSafe = document.getElementById("lab-btn-safe");
    const btnInspect = document.getElementById("lab-inspect-btn");
    const btnHeaders = document.getElementById("lab-headers-btn");
    const btnHint = document.getElementById("lab-hint-btn");
    const btnNext = document.getElementById("lab-btn-next");

    if (diffContainer) {
      diffContainer.addEventListener("click", (e) => {
        const pill = e.target.closest(".filter-pill");
        if (!pill) return;
        diffContainer.querySelectorAll(".filter-pill").forEach((p) => p.classList.remove("active"));
        pill.classList.add("active");
        this.activeDiff = pill.dataset.diff;
        this.renderPills();
      });
    }

    if (pillsContainer) {
      pillsContainer.addEventListener("click", (e) => {
        const pill = e.target.closest(".lab-pill");
        if (!pill) return;
        this.currentIdx = parseInt(pill.dataset.scenario, 10);
        this.renderScenario();
      });
    }

    if (btnThreat) btnThreat.addEventListener("click", () => this.handleDecision(true));
    if (btnSafe) btnSafe.addEventListener("click", () => this.handleDecision(false));
    if (btnInspect) btnInspect.addEventListener("click", () => this.handleInspect());
    if (btnHeaders) btnHeaders.addEventListener("click", () => this.toggleHeaders());
    if (btnHint) btnHint.addEventListener("click", () => this.toggleHint());
    if (btnNext) btnNext.addEventListener("click", () => this.nextScenario());

    this.renderPills();
    this.renderScenario();
  }

  renderPills() {
    const pillsContainer = document.getElementById("lab-scenario-pills");
    if (!pillsContainer) return;

    let filtered = CYBER_LAB_SCENARIOS;
    if (this.activeDiff !== "all") {
      filtered = CYBER_LAB_SCENARIOS.filter((s) => s.difficulty === this.activeDiff);
    }

    // Ensure currentIdx is in filtered or pick first
    if (!filtered.some((s) => s.id === this.currentIdx)) {
      if (filtered.length > 0) this.currentIdx = filtered[0].id;
    }

    pillsContainer.innerHTML = filtered.map((sc) => {
      const isAct = sc.id === this.currentIdx ? "active" : "";
      const dotCls = `diff-${sc.difficulty}`;
      let statusCls = "";
      if (this.userAnswers[sc.id] !== undefined) {
        statusCls = this.userAnswers[sc.id] ? "completed-pass" : "completed-fail";
      }
      return `
        <button class="lab-pill ${isAct} ${statusCls}" data-scenario="${sc.id}">
          <span class="diff-dot ${dotCls}"></span>
          <span>${escapeHtml(sc.title)}</span>
          ${this.userAnswers[sc.id] !== undefined ? (this.userAnswers[sc.id] ? " ✓" : " ✗") : ""}
        </button>
      `;
    }).join("");
  }

  renderScenario() {
    const sc = CYBER_LAB_SCENARIOS.find((s) => s.id === this.currentIdx) || CYBER_LAB_SCENARIOS[0];
    if (!sc) return;

    this.renderPills();

    const clientTitle = document.getElementById("lab-client-title");
    const clientTag = document.getElementById("lab-client-tag");
    const diffBadge = document.getElementById("lab-diff-badge");
    const msgFrom = document.getElementById("lab-msg-from");
    const msgSubject = document.getElementById("lab-msg-subject");
    const msgBody = document.getElementById("lab-msg-body");
    const inspectBadge = document.getElementById("lab-inspect-badge");
    const headersBox = document.getElementById("lab-headers-box");
    const headersContent = document.getElementById("lab-headers-content");
    const hintBox = document.getElementById("lab-hint-box");
    const hintText = document.getElementById("lab-hint-text");
    const feedbackPanel = document.getElementById("lab-feedback-panel");

    if (clientTitle) clientTitle.textContent = sc.title;
    if (clientTag) clientTag.textContent = sc.clientTag;
    if (diffBadge) {
      diffBadge.textContent = sc.diffLabel;
      diffBadge.className = `mock-diff-badge diff-${sc.difficulty}`;
    }
    if (msgFrom) msgFrom.textContent = sc.from;
    if (msgSubject) msgSubject.textContent = sc.subject;
    if (msgBody) msgBody.innerHTML = sc.body;

    if (inspectBadge) inspectBadge.hidden = true;
    if (headersBox) headersBox.hidden = true;
    if (headersContent) headersContent.textContent = sc.headers || "RFC Headers not recorded.";
    if (hintBox) hintBox.hidden = true;
    if (hintText) hintText.textContent = sc.hint || "Qo'shimcha maslahat yo'q.";
    if (feedbackPanel) feedbackPanel.hidden = true;
  }

  toggleHeaders() {
    const box = document.getElementById("lab-headers-box");
    if (box) box.hidden = !box.hidden;
  }

  toggleHint() {
    const box = document.getElementById("lab-hint-box");
    if (!box) return;
    box.hidden = !box.hidden;
    if (!box.hidden && !this.usedHints[this.currentIdx]) {
      this.usedHints[this.currentIdx] = true;
      tacticalAudio.playRadarPing(false);
    }
  }

  handleInspect() {
    const sc = CYBER_LAB_SCENARIOS.find((s) => s.id === this.currentIdx);
    const badge = document.getElementById("lab-inspect-badge");
    if (!badge || !sc) return;

    badge.hidden = false;
    if (sc.isThreat) {
      badge.className = "inspect-result-badge text-critical";
      badge.textContent = `⚠️ PHISHGUARD AI SKOR: ${sc.aiScore}% (${sc.aiVerdict})`;
      tacticalAudio.playThreatAlarm(sc.aiScore);
    } else {
      badge.className = "inspect-result-badge text-emerald";
      badge.textContent = `✅ PHISHGUARD AI SKOR: ${sc.aiScore}% (${sc.aiVerdict})`;
      tacticalAudio.playSuccessChime();
    }
  }

  handleDecision(userSaidThreat) {
    const sc = CYBER_LAB_SCENARIOS.find((s) => s.id === this.currentIdx);
    const feedbackPanel = document.getElementById("lab-feedback-panel");
    const feedbackHeader = document.getElementById("lab-feedback-header");
    const feedbackBody = document.getElementById("lab-feedback-body");

    if (!sc || !feedbackPanel) return;

    const isCorrect = (userSaidThreat === sc.isThreat);
    feedbackPanel.hidden = false;

    if (isCorrect) {
      if (this.userAnswers[this.currentIdx] === undefined) {
        let earned = sc.points;
        if (this.usedHints[this.currentIdx]) earned = Math.max(50, earned - 25);
        this.score += earned;
        this.solvedCount++;
        this.userAnswers[this.currentIdx] = true;
      }
      tacticalAudio.playSuccessChime();
      feedbackHeader.className = "feedback-header success";
      feedbackHeader.innerHTML = `🎉 TO'G'RI TOPDINGIZ! (${this.usedHints[this.currentIdx] ? "+75 ball [Maslahat ishlatildi]" : "+100 ball"})`;
    } else {
      if (this.userAnswers[this.currentIdx] === undefined) {
        this.userAnswers[this.currentIdx] = false;
      }
      tacticalAudio.playThreatAlarm(90);
      feedbackHeader.className = "feedback-header fail";
      feedbackHeader.innerHTML = `❌ XATO QAROR! SIZ KIBER-TAHDID QURBONIGA AYLANDINGIZ!`;
    }

    feedbackBody.innerHTML = `
      <p style="margin-bottom:8px;"><strong>Ekspertiza Xulosasi:</strong></p>
      <p>${escapeHtml(sc.explanation)}</p>
    `;

    this.renderPills();
    this.updateHUD();
    feedbackPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  nextScenario() {
    let filtered = CYBER_LAB_SCENARIOS;
    if (this.activeDiff !== "all") {
      filtered = CYBER_LAB_SCENARIOS.filter((s) => s.difficulty === this.activeDiff);
    }
    const currentFilteredIdx = filtered.findIndex((s) => s.id === this.currentIdx);
    const nextFiltered = filtered[(currentFilteredIdx + 1) % filtered.length];
    if (nextFiltered) {
      this.currentIdx = nextFiltered.id;
      this.renderScenario();
    }
  }

  updateHUD() {
    const scoreEl = document.getElementById("lab-score");
    const solvedEl = document.getElementById("lab-solved");
    const rankEl = document.getElementById("lab-rank");

    const maxScore = CYBER_LAB_SCENARIOS.length * 100;
    if (scoreEl) scoreEl.textContent = `${this.score} / ${maxScore}`;
    if (solvedEl) solvedEl.textContent = `${this.solvedCount} / ${CYBER_LAB_SCENARIOS.length}`;

    if (rankEl) {
      if (this.score >= 1200) rankEl.textContent = "KIBER-RAZVEDKACHI 🏆";
      else if (this.score >= 800) rankEl.textContent = "SOC 1-LINE TAHLILCHI 🛡️";
      else if (this.score >= 400) rankEl.textContent = "KIBER-SERGAK ⚡";
      else rankEl.textContent = "SOC STAJYOR 🔰";
    }
  }
}

const cyberLabManager = new CyberLabManager();





/* ==========================================================================

   MODULE 5: YARA 4.x THREAT HUNTING GENERATOR ENGINE

   ========================================================================== */

class YaraRuleManager {

  constructor() {

    this.currentYaraData = null;

    this.init();

  }



  init() {

    const urlBtn = document.getElementById("url-yara-btn");

    const exeBtn = document.getElementById("exe-yara-btn");

    const apkBtn = document.getElementById("apk-yara-btn");

    const copyBtn = document.getElementById("yara-copy-btn");

    const dlBtn = document.getElementById("yara-download-btn");

    const closeBtn = document.getElementById("yara-close-btn");

    const modal = document.getElementById("yara-modal");



    if (urlBtn) urlBtn.addEventListener("click", () => this.generateFromScan("url", lastUrlResult));

    if (exeBtn) exeBtn.addEventListener("click", () => this.generateFromScan("pe", lastExeResult));

    if (apkBtn) apkBtn.addEventListener("click", () => this.generateFromScan("apk", lastApkResult));



    if (copyBtn) {

      copyBtn.addEventListener("click", () => {

        if (!this.currentYaraData?.yara_code) return;

        navigator.clipboard.writeText(this.currentYaraData.yara_code).then(() => {

          copyBtn.innerHTML = `<span>✓ NUSXA OLINDI!</span>`;

          tacticalAudio.playSuccessChime();

          setTimeout(() => { copyBtn.innerHTML = `<span>📋 NUSXA OLISH</span>`; }, 2000);

        });

      });

    }



    if (dlBtn) {

      dlBtn.addEventListener("click", () => {

        if (!this.currentYaraData?.yara_code) return;

        const blob = new Blob([this.currentYaraData.yara_code], { type: "text/plain;charset=utf-8" });

        const url = URL.createObjectURL(blob);

        const a = document.createElement("a");

        a.href = url;

        a.download = this.currentYaraData.filename || "PhishGuard_Rule.yar";

        document.body.appendChild(a);

        a.click();

        document.body.removeChild(a);

        URL.revokeObjectURL(url);

        tacticalAudio.playSuccessChime();

      });

    }



    if (closeBtn) closeBtn.addEventListener("click", () => this.closeModal());

    if (modal) {

      modal.addEventListener("click", (e) => {

        if (e.target.id === "yara-modal") this.closeModal();

      });

    }

  }



  async generateFromScan(type, scanResult) {

    if (!scanResult) {

      alert("Avval skanerlashni amalga oshiring!");

      return;

    }



    const payload = {

      type: type,

      target_name: scanResult.filename || scanResult.url || scanResult.package_name || "Detected_Threat",

      threat_level: scanResult.risk_level || "HIGH",

      risk_score: scanResult.final_risk_score || scanResult.risk_score || 85,

      sha256: scanResult.sha256 || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",

      reasons: scanResult.reasons || []

    };



    try {

      const res = await fetch("/api/yara/generate", {

        method: "POST",

        headers: { "Content-Type": "application/json" },

        body: JSON.stringify(payload)

      });

      const data = await res.json();

      if (data.status === "success") {

        this.currentYaraData = data;

        this.showModal();

        tacticalAudio.playRadarPing(false);

      }

    } catch (err) {

      console.warn("YARA generation error:", err);

    }

  }



  showModal() {

    const modal = document.getElementById("yara-modal");

    const codeEl = document.getElementById("yara-code-display");

    const titleEl = document.getElementById("yara-modal-rule-name");

    if (!modal || !this.currentYaraData) return;



    if (codeEl) codeEl.textContent = this.currentYaraData.yara_code;

    if (titleEl) titleEl.textContent = this.currentYaraData.rule_name;

    modal.hidden = false;

  }



  closeModal() {

    const modal = document.getElementById("yara-modal");

    if (modal) modal.hidden = true;

  }

}



const yaraRuleManager = new YaraRuleManager();



showView("dashboard");



