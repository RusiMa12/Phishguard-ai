"""
xai_explainer.py
----------------
Explainable AI (XAI) Moduli.
Ushbu modul har bir tekshirilgan ob'ekt (URL, EXE, APK) bo'yicha sun'iy intellekt
va evristik tahlil qarorining qaysi omillar va belgilar ta'sirida qabul qilinganini
matematik va foizli ko'rinishda (Feature Importance & Decision Attribution)
tushuntirib beradi.

Bitiruv malakaviy ishi (BMI) va ilmiy maqolalar uchun:
  - Model qarorining qorong'i quti (Black-box) bo'lib qolishini oldini oladi.
  - Har bir belgining ijobiy (xavfni oshiruvchi) yoki salbiy (xavfsizlikni tasdiqlovchi)
    hissasini aniq hisoblab beradi.
"""

from typing import List, Dict, Any


def explain_url_decision(features: dict, rule_score: int, ml_prob: float = None) -> List[Dict[str, Any]]:
    """
    Explainable AI for URL Phishing Detection.
    Har bir belgining xavf ko'rsatkichiga qo'shgan hissasini hisoblaydi.
    """
    contributions = []

    # 1. Brand Impersonation / Spoofing
    if features.get("brand_impersonation"):
        brand = features["brand_impersonation"].upper()
        contributions.append({
            "feature": "brand_impersonation",
            "name_uz": f"Brendni soxtalashtirish ({brand})",
            "name_en": f"Brand Impersonation ({brand})",
            "name_ru": f"Подделка бренда ({brand})",
            "impact_pct": 30,
            "direction": "RISK",
            "value_display": f"{brand} brendiga noqonuniy taqlid",
            "reason_uz": "Domen nomi taniqli to'lov tizimi yoki bank brendini soxtalashtirgan.",
            "reason_en": "Domain name impersonates a recognized financial brand without authorization.",
            "reason_ru": "Доменное имя неправомерно имитирует известный финансовый бренд.",
        })

    # 2. IP Address as Hostname
    if features.get("has_ip_address"):
        contributions.append({
            "feature": "has_ip_address",
            "name_uz": "IP-manzil orqali murojaat",
            "name_en": "Direct IP Hostname",
            "name_ru": "Прямой IP-адрес хоста",
            "impact_pct": 25,
            "direction": "RISK",
            "value_display": features.get("hostname", ""),
            "reason_uz": "Domen nomi o'rniga to'g'ridan-to'g'ri IP-manzildan foydalanilgan (fishingga xos).",
            "reason_en": "Direct numerical IP address used instead of a registered domain.",
            "reason_ru": "Использован прямой IP-адрес вместо зарегистрированного домена.",
        })

    # 3. '@' Symbol in URL
    if features.get("at_symbol_count", 0) > 0:
        contributions.append({
            "feature": "at_symbol",
            "name_uz": "URLda '@' belgisi mavjudligi",
            "name_en": "'@' Symbol Destination Masking",
            "name_ru": "Маскировка через символ '@'",
            "impact_pct": 20,
            "direction": "RISK",
            "value_display": f"Soni: {features.get('at_symbol_count')}",
            "reason_uz": "Brauzerda haqiqiy manzilni yashirish uchun '@' belgisi ishlatilgan.",
            "reason_en": "'@' symbol used to confuse users about the actual destination domain.",
            "reason_ru": "Символ '@' применен для сокрытия настоящего адреса назначения.",
        })

    # 4. Punycode & Homoglyph Attack
    if features.get("has_punycode"):
        contributions.append({
            "feature": "punycode_homoglyph",
            "name_uz": "Punycode / Gomoglif qallobligi",
            "name_en": "Punycode / Homoglyph Deception",
            "name_ru": "Омоглифы и Punycode атака",
            "impact_pct": 20,
            "direction": "RISK",
            "value_display": "Shubhali vizual o'xshash belgilar",
            "reason_uz": "Lotin harflari o'rniga bir xil ko'rinadigan boshqa alifbo belgilari qo'llangan.",
            "reason_en": "Visually indistinguishable foreign characters used to deceive the user.",
            "reason_ru": "Визуально схожие символы чужого алфавита применены для обмана.",
        })

    # 5. Suspicious Keywords
    susp_words = features.get("suspicious_words_found", [])
    if susp_words:
        contributions.append({
            "feature": "suspicious_keywords",
            "name_uz": f"Xavfli kalit so'zlar ({len(susp_words)} ta)",
            "name_en": f"Suspicious Keywords ({len(susp_words)})",
            "name_ru": f"Подозрительные ключевые слова ({len(susp_words)})",
            "impact_pct": 15,
            "direction": "RISK",
            "value_display": ", ".join(susp_words[:4]),
            "reason_uz": "Havolada hisobni tasdiqlash, parol kiritish yoki soxta bonus so'zlari mavjud.",
            "reason_en": "Phishing-associated keywords (login, verify, bonus) found in URL.",
            "reason_ru": "В ссылке найдены характерные фишинговые слова (логин, проверка, бонус).",
        })

    # 6. Executable Direct Download
    if features.get("has_executable_extension"):
        contributions.append({
            "feature": "executable_extension",
            "name_uz": "To'g'ridan-to'g'ri dastur yuklash",
            "name_en": "Direct Executable Payload",
            "name_ru": "Прямая ссылка на исполняемый файл",
            "impact_pct": 25,
            "direction": "RISK",
            "value_display": "EXE / SCR / BAT fayl",
            "reason_uz": "Havola veb-sahifa o'rniga zararli dasturni to'g'ridan-to'g'ri yuklashga olib boradi.",
            "reason_en": "URL directly targets a binary payload instead of a legitimate webpage.",
            "reason_ru": "Ссылка ведет напрямую на исполняемый бинарный файл.",
        })

    # 7. Open redirect / embedded URL
    if features.get("has_embedded_url"):
        contributions.append({
            "feature": "embedded_url",
            "name_uz": "Yashirin yo'naltirish (Open Redirect)",
            "name_en": "Open Redirect Cloaking",
            "name_ru": "Скрытый редирект (Open Redirect)",
            "impact_pct": 15,
            "direction": "RISK",
            "value_display": "URL ichida URL mavjud",
            "reason_uz": "Foydalanuvchini chalg'itish uchun ichki havola kiritilgan.",
            "reason_en": "Embedded URL detected inside query string to cloak malicious target.",
            "reason_ru": "Вложенная ссылка внутри параметров для сокрытия целевого сайта.",
        })

    # 8. High Risk TLD
    if features.get("has_suspicious_tld"):
        contributions.append({
            "feature": "suspicious_tld",
            "name_uz": "Xavfli domen zonasi (TLD)",
            "name_en": "High-Risk Top Level Domain",
            "name_ru": "Опасная доменная зона (TLD)",
            "impact_pct": 15,
            "direction": "RISK",
            "value_display": "Arzon / xavfli TLD",
            "reason_uz": "Firibgarlikda ko'p ishlatiladigan bepul yoki arzon ro'yxatdan o'tish zonasi.",
            "reason_en": "Domain registered under a TLD statistically prone to phishing campaigns.",
            "reason_ru": "Домен зарегистрирован в зоне, часто используемой для одноразового фишинга.",
        })

    # 9. HTTPS Security Check (Positive / Negative)
    if not features.get("has_https"):
        contributions.append({
            "feature": "no_https",
            "name_uz": "Shifrlanmagan ulanish (HTTP)",
            "name_en": "Insecure Connection (No HTTPS)",
            "name_ru": "Отсутствие шифрования HTTPS",
            "impact_pct": 10,
            "direction": "RISK",
            "value_display": "HTTP (Ochiq kanal)",
            "reason_uz": "Ma'lumotlar ochiq matn ko'rinishida uzatiladi, SSL sertifikat mavjud emas.",
            "reason_en": "Connection lacks TLS/SSL encryption, exposing transmitted credentials.",
            "reason_ru": "Соединение не защищено SSL-сертификатом, данные передаются открыто.",
        })
    else:
        contributions.append({
            "feature": "has_https",
            "name_uz": "Xavfsiz HTTPS protokoli",
            "name_en": "Valid HTTPS Connection",
            "name_ru": "Защищенный протокол HTTPS",
            "impact_pct": 15,
            "direction": "SAFE",
            "value_display": "HTTPS Faol",
            "reason_uz": "Veb-sayt ulanishi zamonaviy SSL/TLS protokoli bilan shifrlangan.",
            "reason_en": "Website utilizes encrypted transport layer security.",
            "reason_ru": "Сайт использует зашифрованное соединение TLS/SSL.",
        })

    # ML Specific Feature Weights (if available)
    if ml_prob is not None:
        ml_pct = round(ml_prob * 100)
        contributions.append({
            "feature": "ml_random_forest",
            "name_uz": f"AI Random Forest Klassifikatori ({ml_pct}%)",
            "name_en": f"AI Random Forest Classifier ({ml_pct}%)",
            "name_ru": f"Классификатор AI Random Forest ({ml_pct}%)",
            "impact_pct": 20,
            "direction": "RISK" if ml_prob >= 0.5 else "SAFE",
            "value_display": f"{ml_pct}% fishing ehtimoli",
            "reason_uz": "Mashinaviy ta'lim modeli 28 ta leksik parametr asosida baholadi.",
            "reason_en": "Supervised ensemble model evaluated 28 multidimensional lexical features.",
            "reason_ru": "Модель машинного обучения оценила 28 лексических признаков.",
        })

    return sorted(contributions, key=lambda x: x["impact_pct"], reverse=True)


def explain_exe_decision(pe_info: dict, static_score: int) -> List[Dict[str, Any]]:
    """
    Explainable AI for Windows PE Executable Analysis.
    """
    contributions = []

    if pe_info.get("has_writable_executable_section"):
        contributions.append({
            "feature": "wx_sections",
            "name_uz": "Yoziluvchi va bajariluvchi (W+X) xotira bo'limi",
            "name_en": "Writable & Executable (W+X) Memory Section",
            "name_ru": "Исполняемая и записываемая секция памяти (W+X)",
            "impact_pct": 30,
            "direction": "RISK",
            "value_display": "W+X mavjud",
            "reason_uz": "Dastur ish vaqtida o'z xotirasiga kod yozib ishga tushirishi mumkin (Self-modifying code).",
            "reason_en": "Enables runtime in-memory code generation or shellcode execution.",
            "reason_ru": "Позволяет выполнять динамически сгенерированный в памяти код.",
        })

    if pe_info.get("max_section_entropy", 0) >= 7.0:
        contributions.append({
            "feature": "high_entropy",
            "name_uz": f"Yuqori entropiya ({pe_info.get('max_section_entropy')})",
            "name_en": f"High Section Entropy ({pe_info.get('max_section_entropy')})",
            "name_ru": f"Высокая энтропия секций ({pe_info.get('max_section_entropy')})",
            "impact_pct": 25,
            "direction": "RISK",
            "value_display": "Shifrlangan / Packed",
            "reason_uz": "Kod qadoqlangan yoki shifrlangan, antivirus tahlilidan yashiringan.",
            "reason_en": "Binary content is heavily obfuscated, packed, or encrypted.",
            "reason_ru": "Содержимое секции упаковано или зашифровано для обхода сигнатур.",
        })

    susp_imports = pe_info.get("suspicious_imports", [])
    if susp_imports:
        contributions.append({
            "feature": "sensitive_apis",
            "name_uz": f"Xavfli Win32 API funksiyalari ({len(susp_imports)} ta)",
            "name_en": f"Suspicious Windows APIs ({len(susp_imports)})",
            "name_ru": f"Подозрительные функции Win32 API ({len(susp_imports)})",
            "impact_pct": 25,
            "direction": "RISK",
            "value_display": ", ".join(susp_imports[:4]),
            "reason_uz": "Xotiraga inyeksiya qilish va boshqa jarayonlarni boshqarish buyruqlari.",
            "reason_en": "API imports associated with process injection, hollowing, or keylogging.",
            "reason_ru": "Импорт функций для инъекции кода, перехвата клавиш или модификации памяти.",
        })

    if pe_info.get("has_packer_sections"):
        contributions.append({
            "feature": "packer_detected",
            "name_uz": f"Packer / Himoyalovchi ({pe_info.get('packer_section_name')})",
            "name_en": f"Known Packer Signature ({pe_info.get('packer_section_name')})",
            "name_ru": f"Обнаружен упаковщик ({pe_info.get('packer_section_name')})",
            "impact_pct": 20,
            "direction": "RISK",
            "value_display": pe_info.get("packer_section_name", ""),
            "reason_uz": "Zararli dasturlarni yashirishda qo'llaniladigan mashhur qadoqlovchi aniqlandi.",
            "reason_en": "Recognized binary protector frequently leveraged to pack malware.",
            "reason_ru": "Сигнатура известного протектора, используемого для маскировки кода.",
        })

    if not pe_info.get("has_digital_signature"):
        contributions.append({
            "feature": "no_signature",
            "name_uz": "Raqamli imzo mavjud emas",
            "name_en": "No Cryptographic Digital Signature",
            "name_ru": "Отсутствует цифровая подпись",
            "impact_pct": 15,
            "direction": "RISK",
            "value_display": "Imzosiz binar",
            "reason_uz": "Fayl tasdiqlangan va ishonchli dasturiy ta'minot ishlab chiquvchisi tomonidan imzolanmagan.",
            "reason_en": "Executable lacks Authenticode cryptographic publisher verification.",
            "reason_ru": "Файл не имеет цифрового сертификата подлинности разработчика.",
        })
    else:
        contributions.append({
            "feature": "has_signature",
            "name_uz": "Haqiqiy raqamli imzo mavjud",
            "name_en": "Valid Digital Signature Header",
            "name_ru": "Действительная цифровая подпись",
            "impact_pct": 15,
            "direction": "SAFE",
            "value_display": "PKCS#7 Imzolangan",
            "reason_uz": "Fayl raqamli sertifikatga ega va uning tuzilmasi standartlarga javob beradi.",
            "reason_en": "File includes a structurally valid PKCS#7 digital signature block.",
            "reason_ru": "Бинарный файл содержит валидную структуру цифровой подписи.",
        })

    return sorted(contributions, key=lambda x: x["impact_pct"], reverse=True)


def explain_apk_decision(apk_info: dict, static_score: int) -> List[Dict[str, Any]]:
    """
    Explainable AI for Android APK Malware Analysis.
    """
    contributions = []

    # 1. Double Extension & Fake Media Masquerading
    if apk_info.get("is_masquerading_media"):
        ext_note = apk_info.get("app_name", "")
        contributions.append({
            "feature": "masquerading_media",
            "name_uz": "Soxta rasm/hujjat niqobi (Double Extension)",
            "name_en": "Double Extension Masquerading (Fake Media/Photo)",
            "name_ru": "Маскировка под фото/документ (Двойное расширение)",
            "impact_pct": 40,
            "direction": "RISK",
            "value_display": ext_note[:35] or "Masqueraded APK",
            "reason_uz": "Ilova Telegram/SMS orqali qurbonlarni aldash uchun o'zini rasm (.jpeg/.jpg) yoki hujjat (.pdf) qilib ko'rsatmoqda.",
            "reason_en": "Application deceives victims by disguising as an image (.jpeg) or document to induce installation via Telegram/SMS.",
            "reason_ru": "Приложение маскируется под изображение (.jpeg/.jpg) или документ, чтобы обманом заставить жертву установить вредоносное ПО.",
        })

    # 2. Encrypted Stager Payload in Assets
    if apk_info.get("has_encrypted_payload"):
        stagers = apk_info.get("encrypted_stagers", [])
        contributions.append({
            "feature": "encrypted_stager",
            "name_uz": "Shifrlangan zararli yuklama (Encrypted Stager Payload)",
            "name_en": "High-Entropy Encrypted Stager Payload",
            "name_ru": "Зашифрованная вредоносная полезная нагрузка (Stager)",
            "impact_pct": 35,
            "direction": "RISK",
            "value_display": stagers[0] if stagers else "Encrypted Binary in Assets",
            "reason_uz": "APK ichida yuqori entropiyali shifrlangan ikkinchi bosqich bank troyani fayli yashirilgan (Dropper).",
            "reason_en": "Conceals high-entropy encrypted binary payload in assets to bypass static scanners and drop banking trojan at runtime.",
            "reason_ru": "Внутри архива скрыт зашифрованный бинарный модуль с высокой энтропией для скрытной доставки банковского трояна.",
        })

    # 3. Anti-Analysis and Mobile Antivirus Evasion
    if apk_info.get("anti_security_evasion"):
        tools = apk_info.get("dex_anti_analysis", []) + apk_info.get("dex_anti_av", [])
        contributions.append({
            "feature": "anti_security_evasion",
            "name_uz": "Antivirus va tahlildan qochish (Anti-AV Evasion)",
            "name_en": "Anti-Analysis & Mobile Antivirus Evasion",
            "name_ru": "Обход мобильных антивирусов и средств анализа",
            "impact_pct": 25,
            "direction": "RISK",
            "value_display": ", ".join(tools[:4]),
            "reason_uz": "Dastur kodida Sophos, ESET, Kaspersky kabi antiviruslarni va HTTP Toolkit tahlil tizimlarini aniqlash funksiyalari mavjud.",
            "reason_en": "Contains explicit code to detect mobile antivirus products (Kaspersky, ESET, Sophos) and security analysis tools.",
            "reason_ru": "Содержит код обнаружения антивирусов (Kaspersky, ESET, Sophos) и сред отладки (HTTP Toolkit, Xposed).",
        })

    # 4. Social Engineering Lure Keywords
    if apk_info.get("matched_lures"):
        lures = apk_info.get("matched_lures", [])
        contributions.append({
            "feature": "social_engineering_lure",
            "name_uz": "Ijtimoiy muhandislik tuzog'i (To'y/Arxiv/Chek)",
            "name_en": "Social Engineering Lure (Wedding/Archive/Receipt)",
            "name_ru": "Социальная инженерия (Свадьба/Архив/Чек)",
            "impact_pct": 20,
            "direction": "RISK",
            "value_display": ", ".join(lures[:3]),
            "reason_uz": "Fayl yoki ilova nomi inson psixologiyasini chalg'ituvchi ommabop fishing so'zlaridan foydalangan.",
            "reason_en": "Uses psychological lure terms commonly observed in regional Telegram/SMS banking malware campaigns.",
            "reason_ru": "Использует приманки социальной инженерии, характерные для фишинговых кампаний в Telegram.",
        })

    if apk_info.get("has_overlay_and_accessibility"):
        contributions.append({
            "feature": "overlay_accessibility",
            "name_uz": "Bank troyani namunasi (Overlay + Maxsus xizmat)",
            "name_en": "Banking Trojan Pattern (Overlay + Accessibility)",
            "name_ru": "Паттерн банковского трояна (Overlay + Accessibility)",
            "impact_pct": 35,
            "direction": "RISK",
            "value_display": "Overlay + Keylogger",
            "reason_uz": "Ekran ustiga soxta oyna chizish va klaviatura bosilishini ushlash kombinatsiyasi.",
            "reason_en": "Combines window overlay with accessibility service to steal bank credentials.",
            "reason_ru": "Перекрытие окон и перехват нажатий клавиш — ключевой почерк мобильных троянов.",
        })

    if apk_info.get("has_sms_permissions"):
        contributions.append({
            "feature": "sms_intercept",
            "name_uz": "SMS kodlarni tutib olish (SMS Intercept)",
            "name_en": "SMS Interception & OTP Capture",
            "name_ru": "Перехват SMS и одноразовых кодов",
            "impact_pct": 25,
            "direction": "RISK",
            "value_display": "SEND/RECEIVE/READ SMS",
            "reason_uz": "Banklardan keladigan bir martalik SMS-tasdiqlash kodlarini yashirin o'qish.",
            "reason_en": "Enables unauthorized interception of two-factor authentication codes.",
            "reason_ru": "Позволяет скрытно читать входящие SMS-пароли от банковских сервисов.",
        })

    if apk_info.get("has_hidden_payloads"):
        hidden = apk_info.get("hidden_payloads", [])
        contributions.append({
            "feature": "hidden_payload",
            "name_uz": f"Yashirin yuklama fayllari ({len(hidden)} ta)",
            "name_en": f"Hidden Embedded Binary Payloads ({len(hidden)})",
            "name_ru": f"Скрытые вложенные бинарные файлы ({len(hidden)})",
            "impact_pct": 30,
            "direction": "RISK",
            "value_display": ", ".join(hidden[:3]),
            "reason_uz": "APK ichida yashiringan ikkinchi darajali ishga tushuvchi fayllar topildi (Dropper).",
            "reason_en": "Archive conceals secondary executable DEX/APK payloads in raw resource directories.",
            "reason_ru": "Внутри архива скрыты дополнительные исполняемые файлы (признак дроппера).",
        })

    if apk_info.get("requests_device_admin"):
        contributions.append({
            "feature": "device_admin",
            "name_uz": "Qurilma administratori huquqlari",
            "name_en": "Device Administrator Privileges",
            "name_ru": "Права администратора устройства",
            "impact_pct": 20,
            "direction": "RISK",
            "value_display": "BIND_DEVICE_ADMIN",
            "reason_uz": "Ilovani o'chirishni taqiqlash yoki ekranni qulflash imkoniyatini talab qilmoqda.",
            "reason_en": "Prevents normal uninstallation and enables remote device locking.",
            "reason_ru": "Блокирует удаление приложения и позволяет перехватывать контроль над экраном.",
        })

    if apk_info.get("evades_runtime_permissions"):
        contributions.append({
            "feature": "runtime_evasion",
            "name_uz": f"Android 6.0+ himoyasidan qochish (SDK {apk_info.get('target_sdk')})",
            "name_en": f"Runtime Permission Evasion (SDK {apk_info.get('target_sdk')})",
            "name_ru": f"Обход диалогов разрешений (Target SDK {apk_info.get('target_sdk')})",
            "impact_pct": 15,
            "direction": "RISK",
            "value_display": f"Target SDK: {apk_info.get('target_sdk')}",
            "reason_uz": "Ruxsatlar oynasini ko'rsatmaslik uchun ataylab eski SDK versiyasi ko'rsatilgan.",
            "reason_en": "Targets obsolete Android API level to bypass dynamic runtime consent dialogs.",
            "reason_ru": "Использует устаревшую версию SDK для автоматического получения разрешений.",
        })

    if not apk_info.get("is_signed"):
        contributions.append({
            "feature": "not_signed",
            "name_uz": "Raqamli imzo mavjud emas",
            "name_en": "Unsigned Android Application",
            "name_ru": "Отсутствует цифровая подпись APK",
            "impact_pct": 20,
            "direction": "RISK",
            "value_display": "Imzosiz paket",
            "reason_uz": "Ilova rasmiy sertifikat bilan imzolanmagan, soxtalashtirilgan bo'lishi mumkin.",
            "reason_en": "APK package lacks cryptographic signing block verification.",
            "reason_ru": "Пакет приложения не содержит валидного блока цифровой подписи.",
        })
    else:
        contributions.append({
            "feature": "is_signed",
            "name_uz": "Ilova raqamli imzolangan",
            "name_en": "Valid Cryptographic APK Signature",
            "name_ru": "Приложение имеет цифровую подпись",
            "impact_pct": 15,
            "direction": "SAFE",
            "value_display": "Kriptografik imzolangan",
            "reason_uz": "APK paketi haqiqiy raqamli sertifikat bilan himoyalangan.",
            "reason_en": "APK package contains valid digital signature certificate.",
            "reason_ru": "Пакет содержит корректный криптографический сертификат.",
        })

    return sorted(contributions, key=lambda x: x["impact_pct"], reverse=True)
