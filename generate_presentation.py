"""
generate_presentation.py
-------------------------
PhishGuard AI — Bitiruv Malakaviy Ishi (BMI / Diplom) Himoyasi Uchun
Professional 12-Slaydli PowerPoint (.pptx) Taqdimotini Generatsiya Qilish.

Dizayn:
  - 16:9 Widescreen (13.333 x 7.5 dyuym)
  - Cyber Defense SOC Dark Palette (Deep Dark #070B14, Navy Panel #111A2E, Neon Cyan #00F0FF)
  - Har bir slayd ostida talaba/spiker uchun to'liq himoya nutqi (Speaker Notes) biriktirilgan.
"""

import sys
from pathlib import Path
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

OUTPUT_FILE = Path("C:/Users/user_15184/Desktop/Phishguard-ai/PhishGuard_AI_Himoya_Taqdimoti.pptx")

# Ranglar palitrasi
COLOR_BG = RGBColor(7, 11, 20)           # #070B14 (Ultra Deep Dark)
COLOR_PANEL = RGBColor(17, 26, 46)       # #111A2E (Glassmorphism Navy Card)
COLOR_PANEL_BORDER = RGBColor(35, 50, 85)# Border highlight
COLOR_CYAN = RGBColor(0, 240, 255)       # #00F0FF (Neon Cyber Cyan)
COLOR_BLUE = RGBColor(59, 130, 246)      # #3B82F6 (Primary Blue)
COLOR_GREEN = RGBColor(16, 185, 129)     # #10B981 (Success / Safe)
COLOR_YELLOW = RGBColor(245, 158, 11)    # #F59E0B (Warning / Medium)
COLOR_RED = RGBColor(239, 68, 68)        # #EF4444 (Critical / Threat)
COLOR_WHITE = RGBColor(248, 250, 252)    # #F8FAFC (Main Title Text)
COLOR_SLATE = RGBColor(148, 163, 184)    # #94A3B8 (Subtitle / Body Text)
COLOR_DIM = RGBColor(100, 116, 139)      # #64748B (Footer text)


def create_presentation():
    prs = Presentation()
    # 16:9 Widescreen o'lchami
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6] # Blank slide

    def set_slide_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = COLOR_BG
        bg.line.fill.background() # No border
        return bg

    def add_header(slide, title_text, category="PHISHGUARD AI — FORENSIC SOC DEFENSE PLATFORM"):
        # Category tag
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11), Inches(0.35))
        tf_c = cat_box.text_frame
        tf_c.word_wrap = True
        p_c = tf_c.paragraphs[0]
        p_c.text = category.upper()
        p_c.font.size = Pt(10)
        p_c.font.bold = True
        p_c.font.color.rgb = COLOR_CYAN
        p_c.font.name = "Arial"

        # Main Slide Title
        t_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.7), Inches(0.8))
        tf = t_box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title_text
        p.font.size = Pt(24)
        p.font.bold = True
        p.font.color.rgb = COLOR_WHITE
        p.font.name = "Arial"

        # Subtle separator line
        line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.5), Inches(11.7), Inches(0.02))
        line.fill.solid()
        line.fill.fore_color.rgb = COLOR_PANEL_BORDER
        line.line.fill.background()

    def add_card(slide, left, top, width, height, title, items, badge="", badge_color=COLOR_CYAN, title_color=COLOR_WHITE):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        card.fill.solid()
        card.fill.fore_color.rgb = COLOR_PANEL
        card.line.color.rgb = COLOR_PANEL_BORDER
        card.line.width = Pt(1.5)

        tf = card.text_frame
        tf.word_wrap = True
        tf.margin_left = Inches(0.25)
        tf.margin_right = Inches(0.25)
        tf.margin_top = Inches(0.25)
        tf.margin_bottom = Inches(0.2)

        # Title
        p0 = tf.paragraphs[0]
        p0.text = (badge + "  " if badge else "") + title
        p0.font.size = Pt(16)
        p0.font.bold = True
        p0.font.color.rgb = title_color
        p0.font.name = "Arial"
        p0.space_after = Pt(10)

        # Bullets
        for item in items:
            p = tf.add_paragraph()
            p.text = "• " + item
            p.font.size = Pt(12)
            p.font.color.rgb = COLOR_SLATE
            p.font.name = "Arial"
            p.space_after = Pt(6)

    def set_speaker_notes(slide, notes_text):
        notes_slide = slide.notes_slide
        tf = notes_slide.notes_text_frame
        tf.text = notes_text

    # ========================================================
    # 1-SLAYD: TITUL / MUQOVA
    # ========================================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    # Decorative Cyan Bar
    bar = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.4), Inches(0.15), Inches(4.5))
    bar.fill.solid()
    bar.fill.fore_color.rgb = COLOR_CYAN
    bar.line.fill.background()

    tb = s1.shapes.add_textbox(Inches(1.2), Inches(1.2), Inches(11.0), Inches(5.0))
    tf1 = tb.text_frame
    tf1.word_wrap = True

    p = tf1.paragraphs[0]
    p.text = "BITIRUV MALAKAVIY ISHI (BMI / DIPLOM ISHI HIMOYASI)"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_CYAN
    p.space_after = Pt(16)

    p = tf1.add_paragraph()
    p.text = "PhishGuard AI — Ko'p Pog'onali Kiberxavfsizlik va Intellektual Tahdidlarni Tahlil Qilish Platformasi"
    p.font.size = Pt(28)
    p.font.bold = True
    p.font.color.rgb = COLOR_WHITE
    p.space_after = Pt(20)

    p = tf1.add_paragraph()
    p.text = "Multi-Layer Cyber Threat Detection, Reverse Engineering & Forensic Threat Intelligence Engine"
    p.font.size = Pt(14)
    p.font.color.rgb = COLOR_SLATE
    p.space_after = Pt(36)

    p = tf1.add_paragraph()
    p.text = "Talaba:  RusiMa12                                         Ilmiy Rahbar:  Axborot Xavfsizligi Kafedrasi"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = COLOR_WHITE
    p.space_after = Pt(10)

    p = tf1.add_paragraph()
    p.text = "Jonli Veb-Ilova: https://phishguard-soc.netlify.app       GitHub: https://github.com/RusiMa12/Phishguard-ai"
    p.font.size = Pt(11)
    p.font.color.rgb = COLOR_CYAN

    set_speaker_notes(s1, "Assalomu alaykum, hurmatli Davlat Attestatsiya Komissiyasi raisi, a'zolari va mehmonlar! Bugungi kunda raqamli iqtisodiyot va to'lov tizimlarining shiddatli rivojlanishi sharoitida kiber-hujumlar jamiyat va iqtisodiyot uchun eng jiddiy xavfga aylandi. E'tiboringizga havola etilayotgan 'PhishGuard AI' loyihasi — veb-havolalar, Windows dasturlari va Android APK ilovalarini sun'iy intellekt va ko'p qatlamli sintez orqali xavfsiz tahlil qiluvchi innovatsion platformadir. Ruxsatingiz bilan loyiha taqdimotini boshlasam.")

    # ========================================================
    # 2-SLAYD: MUAMMONING DOLZARBLIGI
    # ========================================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "Muammoning Dolzarbligi va An'anaviy Usullarning Cheklovlari")

    add_card(s2, Inches(0.8), Inches(1.8), Inches(3.6), Inches(4.8),
             "1. Oddiy Qoidalar (Rule-Based)",
             ["Tez va tushunarli, lekin o'ta qolipiy (rigid).",
              "Faqat ma'lum shablonlar bilan ishlaydi.",
              "Yangi avlod gomoglif va obfuskatsiya usullarini o'tkazib yuboradi.",
              "Har bir yangi hujum turiga qo'lda qoida yozishni talab qiladi."],
             badge="⚠️", title_color=COLOR_YELLOW)

    add_card(s2, Inches(4.8), Inches(1.8), Inches(3.6), Inches(4.8),
             "2. Sof Machine Learning",
             ["Statistik korrelyatsiyalarni juda yaxshi ushlaydi.",
              "Biroq to'liq 'Qora quti' (Black-box) bo'lib qoladi.",
              "Nima uchun xavfli deb baholaganini tushuntirib berolmaydi.",
              "Domen reputatsiyasi va brend kontekstini hisobga ololmaydi."],
             badge="🧠", title_color=COLOR_BLUE)

    add_card(s2, Inches(8.8), Inches(1.8), Inches(3.6), Inches(4.8),
             "3. Antiviruslar (VirusTotal)",
             ["Eski va ma'lum viruslar uchun juda ishonchli.",
              "Biroq mutlaqo yangi Zero-Day namunalar oldida ojiz.",
              "Yangi virusga 0/70 ko'rsatkich berib, foydalanuvchini aldaydi.",
              "Qimmat korporativ litsenziya va so'rovlar limiti mavjud."],
             badge="🛡️", title_color=COLOR_RED)

    set_speaker_notes(s2, "Kiberxavfsizlikda mavjud 3 ta an'anaviy yondashuvning hech biri alohida olinganda to'liq xavfsizlikni bera olmaydi. Qoidalar yangi nayranglarni o'tkazib yuboradi; sun'iy intellekt sababini tushuntirib bera olmaydi; VirusTotal kabi global bazalar esa hali katalogga kirmagan Zero-Day tahdidlar oldida ojiz. PhishGuard AI loyihasining dolzarbligi — ushbu uchala manbani yagona gibrid sintezga birlashtirib, har birining kamchiligini boshqasi orqali bartaraf etishidadir.")

    # ========================================================
    # 3-SLAYD: MAQSAD VA ASOSIY VAZIFALAR
    # ========================================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "Tadqiqotning Maqsadi va Asosiy Ilmiy-Amaliy Vazifalari")

    add_card(s3, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "Tadqiqotning Bosh Maqsadi",
             ["Foydalanuvchi va SOC tahlilchisi uchun shubhali obyektlarni (URL, EXE, APK) kompyuterda ochmasdan turib xavfini 0-100% oraliqda aniqlovchi xavfsiz intellektual platforma yaratish.",
              "Faqatgina ball berib qolmay, xalqaro MITRE ATT&CK standartida har bir indikatorning ta'sirini tushuntirib berish (Explainable AI).",
              "O'zbekiston kiber-makoniga xos milliy to'lov tizimlari va fishing nayranglariga qarshi moslashgan himoyani ta'minlash."],
             badge="🎯", title_color=COLOR_CYAN)

    add_card(s3, Inches(6.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "Amaliy Vazifalar",
             ["1. Veb-havolalardan 26 ta leksik xususiyatni ajratib olib, Random Forest ML modelini 133k+ datasetda o'rgatish.",
              "2. Windows PE (Portable Executable) formatini xotirada chuqur tahlil qilib, xavfli API klasterlarini aniqlash.",
              "3. Android APK ilovalarining ruxsatnomalar matritsasi va Telegram aldovlarini filtrlash.",
              "4. Zero-Day paradoksini yechuvchi dinamik 'Risk Fusion' formulasini ishlab chiqish va sinovdan o'tkazish."],
             badge="📋", title_color=COLOR_GREEN)

    set_speaker_notes(s3, "Tadqiqotimizning bosh maqsadi — kompyuter va serverni xavf ostiga qo'ymasdan, to'liq xotirada (In-Memory) statik tahlil va mashinali o'rganish sintezini amalga oshirishdir. Asosiy vazifalar sifatida 26 ta leksik belgi bo'yicha URL ML modelini o'rgatish, Windows PE va Android APK strukturaviy tahlilini yo'lga qo'yish hamda Zero-Day paradoksini yechuvchi dinamik Risk Fusion algoritmini ishlab chiqish belgilandi.")

    # ========================================================
    # 4-SLAYD: TIZIM ARXITEKTURASI
    # ========================================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "PhishGuard AI — 5 Pog'onali Gibrid Arxitekturasi")

    cards_data = [
        ("1. INTAKE", ["URL / EXE / APK", "Hajm cheklovi", "Path sanitization"], "📥"),
        ("2. HEURISTICS", ["26 leksik belgi", "PE W+X & Entropiya", "APK ruxsatnomalar"], "🔍"),
        ("3. AI ENGINE", ["Random Forest URL", "Random Forest PE", "VirusTotal v3"], "🧠"),
        ("4. RISK FUSION", ["Zero-Day Defense", "Dinamik vaznlar", "0-100% Risk Score"], "⚖️"),
        ("5. FORENSICS", ["Explainable AI (XAI)", "YARA 4.x Qoidasi", "SOC PDF Hisobot"], "📊")
    ]
    w = Inches(2.2)
    for idx, (title, items, icon) in enumerate(cards_data):
        pos_x = Inches(0.8 + idx * 2.38)
        add_card(s4, pos_x, Inches(1.8), w, Inches(4.8), title, items, badge=icon, title_color=COLOR_CYAN)

    set_speaker_notes(s4, "Slaydda PhishGuard AI ning 5 pog'onali axborot oqimi ko'rsatilgan. 1-bosqichda kiruvchi obyektlar sanitizatsiya qilinadi. 2-bosqichda statik evristik belgilar ajratiladi. 3-bosqichda o'rgatilgan Random Forest modeli va VirusTotal ulanadi. 4-bosqichda biz ishlab chiqqan Risk Fusion mexanizmi barchasini yagona ballga keltiradi. 5-bosqichda esa XAI tushuntirish, YARA qoidasi va rasmiy PDF hisobot shakllantiriladi.")

    # ========================================================
    # 5-SLAYD: URL SCANNER VA MACHINE LEARNING
    # ========================================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "1-Qatlam: Veb-Havolalar (URL) Tahlili va Random Forest ML")

    add_card(s5, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "26 Ta Leksik-Strukturaviy Belgilar",
             ["URL, Hostname va Path belgilar uzunligi (scheme-siz).",
              "Shannon Entropiyasi — avtomatik DGA (Domain Generation Algorithm) domenlarini aniqlash.",
              "To'g'ridan-to'g'ri IP-manzil orqali ochilgan xostlar.",
              "Gomoglif va Punycode (IDN) almashtirishlari.",
              "Qisqartirilgan havolalar (bit.ly, tinyurl) va xavfli TLDlar.",
              "Shubhali kalit so'zlar: login, verify, banking, update, confirm."],
             badge="🌐", title_color=COLOR_CYAN)

    add_card(s5, Inches(6.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "ML Natijalari (133k Balanslangan Dataset)",
             ["Algoritm: Random Forest Classifier (200 ta daraxt).",
              "Optimizatsiya: RandomizedSearchCV + 5-Fold Cross-Validation.",
              "Accuracy (Aniqlik): 88.0%",
              "Precision (Aniqlik darajasi): 88.4%",
              "Recall (To'liqlik ko'rsatkichi): 87.7%",
              "F1-Score (Garmonik o'rtacha): 88.0%",
              "XGBoost taqqoslashi: 87.1% (Random Forest barqarorroq bo'ldi)."],
             badge="📈", title_color=COLOR_GREEN)

    set_speaker_notes(s5, "Veb-havolalar tahlilida 26 ta leksik xususiyat ajratiladi. Shannon entropiyasi avtomatik generatsiya qilingan fishing domenlarini ushlashda yuqori samaradorlik ko'rsatdi. Biz 133 090 ta balanslangan ma'lumotlar to'plamida Random Forest va XGBoost algoritmlarini solishtirdik. Random Forest 5 bosqichli kross-validatsiyada 88.0% F1-score ko'rsatkichini berib, yuqori barqarorlikni namoyish etdi.")

    # ========================================================
    # 6-SLAYD: WINDOWS PE (EXE) FORENSIK TAHLILI
    # ========================================================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "2-Qatlam: Windows PE (EXE) Fayllarini Xotirada Chuqur Tahlil Qilish")

    add_card(s6, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "PE Strukturaviy Indikatorlari",
             ["Pure In-Memory Parsing: Fayl diskka tushmaydi va ishga tushmaydi.",
              "Shannon Entropiyasi > 7.0 — shifrlangan yoki pakerlangan tana.",
              "W+X (Write + Execute) Anomaliyasi — bir vaqtda xotiraga yozish va bajarish huquqi (polimorfik kod belgisi).",
              "Pakerlar deteksiyasi: UPX, Themida, VMProtect.",
              "Soxta yoki nosoz PKCS#7 raqamli xavfsizlik sertifikatlari.",
              "TLS Callbacks — asosiy dastur boshlanishidan oldin kod chaqirish."],
             badge="🖥️", title_color=COLOR_CYAN)

    add_card(s6, Inches(6.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "MITRE ATT&CK Win32 API Klasterlari",
             ["T1055 (Process Injection): VirtualAllocEx, WriteProcessMemory, CreateRemoteThread kombinatsiyasi.",
              "T1055.012 (Process Hollowing): NtUnmapViewOfSection, SetThreadContext, ResumeThread.",
              "T1056.001 (Keylogging): SetWindowsHookEx, GetAsyncKeyState.",
              "T1497 (Defense Evasion): IsDebuggerPresent, CheckRemoteDebugger.",
              "T1486 (Ransomware Strings): 'vssadmin delete shadows', 'wbadmin' buyruqlarining xom baytlarda uchrashi."],
             badge="⚔️", title_color=COLOR_RED)

    set_speaker_notes(s6, "Windows ijro fayllari tahlilida `pefile` kutubxonasi orqali fayl sarlavhalari, entropiya va import jadvallari tekshiriladi. Eng katta yutug'imiz — xavfli Win32 API funksiyalarini alohida emas, MITRE ATT&CK hujum klasterlariga birlashtirganimizdir. Agar dasturda xotiraga joy ajratish va masofadan oqim yaratish birgalikda aniqlansa, tizim buni Process Injection deb to'g'ri baholaydi.")

    # ========================================================
    # 7-SLAYD: ANDROID APK TROYANLARI TAHLILI
    # ========================================================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7)
    add_header(s7, "3-Qatlam: Android APK Troyanlari va Mobil Bank Xavfsizligi")

    add_card(s7, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "AndroidManifest.xml Tahlili & Ruxsatnomalar",
             ["pyaxmlparser orqali binar XML manifestini xotirada dekodlash.",
              "Klassik Bank Troyani Sxemasi: SYSTEM_ALERT_WINDOW (Overlay) + BIND_ACCESSIBILITY_SERVICE.",
              "SMS / OTP O'g'irlash: SEND_SMS, RECEIVE_SMS, READ_SMS.",
              "Yashirin Kuzatuv: RECORD_AUDIO, CAMERA, ACCESS_FINE_LOCATION.",
              "Dropper Xususiyati: REQUEST_INSTALL_PACKAGES (boshqa ilovalarni yashirin o'rnatish)."],
             badge="📱", title_color=COLOR_CYAN)

    add_card(s7, Inches(6.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "O'zbekiston Telegram Lures (Aldov So'zlar Lug'ati)",
             ["Mahalliy fishingchilar Telegram orqali tarqatayotgan soxta nomlar:",
              "O'zbekcha aldovlar: 'to'y', 'kelin', 'fotolar', 'jarima', 'soliq', 'kvitansiya', 'ovoz_bering', 'sovg'a'.",
              "Ijtimoiy muhandislik: Foydalanuvchi foto-arxiv deb o'ylab, bank parolini o'g'irlovchi troyanni o'rnatib oladi.",
              "Imzosiz APKlar va shubhali ruxsatlar kombinatsiyasi darhol bloklanadi."],
             badge="🚨", title_color=COLOR_YELLOW)

    set_speaker_notes(s7, "O'zbekiston kiber-muhiti uchun eng og'riqli nuqta — Telegram orqali tarqalayotgan zararli APK fayllardir. Tadqiqotimizda binar manifest XML tahlil qilinib, bank troyanlariga xos Overlay va Accessibility ruxsatnomalarining birgalikda so'ralishi aniqlanadi. Shuningdek, 'to'y rasmlari' yoki 'jarima kvitansiyasi' kabi mashhur aldov so'zlari lug'ati orqali ijtimoiy muhandislik hujumlari fosh etiladi.")

    # ========================================================
    # 8-SLAYD: ILMIY YANGILIK — ZERO-DAY PARADOKSI
    # ========================================================
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8)
    add_header(s8, "Ilmiy Yangilik: Zero-Day Paradoksi va Dinamik Risk Fusion Dvigateli")

    add_card(s8, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "Zero-Day Paradoksi Nima?",
             ["Muammo: Yangi virus hali hech qaysi antivirus bazasiga kirmagan.",
              "Oqibat: VirusTotal 0/70 (toza) deb qaytaradi. Oddiy tizimlar uni 'Xavfsiz' deb adashadi.",
              "Yechim: Agar lokal evristika xavfli belgilarni aniqlasa (S_local >= 60%), tashqi bazaning nol natijasiga qaramay, lokal tahlilga 80% ustuvorlik beriladi.",
              "Natija: Yangi va unikal viruslar ham o'tkazib yuborilmaydi."],
             badge="💡", title_color=COLOR_GREEN)

    add_card(s8, Inches(6.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "Dinamik Matematik Konsensus Formulalari",
             ["Final Score = w_local * S_local + w_vt * S_vt",
              "1. Kuchli Konsensus (VT >= 5 ta dvijok tasdiqlasa):",
              "   w_vt = 0.8  (va minimal kafolatlangan ball 75%)",
              "2. Noaniq Zona (1-4 ta dvijok shubhalansa):",
              "   w_vt = 0.5, w_local = 0.5  (yolg'on trevogalarni elash)",
              "3. Zero-Day Himoyasi (VT = 0, lekin S_local >= 60):",
              "   w_local = 0.8, w_vt = 0.2  (lokal tahlil g'olib chiqadi)."],
             badge="📐", title_color=COLOR_CYAN)

    set_speaker_notes(s8, "Ishimizning asosiy ilmiy-nazariy yangiligi — 'Zero-Day Paradoksi'ning hal etilishidir. Oddiy tizimlar VirusTotal nol ko'rsatkich bersa, virusni xavfsiz deb hisoblaydi. Biz ishlab chiqqan 'Risk Fusion' modelida, agar lokal tahlil jiddiy xavf belgilarini topsa, tashqi bazaning nol ko'rsatkichiga qaramasdan lokal tahlilga 80% vazn beriladi. Bu esa xalqaro bazalarda hali ro'yxatga olinmagan yangi tahdidlarni o'tkazib yubormaslikni ta'minlaydi.")

    # ========================================================
    # 9-SLAYD: EXPLAINABLE AI (XAI) VA YARA GENERATORI
    # ========================================================
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_background(s9)
    add_header(s9, "Explainable AI (XAI) va Avtomatlashtirilgan YARA 4.x Generatori")

    add_card(s9, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "Explainable AI (Feature Attribution)",
             ["Qora quti (black-box) muammosining to'liq yechilishi.",
              "Har bir belgining riskka qo'shgan hissasi foizlarda ko'rsatiladi:",
              "  • Brendni soxtalashtirish: +30% xavf",
              "  • To'g'ridan-to'g'ri IP-manzil: +25% xavf",
              "  • '@' belgisi bilan maskalash: +20% xavf",
              "  • HTTPS mavjudligi: -10% (ijobiy xavfsizlik signali)",
              "SOC tahlilchisi qaror sababini bir qarashda tushunadi."],
             badge="🔍", title_color=COLOR_CYAN)

    add_card(s9, Inches(6.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "Avtomatlashtirilgan YARA 4.x Dvigateli",
             ["Har bir aniqlangan tahdid uchun bir tugma bilan YARA qoidasi yaratiladi.",
              "Xalqaro TLP:AMBER klassifikatsiyasi va MITRE ATT&CK texnikalari kiritiladi.",
              "Korporativ SIEM/SOAR tizimlariga (Wazuh, Splunk, QRadar) to'g'ridan-to'g'ri integratsiya qilinadi.",
              "Pure-Python SOC PDF Eksport: Hech qanday tashqi kutubxonalarsiz rasmiy ekspertiza xulosasini PDF 1.4 da yuklab olish."],
             badge="📜", title_color=COLOR_GREEN)

    set_speaker_notes(s9, "Zamonaviy SOC talablariga binoan AI shunchaki raqam berib qolmasdan, qarorini isbotlab berishi kerak. Explainable AI modulimiz har bir belgining xavfga qo'shgan foizini aniq ko'rsatadi. Bundan tashqari, aniqlangan har qanday havola, EXE yoki APK uchun tizim avtomatik ravishda xalqaro standartdagi YARA qoidasini va rasmiy PDF ekspertiza hisobotini generatsiya qiladi.")

    # ========================================================
    # 10-SLAYD: BRAND RADAR VA MAHALLIY ADAPTATSIYA
    # ========================================================
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_background(s10)
    add_header(s10, "O'zbekiston Kiber-Makoniga Moslashtirilganlik: Brand Radar")

    add_card(s10, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "O'zbekiston Brend Radari (Brand Radar)",
             ["10 ta eng yirik milliy brendlar monitoringi: Payme, Click, Uzum, Hamkorbank, NBU, Anorbank, Soliq.uz, MyGov, Kun.uz.",
              "Typosquatting & Klon Domenlar: 'payme-tasdiqlash.uz', 'click-bonus.uz' kabi soxta nomlarni avtomatik aniqlash.",
              "Ko'p bo'g'inli ccSLD domenlar: .com.uz, .co.uz, .gov.uz zonalarini to'g'ri ajratib olish.",
              "Mahalliy Geotelemetriya: Viloyatlar o'rtasidagi kiber-hujumlar traektoriyalari monitoringi."],
             badge="🏢", title_color=COLOR_CYAN)

    add_card(s10, Inches(6.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "Gomoglif (Punycode) Hujumlari",
             ["Kirill/Lotin almashtirish nayrangi: 'google.com' dagi 'o' harfini kirillcha 'о' bilan yozish.",
              "IDNA standarti bo'yicha bu 'xn--ggle-p50aa.com' ga aylanadi.",
              "PhishGuard AI brauzer darajasida Punycode mavjudligini ushlaydi va darhol xavf sifatida baholaydi.",
              "Global antiviruslar bilmaydigan milliy kontekstni 100% qamrab oladi."],
             badge="🇺🇿", title_color=COLOR_YELLOW)

    set_speaker_notes(s10, "Global antiviruslar Payme yoki Click O'zbekiston uchun qanchalik muhim to'lov tizimi ekanligini bilmaydi. Biz yaratgan 'Brend Radari' 10 dan ortiq milliy bank va portallarning klon domenlarini, kirill harflari orqali yozilgan gomoglif soxta saytlarni va ko'p bo'g'inli ccSLD zonalarini to'liq hisobga oladi. Bu esa xalqaro tizimlarga qaraganda mahalliy fishingni ancha erta aniqlash imkonini beradi.")

    # ========================================================
    # 11-SLAYD: JONLI EKOSISTEMA VA TATBIQ
    # ========================================================
    s11 = prs.slides.add_slide(blank_layout)
    set_slide_background(s11)
    add_header(s11, "PhishGuard AI — Jonli Amaliy Ekosistema")

    ecosystem = [
        ("🌐 Jonli Veb-SOC", ["https://phishguard-soc.netlify.app", "Netlify CDN global tarmog'i", "Glassmorphism interfeys"], COLOR_CYAN),
        ("🧩 Chrome Kengaytmasi", ["Manifest V3 arxitekturasi", "Real vaqtda saytni tekshirish", "Xavfli saytni avtomatik bloklash"], COLOR_BLUE),
        ("🤖 Telegram SOC Bot", ["Mobil qurilmalar uchun", "Havola va fayllarni skanerlash", "PDF xulosani bot orqali olish"], COLOR_GREEN),
        ("🐙 GitHub Open-Source", ["RusiMa12/Phishguard-ai", "Avtomatlashtirilgan CI/CD", "MIT ochiq litsenziyasi"], COLOR_YELLOW)
    ]
    w_e = Inches(2.78)
    for idx, (title, items, color) in enumerate(ecosystem):
        pos_x = Inches(0.8 + idx * 2.97)
        add_card(s11, pos_x, Inches(1.8), w_e, Inches(4.8), title, items, title_color=color)

    set_speaker_notes(s11, "Loyihamiz shunchaki nazariya emas — u to'laqonli ishlab turgan jonli ekotizimdir! Frontend qismi Netlify platformasida global tarmoqda ishlab turibdi. Foydalanuvchilar veb-sayt orqali, Google Chrome kengaytmasi orqali yoki Telegram bot orqali tizimdan bemalol foydalanishlari mumkin. Barcha kodlar va avtomatlashtirilgan CI/CD pipeline GitHub platformasida ochiq manba sifatida joylashtirilgan.")

    # ========================================================
    # 12-SLAYD: XULOSA VA AMALIY QIYMAT
    # ========================================================
    s12 = prs.slides.add_slide(blank_layout)
    set_slide_background(s12)
    add_header(s12, "Xulosa, Ilmiy-Iqtisodiy Samaradorlik va Kelgusi Rejalar")

    add_card(s12, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "Asosiy Xulosalar & Amaliy Qiymat",
             ["1. Ko'p pog'onali tahlil orqali tahdidlarni aniqlash samaradorligi an'anaviy usullarga nisbatan 25-30% ga oshirildi.",
              "2. Zero-Day tahdidlarni lokal statik tahlil orqali ushlab qolish mexanizmi isbotlandi.",
              "3. 88% aniqlikka ega Random Forest ML modeli va XAI moduli muvaffaqiyatli integratsiya qilindi.",
              "4. Iqtisodiy samara: Xorijiy qimmatbaho litsenziyalarga muqobil bepul milliy kiber-qalqon yaratildi."],
             badge="✅", title_color=COLOR_GREEN)

    add_card(s12, Inches(6.8), Inches(1.8), Inches(5.6), Inches(4.8),
             "Kelgusi Rejalar & Savol-Javob",
             ["• Dinamik Cuckoo/CAPE Sandbox virtual muhitlari bilan to'liq avtomatik detonation integratsiyasi.",
              "• Korporativ SIEM/SOAR tizimlari (Wazuh, Splunk) uchun Syslog telemetriyasi.",
              "• Banklar va to'lov tashkilotlari ichki perimetriga joriy etish.",
              "\nE'TIBORINGIZ UCHUN KATTA RAHMAT!",
              "Savollaringiz bo'lsa, mamnuniyat bilan javob berishga tayyorman!"],
             badge="🚀", title_color=COLOR_CYAN)

    set_speaker_notes(s12, "Xulosa qilib aytganda, ishlab chiqilgan PhishGuard AI platformasi kiber-tahdidlarga qarshi samarali, tushuntiriluvchan va tejamkor yechim ekanligini to'liq isbotladi. Tizim tijorat banklari, to'lov tashkilotlari va korxonalarda mustaqil xavfsizlik shlyuzi sifatida joriy etilishga to'liq tayyor. E'tiboringiz uchun katta rahmat! Savollaringiz bo'lsa, bajonidil javob beraman.")

    # Save to disk
    prs.save(OUTPUT_FILE)
    print(f"Presentation saved successfully to: {OUTPUT_FILE}")


if __name__ == "__main__":
    create_presentation()
