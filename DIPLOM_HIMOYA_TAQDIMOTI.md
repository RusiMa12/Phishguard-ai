# 🎓 PhishGuard AI — Bitiruv Malakaviy Ishi (BMI / Diplom) Himoyasi Uchun Mukammal Taqdimot va Ssenariy

> **Mavzu:** Ko'p Pog'onali Kiberxavfsizlik va Intellektual Tahdidlarni Tahlil Qilish Platformasini Ishlab Chiqish (PhishGuard AI)  
> **Muallif:** RusiMa12  
> **Format:** 12 ta Slayd Ssenariysi + Himoya Nutqi (7-8 daqiqa) + Komissiyaning 10 ta Murakkab Savol-Javoblari  
> **Jonli Platforma:** [https://phishguard-soc.netlify.app](https://phishguard-soc.netlify.app)  
> **GitHub Repozitoriy:** [https://github.com/RusiMa12/Phishguard-ai](https://github.com/RusiMa12/Phishguard-ai)

---

# I QISM: 12 TA SLAYDNING VIZUAL TUZILISHI VA HIMOYACHI NUTQI

---

### 1-SLAYD: Kirish va Muqova (Title Slide)
* **Vizual qism:** Markazda PhishGuard AI logotipi (Qalqon va neon chiziqlar). O'ng tomonda jonli Netlify sayti va GitHub havolasi QR-kodi. To'q ko'k kiberxavfsizlik SOC uslubidagi zamonaviy fon.
* **Slayddagi matn:**
  - **Mavzu:** Sun'iy Intellekt va Ko'p Pog'onali Sintez Asosida Kiber-Tahdidlarni Tahlil Qilish Platformasi
  - **Bitiruvchi:** [Ismingiz Sharifingiz]
  - **Ilmiy rahbar:** [Ilmiy Rahbaringizning Ismi, Ilmiy darajasi]
  - **OTM / Kafedra:** Axborot Xavfsizligi va Kiberxavfsizlik kafedrasi (2026-yil)
* 🎤 **Himoya nutqi (45 soniya):**
  > *"Assalomu alaykum, hurmatli Davlat Attestatsiya Komissiyasi raisi, a'zolari va qatnashchilar! Bugungi kunda raqamli iqtisodiyot va to'lov tizimlarining jadal rivojlanishi bilan bir qatorda kiber-jinoyatchilarning fishing, zararli dasturlar va troyanlar orqali fuqarolar va korxonalarga qilayotgan hujumlari eng jiddiy xavflardan biriga aylandi. E'tiboringizga havola etilayotgan bitiruv malakaviy ishim **'PhishGuard AI — Ko'p Pog'onali Kiberxavfsizlik va Tahdidlarni Tahlil Qilish Platformasi'** deb nomlanadi. Ruxsatingiz bilan loyihaning dolzarbligi, arxitekturasi va olingan ilmiy-amaliy natijalarni bayon etishga kirishsam."*

---

### 2-SLAYD: Muammoning Dolzarbligi va Kamchiliklar (Problem Statement)
* **Vizual qism:** 3 ta qiyosiy infografika:
  1. *Oddiy qoidalar (Rule-based):* Moslashuvchan emas, yangi nayranglarni o'tkazib yuboradi.
  2. *Sof Machine Learning:* "Qora quti" (Black-box), sababini tushuntirib berolmaydi, reputatsiyani bilmaydi.
  3. *Tashqi antiviruslar (VirusTotal):* Zero-Day (yangi) viruslarni umuman tanimaydi (0/70 natija beradi).
* **Slayddagi matn:**
  - Kiber-hujumlarning 90% dan ortig'i fishing havolalari va ijtimoiy muhandislik orqali sodir etiladi.
  - O'zbekiston kiber-makonida soxta to'lov tizimlari (Payme/Click klonlari) va Telegram orqali tarqaluvchi zararli APK fayllar keskin ko'paygan.
  - **Mavjud muammo:** Alohida olingan hech bir tahlil usuli 100% samaradorlik bera olmaydi.
* 🎤 **Himoya nutqi (45 soniya):**
  > *"Kiberxavfsizlik sohasida uchta asosiy tahlil yondashuvi mavjud: qoidalarga asoslangan evristika, mashinali o'rganish va global antivirus bazalari. Biroq ularning har biri jiddiy kamchiliklarga ega: qoidalar tez eskiradi; AI modeli nima uchun xavfli deganini tushuntirib berolmaydi; VirusTotal esa hali bazaga kirmagan mutlaqo yangi Zero-Day tahdidlar oldida ojiz. Ayniqsa O'zbekistonda milliy to'lov tizimlariga taqlid qiluvchi klon domenlar va Telegram orqali tarqalayotgan bank troyanlari an'anaviy himoya vositalarini osongina aylanib o'tmoqda."*

---

### 3-SLAYD: Tadqiqotning Maqsadi va Asosiy Vazifalari
* **Vizual qism:** Maqsad markazda joylashgan bo'lib, undan 4 ta yo'nalish strelkalar orqali tarmoqlanadi.
* **Slayddagi matn:**
  - **Bosh maqsad:** Hech qanday faylni ochmasdan va havolaga kirmasdan turib, xavfni xavfsiz aniqlovchi va tushuntirib beruvchi yagona intellektual platforma yaratish.
  - **Vazifalar:**
    1. Veb-havolalardan (URL) 26 ta leksik-strukturaviy belgilarni ajratib olish va Random Forest modelini o'rgatish;
    2. Windows PE/EXE fayllarini xotirada chuqur statik tahlil qilish;
    3. Android APK ilovalarining manifest va ruxsatnomalar matritsasini tekshirish;
    4. Barcha manbalarni yagona 'Risk Fusion Engine' orqali birlashtirib, Zero-Day paradoksini yechish.
* 🎤 **Himoya nutqi (40 soniya):**
  > *"Tadqiqotimizning bosh maqsadi — foydalanuvchi yoki SOC tahlilchisiga kelgan har qanday shubhali havola, Windows ijro fayli yoki Android dasturini xavfsiz xotira tahlili, mashinali o'rganish va global razvedka sintezi orqali tahlil qiluvchi ko'p pog'onali intellektual tizimni ishlab chiqishdir. Bunda nafaqat xavf darajasini foizlarda (0-100%) hisoblash, balki xalqaro MITRE ATT&CK standartiga muvofiq qarorni to'liq tushuntirib berish vazifasi qo'yildi."*

---

### 4-SLAYD: Tizim Arxitekturasi (System Architecture & Pipeline)
* **Vizual qism:** Tizimning 5 qatlamli to'liq blok-sxemasi (Intake ➔ Heuristics ➔ AI Engine ➔ Risk Fusion ➔ Forensics).
* **Slayddagi matn:**
  - **Backend:** Python 3.12, FastAPI (Asinxron non-blocking arxitektura), scikit-learn, pefile, pyaxmlparser.
  - **Ma'lumotlar bazasi:** SQLite WAL (Write-Ahead Logging) va Redis Distributed Cache.
  - **Frontend:** Glassmorphism SOC Design, Web Audio API, Multi-language (UZ / EN / RU).
  - **Infratuzilma:** Docker, Netlify CDN, Chrome Extension (MV3), Telegram SOC Bot.
* 🎤 **Himoya nutqi (45 soniya):**
  > *"Slaydda PhishGuard AI tizimining umumiy arxitekturasi keltirilgan. Tizim 5 ta mustaqil blokdan iborat. Foydalanuvchi yuborgan ob'ekt serverda hech qachon diskka yozilmaydi va operatsion tizimda ishga tushirilmaydi — barcha tahlil xotirada (in-memory) amalga oshiriladi. FastAPI asosidagi asinxron oqimlar og'ir hisob-kitoblarni alohida workerlarga uzatadi, bu esa tizimning bir soniyada yuzlab so'rovlarga tezkor javob berishini ta'minlaydi."*

---

### 5-SLAYD: 1-Qatlam — Veb-Havolalar (URL) Tahlili va ML Modeli
* **Vizual qism:** 133 000 ta URL datasetining balansi grafigi va Random Forest ning 5-Fold Cross Validation natijalari diagrammasi.
* **Slayddagi matn:**
  - **26 ta leksik belgi:** URL/Domen uzunligi, Shannon entropiyasi, IP-xostlar, gomoglif/punycode, shubhali TLDlar, fayl kengaytmalari.
  - **Dataset:** 420 000 tadan saralangan 133 090 ta balanslangan namunalar (66 643 xavfsiz / 66 447 fishing).
  - **Optimizatsiya:** RandomizedSearchCV orqali giperparametrlarni nozik sozlash (n_estimators=200).
  - **Muvaffaqiyat ko'rsatkichlari:** **Accuracy: 88.0% | F1-Score: 88.0% | Precision: 88.4% | Recall: 87.7%**.
* 🎤 **Himoya nutqi (50 soniya):**
  > *"Birinchi qatlam — veb-havolalarni tahlil qilishdir. URL manzilidan 26 ta matematik va leksik parametr ajratib olinadi. Ayniqsa Shannon entropiyasi avtomatik generatsiya qilingan domenlarni aniqlashda katta ahamiyatga ega. Biz 133 mingdan ortiq haqiqiy namunalar ustida Random Forest va XGBoost algoritmlarini solishtirdik. Random Forest modeli 5 bosqichli kross-validatsiyada 88.0% lik F1-score ko'rsatkichini berib, yuqori barqarorlikni namoyish etdi."*

---

### 6-SLAYD: 2-Qatlam — Windows PE (EXE) Fayllarining Forensik Tahlili
* **Vizual qism:** PE fayl sarlavhasi (DOS, PE, Sections) chizmasi va xavfli Win32 API funksiyalari klasteri.
* **Slayddagi matn:**
  - **Strukturaviy tahlil:** PE Headers, Section Entropiyasi (Shannon > 7.0 bo'lsa shifrlangan payload).
  - **W+X Anomaliyasi:** Bir vaqtning o'zida yozish (Write) va ijro etish (Execute) ruxsati berilgan bo'limlar — polimorfik viruslar belgisi.
  - **MITRE ATT&CK API Klasterlari:**
    - *Process Injection (T1055):* `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`.
    - *Process Hollowing (T1055.012):* `NtUnmapViewOfSection`, `SetThreadContext`.
    - *Defense Evasion:* `IsDebuggerPresent`, TLS Callbacks, UPX/Themida pakerlari.
* 🎤 **Himoya nutqi (50 soniya):**
  > *"Ikkinchi qatlam — Windows ijro fayllarini statik tahlil qilishdir. Bunda `pefile` moduli orqali fayl sarlavhalari, raqamli imzo haqiqiyligi va bo'limlar entropiyasi tekshiriladi. Eng muhim yutuqlarimizdan biri — xavfli Win32 API funksiyalarini xalqaro MITRE ATT&CK klasterlariga ajratganimizdir. Masalan, tizim `VirtualAllocEx` va `WriteProcessMemory` funksiyalarining birgalikda chaqirilishini ko'rsa, uni Process Injection hujumi sifatida darhol qayd etadi."*

---

### 7-SLAYD: 3-Qatlam — Android APK Troyanlari Tahlili
* **Vizual qism:** Bank troyani sxemasi (Overlay + Accessibility Service) va Telegram aldov so'zlari buluti.
* **Slayddagi matn:**
  - `AndroidManifest.xml` strukturaviy tahlili (`pyaxmlparser`).
  - **Xavfli kombinatsiyalar:** `SYSTEM_ALERT_WINDOW` (Overlay) + `ACCESSIBILITY_SERVICE` — bank to'lov oynalari ustiga soxta interfeys tortish (Banker Dropper).
  - SMS/OTP ruxsatlari: Kiruvchi tasdiqlash kodlarini yashirin o'g'irlash.
  - **O'zbekiston kiber-muhitiga xos aldovlar (Lures):** *"to'y", "kelin", "fotolar", "jarima", "soliq", "ovoz_bering"*.
* 🎤 **Himoya nutqi (45 soniya):**
  > *"Uchinchi qatlam — O'zbekiston kiber-muhiti uchun o'ta dolzarb bo'lgan Android APK troyanlari tahlilidir. Hozirda Telegram guruhlarida 'to'ydan rasmlar' yoki 'ovoz bering' niqobi ostida tarqalayotgan ilovalarni tadqiq qildik. Vredonos ilovalar odatda ruxsatlar kombinatsiyasi orqali aniqlanadi. Agar APK bir vaqtda ekranga oyna chiqarish va Maxsus imkoniyatlar (Accessibility) xizmatini so'rasa, bu 99% ehtimol bilan bank hisoblaridan pul yechuvchi troyandir."*

---

### 8-SLAYD: Ilmiy Yangilik — Zero-Day Paradoksi va Risk Fusion Formulalari
* **Vizual qism:** Dinamik vaznlar formulasi grafigi va konsensus taqsimoti.
* **Slayddagi matn:**
  - **Muammo:** VirusTotal noma'lum Zero-Day virusga 0 ta aniqlash (`0/70`) berganda tizim uni "Xavfsiz" demasligi shart.
  - **Dinamik formula:**
    $$\text{Final Score} = w_{\text{local}} \cdot S_{\text{local}} + w_{\text{vt}} \cdot S_{\text{vt}}$$
  - Agar $\text{VT} = 0$, lekin $S_{\text{local}} \ge 60$ bo'lsa:
    $$w_{\text{local}} = 0.8, \quad w_{\text{vt}} = 0.2$$
  - Agar VT da 5+ mustaqil antivirus tahdidni tasdiqlasa:
    $$w_{\text{vt}} = 0.8 \quad (\text{va minimal ball } 75\%)$$
* 🎤 **Himoya nutqi (50 soniya):**
  > *"Tadqiqotimizning eng muhim ilmiy-nazariy yangiligi — 'Zero-Day Paradoksi'ning hal etilishidir. Ko'pgina an'anaviy tizimlar VirusTotal nol natija qaytarsa, virusni xavfsiz deb xato xulosa qiladi. Biz taklif etgan dinamik 'Risk Fusion' modelida, agar lokal tahlil jiddiy indikatorlarni aniqlasa, tashqi bazaning nol ko'rsatkichiga qaramasdan lokal tahlilga 80% ustuvorlik beriladi. Bu esa hali dunyo antivirus bazalariga tushmagan mutlaqo yangi tahdidlardan ishonchli himoyani ta'minlaydi."*

---

### 9-SLAYD: Explainable AI (XAI) va Avtomatlashtirilgan YARA Generatori
* **Vizual qism:** Interfeysdagi XAI Attribution foizlari va generatsiya qilingan haqiqiy YARA 4.x qoidasi kodi.
* **Slayddagi matn:**
  - **Explainable AI:** Qaror "Qora quti" emas — xavfga ta'sir qilgan har bir belgi (Feature Importance & Decision Attribution) foizlarda ko'rsatiladi.
  - **Avtomatlashtirilgan YARA 4.x Qoidalari:**
    - TLP:AMBER klassifikatsiyasi;
    - MITRE ATT&CK texnikalari kiritilgan;
    - Har qanday SOC SIEM tizimiga (Wazuh, Splunk, QRadar) to'g'ridan-to'g'ri import qilinadi.
  - **Forensik PDF Eksport:** Pure-Python (Zero-dependency) rasmiy SOC xulosasi.
* 🎤 **Himoya nutqi (45 soniya):**
  > *"Zamonaviy kiberxavfsizlikda faqatgina 'bu fayl xavfli' deb aytish yetarli emas — tahlilchi har bir belgi qancha xavf qo'shganini bilishi kerak. Ishimizda Explainable AI moduli joriy etilib, masalan, brendni soxtalashtirish +30%, shubhali API lar +35% hissa qo'shgani aniq ko'rsatiladi. Shuningdek, tizim har bir aniqlangan tahdid uchun avtomatik ravishda xalqaro standartdagi YARA qoidasini va rasmiy PDF ekspertiza hisobotini generatsiya qiladi."*

---

### 10-SLAYD: O'zbekiston Kiber-Makoniga Moslashtirilganlik (Brand Radar)
* **Vizual qism:** O'zbekiston xaritasi, Payme, Click, Uzum, Hamkorbank, NBU piktogrammalari va omoglif domen misollari.
* **Slayddagi matn:**
  - **Brand Radar:** Milliy to'lov tizimlari va banklar monitoringi.
  - **Omoglif va Gomograf hujumlar:** Kirill/Lotin almashtirishlari (masalan, `gооgle.com` IDNA: `xn--ggle-p50aa.com`).
  - **Ko'p qismli ccSLD domenlar:** `.com.uz`, `.org.uz`, `.edu.uz` zonalari bilan to'g'ri ishlash.
  - **Mahalliy Geotelemetriya:** Viloyatlararo kiber-tahdidlar xaritasi.
* 🎤 **Himoya nutqi (45 soniya):**
  > *"PhishGuard AI O'zbekiston kiber-muhitiga chuqur moslashtirilgan. Platformaga 'Brend Radari' kiritilgan bo'lib, u Payme, Click, Uzum Market, Hamkorbank, NBU kabi 10 dan ortiq milliy brendlarning soxta klonlarini, gomoglif harflar (kirillcha 'о' bilan yozilgan soxta saytlar) va typosquatting domenlarini real vaqtda aniqlaydi. Tizim milliy `.uz` va `.com.uz` domen tuzilmalarini to'liq hisobga oladi."*

---

### 11-SLAYD: Amaliy Tatbiq va Jonli Ekosistema (Live Demonstration)
* **Vizual qism:** 4 ta ekotizim qismi kollaji:
  1. Netlify veb-ilovasi (`https://phishguard-soc.netlify.app`);
  2. Chrome Kengaytmasi (MV3);
  3. Telegram SOC Bot;
  4. GitHub Open-Source Repozitoriy (`RusiMa12/Phishguard-ai`).
* **Slayddagi matn:**
  - **Jonli veb-SOC:** Netlify bulutida global tarqatilgan.
  - **Browser Extension:** Google Chrome real vaqt kiber-qalqoni.
  - **Telegram Bot:** Mobil foydalanuvchilar uchun tezkor tahlilchi.
  - **GitHub CI/CD:** Avtomatlashtirilgan testlar va ochiq kodli repozitoriy.
* 🎤 **Himoya nutqi (45 soniya):**
  > *"Ushbu ish shunchaki nazariy tadqiqot emas, balki to'liq ishga tushirilgan amaliy ekotizimdir. Bugungi kunda platformaning frontend qismi Netlify bulutida jonli ishlab turibdi. Foydalanuvchilar brauzer orqali kirishi, Google Chrome kengaytmasi orqali saytlarni real vaqtda filtr qilishi yoki Telegram bot orqali mobil qurilmalaridan turib tekshirishi mumkin. Loyihaning barcha kodlari va CI/CD tizimi GitHub platformasida ochiq manba (Open-Source) sifatida joylashtirilgan."*

---

### 12-SLAYD: Xulosa va Kelgusi Rivojlanish (Conclusion)
* **Vizual qism:** "E'tiboringiz uchun rahmat!", QR-kodlar (Netlify demo va GitHub repo), bog'lanish ma'lumotlari.
* **Slayddagi matn:**
  - **Olingan asosiy natijalar:**
    - Ko'p pog'onali gibrid xavfsizlik arxitekturasi ishlab chiqildi;
    - Zero-Day tahdidlarni lokal tahlil orqali ushlab qolish isbotlandi;
    - 88% aniqlikka ega Random Forest ML modeli integratsiya qilindi;
    - Milliy bank va to'lov tizimlari uchun Brand Radar moduli yaratildi.
  - **Kelgusi rejalar:** Dinamik Cuckoo/CAPE Sandbox integratsiyasini kengaytirish, korporativ SIEM tizimlari bilan to'liq integratsiya.
* 🎤 **Himoya nutqi (35 soniya):**
  > *"Xulosa qilib aytganda, ishlab chiqilgan PhishGuard AI platformasi zamonaviy kiber-tahdidlarga qarshi samarali, tushuntiriluvchan va tezkor himoya vositasi ekanligini to'liq isbotladi. Tizim milliy kiberxavfsizlik markazlari, banklar va korporativ SOC bo'linmalarida mustaqil tekshiruv shlyuzi sifatida joriy etilishga to'liq tayyor. E'tiboringiz uchun katta rahmat! Savollaringiz bo'lsa, mamnuniyat bilan javob berishga tayyorman."*

---
---

# II QISM: KOMISSIYA VA TAQRIZCHILARNING ENG QIYIN 10 TA SAVOLI VA ILMIY JAVOBLARI

Quyidagi savollar davlat attestatsiya komissiyasi a'zolari, professorlar va amaliyotchi xavfsizlik ekspertlari tomonidan eng ko'p beriladigan "tuzoqli" va murakkab savollardir.

---

### ❓ 1-SAVOL: Nima uchun zamonaviy Deep Learning (Neyron to'rlar, BERT yoki LLM) emas, aynan Random Forest algoritmini tanladingiz?

💡 **Mukammal javob:**
> *"Juda to'g'ri va chuqur savol, rahmat! Buning 3 ta asosiy sababi bor:
> 1. **Tezlik va Real-Vaqt talabi (Latency):** Tabulyar va leksik belgilarda (26 ta sonli parametr) Random Forest bitta URLni 2-3 millisoniyada tahlil qiladi. Chuqur neyron to'rlar yoki Transformatorlar esa GPU resurslarini talab qiladi va so'rovga 200-500 millisoniya sarflaydi. Kiber-qalqon uchun har bir millisoniya qadrlidir.
> 2. **Tushuntiriluvchanlik (Interpretability):** Neyron to'rlar 'qora quti' (black-box) bo'lib, kiberxavfsizlik talablariga ko'ra biz qaysi belgi xavfni oshirganini isbotlab berishimiz kerak. Random Forest daraxtlaridagi `feature_importances_` parametri Explainable AI modulimiz bilan to'liq mos keladi.
> 3. **Tabulyar ma'lumotlarda ustunlik:** 2022-yildagi Grinsztajn va hammualliflarining nufuzli tadqiqotlari shuni ko'rsatadiki, o'rta hajmdagi tabulyar ma'lumotlarda daraxtga asoslangan ansambllar (Random Forest, XGBoost) Deep Learning modellaridan ko'pincha yuqoriroq yoki teng aniqlik beradi."*

---

### ❓ 2-SAVOL: Agar VirusTotal tekshirilayotgan faylga 0/70 (toza) deb natija bersa, sizning tizimingiz uni baribir xavfli deb topishi mumkinmi? Bu yolg'on ijobiy (False Positive) xato emasmi?

💡 **Mukammal javob:**
> *"Ha, tizimimiz uni xavfli deb topishi mumkin va bu aynan loyihamizning eng katta ilmiy yangiligidir! Bu holat **'Zero-Day Paradoksi'** deb ataladi. 
> Yangi yaratilgan virus hali hech bir global antivirus bazasiga tushmagan bo'ladi, shuning uchun VirusTotal 0 ta aniqlash ko'rsatadi. Lekin bizning lokal statik tahlilchimiz fayl ichida:
> - Shannon entropiyasi 7.4 dan yuqori ekanini (shifrlangan tana);
> - Bo'limda bir vaqtning o'zida W+X (yozish va bajarish) huquqi borligini;
> - Process Injection API lari mavjudligini aniqlasa, lokal xavf 60% dan oshadi.
> Biz ishlab chiqqan `risk_fusion.py` formulasiga ko'ra, bunday holatda tashqi bazaga emas, **lokal evristikaga 80% vazn** beriladi va tahdid 'Potential Zero-Day Malware' sifatida belgilanadi. SOC amaliyotida yangi virusni o'tkazib yuborishdan ko'ra, gumonli deb tekshirishga ajratish xavfsizlik kafolatidir."*

---

### 3-SAVOL: Foydalanuvchi serverga zararli EXE yoki APK fayl yuklaganda, bu fayl sizning serveringizni zararlab qo'ymasligiga qanday kafolat berasiz?

💡 **Mukammal javob:**
> *"Tizimimiz **'Pure In-Memory Non-Executing'** tamoyiliga qat'iy amal qiladi:
> 1. Yuklangan fayl serverning qattiq diskiga fayl sifatida yozilmaydi — u faqat operativ xotirada (`io.BytesIO`) oddiy baytlar ketma-ketligi sifatida qabul qilinadi.
> 2. Fayl operatsion tizimda hech qachon ishga tushirilmaydi (`exec`, `spawn` yoki `subprocess` chaqirilmaydi).
> 3. Tahlil faqat fayl tuzilmasini (PE header, ZIP arxitekturasi va manifest XML) matn va bayt darajasida o'qish orqali amalga oshiriladi.
> 4. Path Traversal (`../../`) hujumlarining oldini olish uchun fayl nomlari `Path(filename).name` orqali tozalanadi va hajm cheklovlari (50 MB EXE, 100 MB APK) qo'yilgan. Demak, fayl passiv xom-ashyo sifatida o'rganiladi va uning faollashishi 100% imkonsiz."*

---

### ❓ 4-SAVOL: 133 000 ta URL datasetida model qayta o'rganib (Overfitting) qolmaganini qanday isbotlaysiz?

💡 **Mukammal javob:**
> *"Buni 3 ta asosiy metodologiya orqali isbotlaganmiz:
> 1. **5-Fold Stratified Cross-Validation:** Ma'lumotlar 5 ta teng qismga ajratilib, 5 marta turli qismlarda tekshirilgan. Barcha qismlarda F1-score 87.8% dan 88.2% gacha oraliqda bo'lib, dispersiya o'ta past bo'ldi.
> 2. **O'tkazilmagan Test To'plami (Hold-out Test 20%):** Model parametrlari RandomizedSearchCV orqali o'rganilayotganda 20% li test to'plami umuman ko'rsatilmagan. Yakuniy 88.0% aniqlik aynan shu begona test to'plamida olingan.
> 3. **Muvozanat (Balanced classes):** Datasetdagi xavfsiz (66 643 ta) va fishing (66 447 ta) namunalari 50/50 nisbatda bo'lgani sababli, model biror sinfga moyil bo'lib qolmagan."*

---

### ❓ 5-SAVOL: Homoglif (Gomograf) va Punycode hujumlarini tizimingiz qanday aniqlaydi? Masalan, `google.com` dagi 'o' harfi kirillcha bo'lsa?

💡 **Mukammal javob:**
> *"Bu xalqaro IDN (Internationalized Domain Names) standartining asosiy zaifligidir. Brauzerlar bunday domenlarni Punycode shakliga, ya'ni `xn--...` prefiksi bilan boshlanuvchi kodga aylantiradi. 
> Masalan, agar fishingchi kirillcha 'о' harfi bilan `google.com` yozsa, brauzerda bu `xn--ggle-p50aa.com` ga aylanadi. 
> Bizning `url_features.py` modulimiz hostnameda Punycode mavjudligini (`has_punycode`) va aralash alifbo (Mixed Script) belgilarini aniqlaydi. Agar taniqli brend nomida Punycode aniqlansa, Risk Engine darhol unga +20 dan +30 ballgacha xavf yuklaydi va foydalanuvchiga 'Gomoglif orqali soxtalashtirilgan domen' deb aniq ko'rsatadi."*

---

### ❓ 6-SAVOL: Dinamik tahlil (Sandbox) bo'lmasa, dastur ishga tushganda nima qilishini (masalan, reyestrga yozishini yoki process injection qilishini) statik tahlilda qanday aniqlaysiz?

💡 **Mukammal javob:**
> *"Buning uchun biz `services/sandbox.py` modulida **Heuristic Behavioral Reconstruction** (Evristik xatti-harakatlarni modellashtirish) mexanizmini yaratdik. 
> Windows dasturlari operatsion tizim resurslaridan foydalanish uchun Win32 API funksiyalarini Import Table jadvalida e'lon qilishi shart. Masalan:
> - Agar dasturda `RegSetValueExA` va `CurrentVersion\\Run` qatori bo'lsa — u o'zini avtomatik yuklanishga qo'yadi (MITRE T1547).
> - Agar `VirtualAllocEx` va `WriteProcessMemory` bo'lsa — u xotiraga kod kiritadi (MITRE T1055).
> Biz ushbu API zanjirlari va xom baytlar ichidagi buyruqlarni (masalan, `vssadmin delete shadows` — ransomware belgisi) o'qish orqali dasturning tizimdagi jarayonlar daraxti (Process Tree) va reyestr harakatlarini ishga tushirmasdan turib yuqori ehtimollik bilan modellashtiramiz."*

---

### ❓ 7-SAVOL: Tizimingizdagi Explainable AI (XAI) qanday ishlaydi? Qora quti muammosi qanday yechilgan?

💡 **Mukammal javob:**
> *"Biz `xai_explainer.py` modulida **Feature Contribution & Attribution** usulini qo'llaganmiz. 
> Model yakuniy risk balini chiqarganda, u har bir belgining qarorga qo'shgan mutlaq va nisbiy hissasini hisoblaydi:
> Masalan:
> - Domen brendni soxtalashtirgani: **+30% xavf**;
> - To'g'ridan-to'g'ri IP-manzil orqali ochilgani: **+25% xavf**;
> - Havolada '@' belgisi borligi: **+20% xavf**;
> - HTTPS sertifikati mavjudligi: **-10% xavf (ijobiy belgi)**.
> Natijada foydalanuvchi yoki SOC tahlilchisi shunchaki '85% xavfli' degan raqamni emas, balki bu xavf aynan qaysi 3 ta belgi sababli shakllanganini aniq ko'radi. Bu esa xalqaro AI etikasining shaffoflik (transparency) talabiga to'liq mos keladi."*

---

### ❓ 8-SAVOL: Nima uchun O'zbekiston kiber-makoni uchun alohida 'Brand Radar' kerak bo'ldi? Global tizimlar buni eplay olmaydimi?

💡 **Mukammal javob:**
> *"Global antiviruslar (VirusTotal, Google Safe Browsing) birinchi navbatda xalqaro brendlarga (PayPal, Apple, Microsoft) e'tibor qaratadi. 
> O'zbekistonda esa eng ko'p fishing Payme, Click, Uzum, Hamkorbank, NBU va Soliq.uz nomidan qilinadi. Xorijiy tizimlar yangi ochilgan `payme-bonus-tasdiqlash.uz` domenini oddiy sayt deb o'ylashi mumkin, chunki ular 'Payme' O'zbekistonda eng ommabop to'lov tizimi ekanligini hisobga oluvchi maxsus lug'atga ega emas.
> Bizning Brand Radar modulimiz O'zbekistonning 10 ta eng ommabop moliyaviy brendlarini va ko'p bo'g'inli `.com.uz`, `.co.uz` zonalarini chuqur tahlil qilib, milliy segmentdagi fishingni xalqaro tizimlarga qaraganda ancha erta ushlaydi."*

---

### ❓ 9-SAVOL: Agar korxonada tizimingizga bir vaqtning o'zida minglab so'rovlar kelsa, arxitektura bunga qanday bardosh beradi?

💡 **Mukammal javob:**
> *"Tizim korporativ yuklamalarga to'liq tayyorlangan:
> 1. **Non-blocking I/O:** FastAPI asinxron bo'lib, `asyncio` hodisalar tsikli asosida ishlaydi. Fayllarni tahlil qilish kabi og'ir hisob-kitoblar `run_in_threadpool` orqali alohida oqimlarga o'tkazilgan.
> 2. **Taqsimlangan Kesh (Redis):** Biz `rate_limit.py` moduliga Redis klasterini ulaganmiz. Bir nechta server o'rnatilganda so'rovlar markazlashgan keshda hisoblanadi.
> 3. **SQLite WAL Rejimi:** Ma'lumotlar bazasida Write-Ahead Logging yoqilgan, bu esa bir vaqtda cheksiz o'qish (Read) va qulflanmasdan yozish (Write) imkonini beradi.
> 4. **Mikroservis va Docker:** Loyiha Dockerfile va docker-compose orqali osonlik bilan Kubernetes klasterida gorizontal masshtablanadi (auto-scaling)."*

---

### ❓ 10-SAVOL: Ushbu ishning iqtisodiy va amaliy samaradorligi nimada? Uni qayerlarda tatbiq etish mumkin?

💡 **Mukammal javob:**
> *"Loyiha katta iqtisodiy va amaliy qiymatga ega:
> 1. **Mablag'larni tejash:** Xorijiy tijoriy SOC va threat intelligence tizimlari (masalan, VirusTotal Enterprise litsenziyasi) yiliga o'n minglab dollar turadi. PhishGuard AI esa ochiq manbali va tejamkor yechim hisoblanadi.
> 2. **Zararning oldini olish:** O'zbekistonda plastik kartalardan ruxsatsiz yechib olinayotgan milliardlab so'mlik firibgarliklarning oldini oladi.
> 3. **Tatbiq etish sohalari:**
>    - Tijorat banklari va to'lov tashkilotlarida (ichki xavfsizlik shlyuzi sifatida);
>    - Korporativ pochtalarda (kelgan xatlar va havolalarni avtomatik tekshirish uchun);
>    - Oddiy aholi uchun bepul Chrome kengaytmasi va Telegram bot sifatida kiber-gigiyenani ta'minlashda."*

---

<div align="center">
  <b>Ushbu materiallar PhishGuard AI loyihasini "A'lo" (100 ball) bahoga himoya qilish uchun to'liq kafolat beradi! 🎓🛡️</b>
</div>
