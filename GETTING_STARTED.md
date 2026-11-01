# PhishGuard AI — Setup

## `.env` ICHIDA — hech narsa qo'lda ko'chirish shart emas

`backend/.env` allaqachon VirusTotal kalitingiz bilan tayyor.

## Yangi: endi bitta manzil, ikkita usul

### 1) Docker orqali (tavsiya etiladi — eng oson)

Loyihaning bosh papkasida:
```bash
docker compose up --build
```
`http://localhost:8000/` ni oching. Birinchi marta model o'qitilishi kerak:
```bash
docker compose exec backend python train_url_model.py
```
Model, tarix va hisobotlar (`models/`, `data/`, `reports/`) kompyuteringizda
saqlanadi — konteynerni qayta qursangiz ham yo'qolmaydi.

### 2) To'g'ridan-to'g'ri (Docker'siz)

```powershell
cd backend
pip install -r requirements.txt
python train_url_model.py
uvicorn main:app --reload --port 8000
```

**Muhim o'zgarish:** endi `frontend/index.html`ni alohida ochish shart
EMAS — brauzerda `http://127.0.0.1:8000/` manzilini oching, frontend va
backend endi bitta serverdan xizmat qiladi.

## Model o'qitish haqida

`train_url_model.py` endi cross-validation + RandomForest/XGBoost
taqqoslashini o'z ichiga oladi — **~4-5 daqiqa** davom etadi (avvalgi ~35
soniya emas). Bu normal. Tugagach, `python error_analysis.py` orqali model
qaysi URL'larda xato qilayotganini ko'rishingiz mumkin.

## VirusTotal ishlamasa — javobdagi `virustotal.status`ga qarang

- `"not_configured"` — `.env` topilmayapti (bu holatda zip'da bor, chiqmasligi kerak).
- `"unavailable"` — kalit topildi, lekin so'rov muvaffaqiyatsiz bo'ldi.
  Sabab tarmoq bo'lishi mumkin, YOKI **VirusTotal bepul kalitning limiti
  tugagan** (4 so'rov/daqiqa, 500/kun — bu suhbat davomida ko'p marta
  sinalgan). virustotal.com profilingizda tekshiring.
- `"not_found"` — kalit ishlayapti, URL/fayl hali bazada yo'q. **Xato emas.**
- `"completed"` — hammasi ishladi.

## Ixtiyoriy: EXE ML modeli

`backend/build_exe_dataset.py` boshidagi izohni o'qing.

## Telefonda ochish

Interfeys endi telefon ekraniga moslashtirilgan (responsive), va API
manzillari nisbiy (`/api/...`) yozilgan — shu tufayli qo'shimcha sozlashsiz,
faqat serverni **tarmoqqa ochib**, telefoningizdan ulanishingiz mumkin.

**Shart: kompyuter va telefon bitta Wi-Fi tarmog'ida bo'lishi kerak.**

```powershell
uvicorn main:app --host 0.0.0.0 --port 8000
```

E'tibor bering: `--reload` o'rniga endi `--host 0.0.0.0` qo'shildi — bu
serverni faqat kompyuterning o'zi emas, balki bir tarmoqdagi boshqa
qurilmalar (telefon) uchun ham ochadi.

Keyin kompyuteringizning lokal IP-manzilini toping:
```powershell
ipconfig
```
"IPv4 Address" qatoridagi raqamni qidiring (masalan `192.168.1.34`).

Telefon brauzerida oching:
```
http://192.168.1.34:8000/
```
(o'z IP-manzilingiz bilan almashtiring).

### Agar ulanmasa

1. **Windows Defender Firewall** birinchi ulanishda ruxsat so'rashi mumkin —
   "Ruxsat berish" (Allow) tugmasini bosing. Agar so'ramagan bo'lsa:
   Windows Defender Firewall → "Ilovaga tarmoqdan ruxsat berish" → Python
   uchun ham Private, ham Public tarmoqqa ruxsat bering.
2. Telefon va kompyuter **bir xil Wi-Fi tarmog'ida** ekanligini tasdiqlang
   (mobil internet/4G orqali emas).
3. Ba'zi Wi-Fi router'lar "AP Isolation" (qurilmalarni bir-biridan
   izolyatsiya qilish) yoqilgan bo'lishi mumkin — bu ayniqsa jamoat yoki
   universitet Wi-Fi'sida keng tarqalgan va uni faqat router sozlamalaridan
   o'zgartirish mumkin.
