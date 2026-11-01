"""
main.py
-------
Это ГЛАВНЫЙ файл backend'а - то, что реально запускается командой uvicorn.
Он:
  1) создаёт приложение FastAPI;
  2) разрешает фронтенду (другой домен/порт) обращаться к нашему API (CORS);
  3) подключает все эндпоинты из api/routes.py под префиксом /api;
  4) отдаёт сам frontend/ как статические файлы - см. StaticFiles внизу файла.

Запуск (из папки backend/):
    uvicorn main:app --reload --port 8000

После запуска открой в браузере:
    http://127.0.0.1:8000/
Это сразу откроет сам интерфейс PhishGuard AI (не JSON) - frontend и backend
теперь работают на одном и том же адресе/порте. Это не просто удобство:
именно поэтому script.js использует ОТНОСИТЕЛЬНЫЕ пути ("/api/analyze",
а не "http://127.0.0.1:8000/api/analyze") - тот же код без изменений
продолжит работать и после деплоя в облако (Google Cloud Run и т.п.),
где адрес уже не будет 127.0.0.1.
"""

import sys
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

# Ensure backend directory is in sys.path so absolute and relative package imports resolve
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

# Загружаем переменные окружения из .env (например VIRUSTOTAL_API_KEY) ДО
# импорта роутов, чтобы они гарантированно были доступны сервисам ниже.
#
# ВАЖНО: указываем путь ЯВНО (backend/.env), а не полагаемся на поведение
# load_dotenv() по умолчанию - оно ищет .env, поднимаясь по родительским
# папкам, и может случайно найти чужой .env выше по дереву каталогов.
# Явный путь даёт предсказуемое поведение при любом расположении проекта.
load_dotenv(Path(__file__).resolve().parent / ".env")

from database import init_db
from api.routes import router as api_router

# Таблица scans (история сканирований) создаётся при первом запуске
# сервера, если её ещё нет. Файл базы: data/phishguard.db
init_db()

app = FastAPI(
    title="PhishGuard AI",
    description="Intelligent Phishing URL Risk Analyzer - учебный проект по кибербезопасности",
    version="0.1.0",
)

# CORS: на случай, если кто-то всё же откроет frontend отдельно (другой порт/
# файл напрямую) - основной сценарий теперь не требует этого (см. StaticFiles
# внизу), но оставляем для гибкости при разработке.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # на этапе разработки разрешаем всё, ужесточим перед деплоем
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Все эндпоинты из routes.py становятся доступны под /api/...
# ВАЖНО: регистрируем ДО StaticFiles ниже - иначе статика "перехватила" бы
# все пути, включая /api/..., до того как до них дошла бы очередь роутера.
app.include_router(api_router, prefix="/api")


# ============================================================
# ГЛОБАЛЬНАЯ ОБРАБОТКА ОШИБОК (раздел 20 ТЗ)
# ============================================================
# Что бы ни пошло не так - пользователь ДОЛЖЕН получить понятное сообщение
# в JSON, а не сырой Python traceback. Ожидаемые ошибки (неверный URL,
# битый файл и т.д.) уже обрабатываются в самих эндпоинтах через
# HTTPException - эти два обработчика ловят всё ОСТАЛЬНОЕ: непредвиденные
# баги, ошибки валидации запроса от FastAPI/Pydantic и т.п.

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Например, если во фронтенде забыли передать обязательное поле."""
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request data. Please check the values you submitted and try again."},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Последняя линия защиты: любая непредвиденная ошибка (баг, которую мы
    не предусмотрели) всё равно вернёт аккуратный JSON с кодом 500,
    а не traceback. Полный текст ошибки печатается в лог сервера
    (терминал) - для отладки студентом, но НЕ отправляется клиенту.
    """
    print(f"[UNHANDLED ERROR] {request.method} {request.url.path}: {exc!r}")
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred on the server. Please try again."},
    )


# ============================================================
# СТАТИЧЕСКИЙ FRONTEND (Phase 11: контейнеризация/деплой)
# ============================================================
# Отдаём frontend/ (index.html, style.css, script.js) прямо с backend'а.
# html=True означает, что "/" автоматически отдаёт index.html - открыв
# http://127.0.0.1:8000/, пользователь сразу видит интерфейс, а не JSON.
#
# ВАЖНО: этот mount() должен быть ПОСЛЕДНИМ в файле. StaticFiles перехватывает
# все пути, которые не были обработаны выше (роутер /api, обработчики ошибок) -
# зарегистрируй его раньше, и он "закроет" собой все остальные маршруты.
from fastapi.responses import FileResponse

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

@app.get("/favicon.ico", include_in_schema=False)
async def favicon_ico():
    fav = FRONTEND_DIR / "favicon.ico"
    if fav.exists():
        return FileResponse(fav)
    return JSONResponse(status_code=404, content={"detail": "Not found"})

if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
