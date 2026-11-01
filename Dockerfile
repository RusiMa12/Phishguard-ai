# PhishGuard AI - Dockerfile
# Собирается из КОРНЯ проекта (не из backend/), потому что backend/*.py
# ссылается на dataset/ и models/ по относительным путям вида "../dataset" -
# внутри контейнера структура папок должна быть такой же, как на диске.
#
# Сборка (из корня проекта):
#   docker build -t phishguard-ai .
# Запуск:
#   docker run -p 8000:8000 --env-file backend/.env phishguard-ai
#
# На практике удобнее использовать docker-compose.yml (см. рядом) - он же
# подключает models/ и data/ как volume, чтобы обученная модель и история
# сканирований не терялись при пересоздании контейнера.

FROM python:3.12-slim

WORKDIR /app

# Сначала только requirements.txt - так Docker кеширует установленные
# зависимости отдельным слоем и не переустанавливает их при каждом
# изменении кода (только когда меняется сам requirements.txt).
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Код backend'а и датасет (нужен для train_url_model.py)
COPY backend/ backend/
COPY dataset/ dataset/
COPY frontend/ frontend/

# models/ и data/ НЕ копируются - они либо создаются при обучении/работе
# (models/*.pkl через train_url_model.py, data/phishguard.db автоматически),
# либо подключаются как volume в docker-compose.yml, чтобы не терять их
# при пересборке образа.
RUN mkdir -p models data reports

WORKDIR /app/backend
EXPOSE 8000

# Без --reload - это флаг для разработки, в контейнере он не нужен
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
