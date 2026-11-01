FROM python:3.12-slim

WORKDIR /app

# Create non-root user for Hugging Face security compliance
RUN useradd -m -u 1000 user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir --upgrade -r backend/requirements.txt

COPY --chown=user:user backend/ backend/
COPY --chown=user:user dataset/ dataset/
COPY --chown=user:user models/ models/
COPY --chown=user:user frontend/ frontend/

RUN mkdir -p data reports models && chown -R user:user /app

USER user
WORKDIR /app/backend
EXPOSE 7860

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]
