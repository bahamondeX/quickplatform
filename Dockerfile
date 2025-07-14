FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY . .
# Instalar dependencias del sistema y gcsfuse desde el repositorio oficial
RUN python -m pip install --upgrade pip && \
    python -m pip install -r requirements.txt

EXPOSE 8080

CMD ["python","-m","uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]