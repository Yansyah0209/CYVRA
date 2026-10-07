FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements-runtime.lock .
RUN pip install --no-cache-dir -r requirements-runtime.lock
COPY backend/ .
COPY datasets/ /app/datasets/
RUN useradd --create-home cyvra && chown -R cyvra:cyvra /app
USER cyvra
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
