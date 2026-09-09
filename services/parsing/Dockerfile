FROM python:3.11-slim

WORKDIR /app

COPY services/parsing/requirements.txt /app/services/parsing/requirements.txt
RUN pip install --no-cache-dir -r /app/services/parsing/requirements.txt

COPY services/schema /app/services/schema
RUN pip install --no-cache-dir /app/services/schema

COPY services/parsing/app /app/services/parsing/app
COPY services/parsing/prompts /app/services/parsing/prompts
ENV PYTHONPATH=/app/services/parsing
WORKDIR /app/services/parsing

CMD ["python", "-m", "app.worker"]
