FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libffi8 shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY html_templates ./html_templates
RUN mkdir -p /data/reports
EXPOSE 8005
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8005"]

