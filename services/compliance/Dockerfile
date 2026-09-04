FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# The policy bundle is NOT baked in — the opa container mounts
# ./services/compliance/policies at /policies (see docker-compose.yml), so
# editing a .rego file and restarting opa is enough. Copying it here too
# would give the stack two copies that can drift.

EXPOSE 8002
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
