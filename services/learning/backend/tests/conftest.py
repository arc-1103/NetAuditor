import os

os.environ.setdefault("SERVICE_JWT_SECRET", "test-service-secret")  # signed calls and queued-task contexts
