from dataclasses import dataclass
import os


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://ollama:11434").rstrip("/")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    schema_package_version: str = os.getenv("SCHEMA_PACKAGE_VERSION", "1.0.0")
    confidence_threshold: float = float(os.getenv("CONFIDENCE_THRESHOLD", "0.60"))
    chromadb_host: str = os.getenv("CHROMADB_HOST", "chromadb")
    chromadb_port: int = int(os.getenv("CHROMADB_PORT", "8500"))
    max_chunk_lines: int = int(os.getenv("MAX_CHUNK_LINES", "500"))
    grammar_engine: str = os.getenv("GRAMMAR_ENGINE", "outlines")
    use_mock_slm: bool = _bool("USE_MOCK_SLM", True)
    celery_broker_url: str = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
    ollama_timeout_seconds: float = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "60"))
    postgres_dsn: str = os.getenv(
        "POSTGRES_DSN", "postgresql+asyncpg://netaudit:changeme_in_local_env@postgres:5432/netaudit"
    )
    learning_url: str = os.getenv("LEARNING_URL", "http://learning:8003")
    rag_correct_max_distance: float = float(os.getenv("RAG_CORRECT_MAX_DISTANCE", "0.4"))
    rag_ambiguous_max_distance: float = float(os.getenv("RAG_AMBIGUOUS_MAX_DISTANCE", "0.8"))
    logprob_uncertainty_threshold: float = float(os.getenv("LOGPROB_UNCERTAINTY_THRESHOLD", "-0.5"))


settings = Settings()
