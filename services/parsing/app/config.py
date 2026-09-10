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
    chromadb_port: int = int(os.getenv("CHROMADB_PORT", "8000"))
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
    # Exact-hash parse cache (app/parse_cache.py): a byte-identical (up to
    # whitespace) [vendor, os, chunk text] skips RAG + SLM entirely on
    # repeat — enterprise fleets repeat the same NTP/Syslog/AAA blocks
    # across hundreds of devices. Separate Redis logical DB from the
    # Celery broker (db 0) so a cache flush can never touch queued messages.
    enable_parse_cache: bool = _bool("ENABLE_PARSE_CACHE", True)
    parse_cache_redis_url: str = os.getenv("PARSE_CACHE_REDIS_URL", "redis://redis:6379/1")
    # Multi-agent reverse translation (app/reverse_translation.py) roughly
    # triples SLM calls per chunk (forward, reverse, forward again) — this
    # switch lets it be turned off for cost without a code change.
    enable_reverse_translation: bool = _bool("ENABLE_REVERSE_TRANSLATION", True)
    reverse_translation_fidelity_threshold: float = float(
        os.getenv("REVERSE_TRANSLATION_FIDELITY_THRESHOLD", "0.7")
    )


settings = Settings()
