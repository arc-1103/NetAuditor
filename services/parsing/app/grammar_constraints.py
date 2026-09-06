from __future__ import annotations

from typing import Any

from .schema_validator import BaselineValidator


class GrammarConstraintError(RuntimeError):
    pass


class GrammarConstraints:
    """Provides the schema sent to Ollama's structured-output facility.

    `GRAMMAR_ENGINE=outlines` is retained as an architectural compatibility
    setting. Outlines is not imported or used to control a remote Ollama
    decoder. The actual remote constraint is Ollama's `format=<JSON schema>`;
    Pydantic validation is still mandatory after generation.
    """

    def __init__(self, engine: str = "outlines"):
        self.engine = engine
        self.validator = BaselineValidator()

    def json_schema(self) -> dict[str, Any]:
        return self.validator.json_schema()

    def validate_structured(self, candidate: Any) -> dict[str, Any]:
        result = self.validator.validate(candidate)
        if not result.valid or result.baseline is None:
            raise GrammarConstraintError("; ".join(result.errors))
        return result.baseline.model_dump(mode="json")
