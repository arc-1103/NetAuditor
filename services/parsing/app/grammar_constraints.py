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
        schema = self.validator.json_schema()
        # The Pydantic model only requires `device`, so a model can satisfy the
        # constraint by emitting device + topology alone; every other section
        # then defaults to "disabled/none" and a badly insecure config scores as
        # clean. Require every section on the wire so an omission is impossible
        # (Pydantic validation after generation is unchanged).
        schema["required"] = [k for k in schema.get("properties", {}) if k != "schema_version"]
        return schema

    def validate_structured(self, candidate: Any) -> dict[str, Any]:
        result = self.validator.validate(candidate)
        if not result.valid or result.baseline is None:
            raise GrammarConstraintError("; ".join(result.errors))
        return result.baseline.model_dump(mode="json")
