from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from schema.security_baseline import SecurityBaseline


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    baseline: SecurityBaseline | None
    errors: list[str]


class BaselineValidator:
    def validate(self, candidate: Any) -> ValidationResult:
        try:
            baseline = SecurityBaseline.model_validate(candidate)
        except ValidationError as exc:
            return ValidationResult(
                valid=False,
                baseline=None,
                errors=[
                    f"{'.'.join(str(x) for x in err['loc'])}: {err['msg']}"
                    for err in exc.errors()
                ],
            )
        return ValidationResult(valid=True, baseline=baseline, errors=[])

    def json_schema(self) -> dict[str, Any]:
        return SecurityBaseline.model_json_schema()
