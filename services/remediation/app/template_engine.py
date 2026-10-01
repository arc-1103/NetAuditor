"""Render allow-listed, vendor-specific CLI fixes without an LLM."""

import os
from pathlib import Path
from typing import Any

from jinja2 import FileSystemLoader, StrictUndefined, TemplateNotFound
from jinja2.sandbox import SandboxedEnvironment

TEMPLATE_DIR = Path(os.getenv("TEMPLATE_DIR", Path(__file__).parents[1] / "templates")).resolve()


class RemediationTemplateError(ValueError):
    pass


# A template file is the fix script, then a line holding only ROLLBACK_MARKER,
# then the reverse script. The marker is never part of either script;
# render_template() returns only the fix.
ROLLBACK_MARKER = "@@ROLLBACK@@"
NEWLINE = chr(10)
CARRIAGE_RETURN = chr(13)


def _environment() -> SandboxedEnvironment:
    return SandboxedEnvironment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        undefined=StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def available_templates() -> list[str]:
    return sorted(path.name for path in TEMPLATE_DIR.glob("*.j2") if path.is_file())


def _render_full(template_name: str, context: dict[str, Any] | None) -> str:
    """Render only a direct .j2 filename from the configured template directory."""
    if Path(template_name).name != template_name or not template_name.endswith(".j2"):
        raise RemediationTemplateError("Invalid remediation template name")
    for key, value in (context or {}).items():
        if isinstance(value, str) and (NEWLINE in value or CARRIAGE_RETURN in value):
            raise RemediationTemplateError(f"Template variable {key!r} must not contain newlines")
    try:
        template = _environment().get_template(template_name)
        return template.render(**(context or {}))
    except TemplateNotFound as exc:
        raise RemediationTemplateError(f"Unknown remediation template: {template_name}") from exc
    except Exception as exc:
        raise RemediationTemplateError(f"Template {template_name} could not be rendered: {exc}") from exc


def render_template(template_name: str, context: dict[str, Any] | None = None) -> str:
    script = _render_full(template_name, context).split(ROLLBACK_MARKER, 1)[0].strip()
    if not script:
        raise RemediationTemplateError(f"Template {template_name} rendered an empty script")
    return script + NEWLINE


def render_rollback(template_name: str, context: dict[str, Any] | None = None) -> str | None:
    """The reverse commands for the same fix, or None when the template has none."""
    parts = _render_full(template_name, context).split(ROLLBACK_MARKER, 1)
    rollback = parts[1].strip() if len(parts) == 2 else ""
    return rollback + NEWLINE if rollback else None
