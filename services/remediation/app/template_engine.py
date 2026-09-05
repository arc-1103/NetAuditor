"""Render allow-listed, vendor-specific CLI fixes without an LLM."""

import os
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateNotFound

TEMPLATE_DIR = Path(os.getenv("TEMPLATE_DIR", Path(__file__).parents[1] / "templates")).resolve()


class RemediationTemplateError(ValueError):
    pass


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        undefined=StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def available_templates() -> list[str]:
    return sorted(path.name for path in TEMPLATE_DIR.glob("*.j2") if path.is_file())


def render_template(template_name: str, context: dict[str, Any] | None = None) -> str:
    """Render only a direct .j2 filename from the configured template directory."""
    if Path(template_name).name != template_name or not template_name.endswith(".j2"):
        raise RemediationTemplateError("Invalid remediation template name")
    try:
        template = _environment().get_template(template_name)
        rendered = template.render(**(context or {})).strip()
    except TemplateNotFound as exc:
        raise RemediationTemplateError(f"Unknown remediation template: {template_name}") from exc
    except Exception as exc:
        raise RemediationTemplateError(f"Template {template_name} could not be rendered: {exc}") from exc
    if not rendered:
        raise RemediationTemplateError(f"Template {template_name} rendered an empty script")
    return rendered + "\n"

