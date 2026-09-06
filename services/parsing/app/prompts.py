from pathlib import Path

_PROMPT_PATH = Path(__file__).resolve().parents[1] / "prompts" / "normalize.txt"


def load_prompt() -> str:
    return _PROMPT_PATH.read_text(encoding="utf-8")


def build_prompt(
    config_text: str,
    vendor: str,
    os_name: str | None,
    rag_context: str = "",
) -> str:
    template = load_prompt()
    return template.format(
        vendor=vendor,
        os_name=os_name or "unknown",
        rag_context=rag_context or "(none)",
        config_text=config_text,
    )
