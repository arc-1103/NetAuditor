from __future__ import annotations

from copy import deepcopy
from typing import Any

from schema.security_baseline import SecurityBaseline

from .models import DeviceContext


def merge_baselines(
    baselines: list[SecurityBaseline],
    *,
    conflict_penalty: float = 0.05,
    device_context: DeviceContext | None = None,
) -> tuple[SecurityBaseline, list[str]]:
    if not baselines:
        raise ValueError("cannot merge zero baselines")

    merged = baselines[0].model_dump(mode="python", exclude_unset=True)
    conflicts: list[str] = []

    for current in baselines[1:]:
        _merge_dict(merged, current.model_dump(mode="python", exclude_unset=True), conflicts, "")

    confidence_values = [float(b.device.parsing_confidence) for b in baselines]
    confidence = min(confidence_values)
    if conflicts:
        confidence = max(0.0, confidence - conflict_penalty * len(conflicts))

    if device_context is not None:
        merged["device"]["detected_vendor"] = device_context.vendor
        merged["device"]["detected_os"] = device_context.os
        merged["device"]["detected_os_version"] = device_context.os_version
        merged["device"]["detected_hardware_model"] = device_context.hardware_model
        if device_context.raw_hostname is not None:
            merged["device"]["raw_hostname"] = device_context.raw_hostname
        confidence = min(confidence, device_context.confidence)

    merged["device"]["parsing_confidence"] = min(1.0, max(0.0, confidence))
    merged["device"]["unknown_blocks_count"] = sum(
        b.device.unknown_blocks_count for b in baselines
    )

    return SecurityBaseline.model_validate(merged), conflicts


def _merge_dict(
    target: dict[str, Any],
    incoming: dict[str, Any],
    conflicts: list[str],
    path: str,
) -> None:
    for key, value in incoming.items():
        current_path = f"{path}.{key}" if path else key

        if key not in target:
            target[key] = deepcopy(value)
            continue

        if _is_unknown(value):
            continue
        if _is_unknown(target.get(key)):
            target[key] = deepcopy(value)
            continue

        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _merge_dict(target[key], value, conflicts, current_path)
        elif isinstance(value, list) and isinstance(target.get(key), list):
            for item in value:
                if item not in target[key]:
                    target[key].append(deepcopy(item))
        elif target[key] != value:
            conflicts.append(current_path)
            # Deterministic policy: keep the first known scalar observation.


def _is_unknown(value: Any) -> bool:
    return value is None or (
        isinstance(value, str) and value.strip().lower() in {"unknown", "none", ""}
    )
