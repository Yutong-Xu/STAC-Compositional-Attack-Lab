"""Bounded response diagnostics. Diagnostics never contain matched text or private values."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from typing import Any

from stac_attack_lab.hashing import stable_hash

RULES = {
    "credential-format/1": re.compile(
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}|\bsk-[A-Za-z0-9_-]{16,}|\bAIza[A-Za-z0-9_-]{20,}"
    ),
    "secret-assignment/1": re.compile(
        r"(?i)\b(?:api[_-]?key|token|authorization|password|passwd|secret|credential)\s*[=:]\s*[^\s,;]+"
    ),
    "protected-canary/1": re.compile(r"CANARY_[A-Za-z0-9_]+"),
}
KNOWN = {
    "choices",
    "message",
    "content",
    "reasoning_content",
    "usage",
    "model",
    "finish_reason",
    "refusal",
    "id",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "prompt_tokens_details",
    "completion_tokens_details",
}
NUMERIC = {
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "cached_tokens",
    "reasoning_tokens",
    "audio_tokens",
    "accepted_prediction_tokens",
    "rejected_prediction_tokens",
}


def numeric_usage(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, Any] = {}
    for key, number in value.items():
        if (
            key in NUMERIC
            and type(number) in (int, float)
            and math.isfinite(number)
            and number >= 0
        ):
            result[key] = number
        elif key in {"prompt_tokens_details", "completion_tokens_details"}:
            nested = numeric_usage(number)
            if nested:
                result[key] = nested
    return result or None


def _counts(text: str, exact: list[str]) -> dict[str, int]:
    result = {name: len(pattern.findall(text)) for name, pattern in RULES.items()}
    result["exact-private/1"] = sum(text.count(secret) for secret in exact if secret)
    return {name: count for name, count in result.items() if count}


def strict_json(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise ValueError("nonfinite_json_number")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def inspect_response(
    raw: bytes, *, mode: str, exact: list[str], max_bytes: int = 131072, max_chars: int = 65536
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": "planner-field-diagnostic/1",
        "complete": False,
        "decision": "stop",
        "fields": [],
        "raw_counts": {},
        "raw_hash": None,
        "raw_hash_missing_reason": "response_not_archived",
        "projection": None,
    }
    if mode not in {"archive", "required_fields"}:
        raise ValueError("invalid_response_policy")
    if len(raw) > max_bytes:
        result["reason"] = "http_capture_limit"
        return result
    try:
        text = raw.decode("utf-8")
        result["raw_counts"] = _counts(text, exact)
        data = strict_json(text)
        stack = [(data, "", 0, False)]
        totals: Counter[str] = Counter()
        nodes = 0
        content_hits = False
        required_hits = False
        while stack:
            value, path, depth, required = stack.pop()
            nodes += 1
            if depth > 32 or nodes > 4096:
                raise ValueError("diagnostic_resource_limit")
            if isinstance(value, dict):
                if len(value) > 256:
                    raise ValueError("diagnostic_field_limit")
                for index, (key, item) in enumerate(value.items()):
                    key_hits = _counts(key, exact)
                    if re.fullmatch(
                        r"(?i)(api[_-]?key|token|authorization|password|passwd|secret|credential)",
                        key,
                    ):
                        key_hits["sensitive-key/1"] = 1
                    safe_key = key if key in KNOWN and not key_hits else f"field-{index}"
                    child = path + "/" + safe_key
                    if key_hits:
                        totals.update(key_hits)
                        result["fields"].append(
                            {"path": child, "representation": "key", "rules": key_hits}
                        )
                        required_hits = True
                    is_content = child == "/choices/0/message/content"
                    is_required = (
                        required
                        or is_content
                        or child
                        in {"/model", "/choices/0/finish_reason", "/choices/0/message/refusal"}
                    )
                    stack.append((item, child, depth + 1, is_required))
            elif isinstance(value, list):
                stack.extend(
                    (item, path + f"/{i}", depth + 1, required) for i, item in enumerate(value)
                )
            elif isinstance(value, str):
                hits = _counts(value, exact)
                totals.update(hits)
                if hits:
                    result["fields"].append(
                        {"path": path, "representation": "decoded_value", "rules": hits}
                    )
                    content_hits |= path == "/choices/0/message/content"
                    required_hits |= required
        if not isinstance(data, dict):
            raise ValueError("response_not_object")
        result["complete"] = True
        if totals.get("exact-private/1") or result["raw_counts"].get("exact-private/1"):
            result["reason"] = "exact_private_match"
            return result
        if any(count > totals[name] for name, count in result["raw_counts"].items()):
            result["reason"] = "unlocated_serialized_match"
            return result
        if totals and (mode == "archive" or required_hits):
            result["decision"] = (
                "reject_slot" if mode == "required_fields" and content_hits else "stop"
            )
            result["reason"] = "protected_response"
            return result
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ValueError("response_shape_invalid")
        first = choices[0]
        message = first.get("message")
        if not isinstance(message, dict):
            raise ValueError("response_message_invalid")
        content = message.get("content")
        if content is not None and (not isinstance(content, str) or len(content) > max_chars):
            result["reason"] = "model_text_limit"
            return result
        if not isinstance(data.get("model"), str) or not isinstance(
            first.get("finish_reason"), str
        ):
            raise ValueError("response_identity_missing")
        projection = {
            "schema_version": "planner-required-fields-projection/1",
            "model": data["model"],
            "choices": [
                {
                    "finish_reason": first["finish_reason"],
                    "message": {"content": content, "refusal": bool(message.get("refusal"))},
                }
            ],
            "usage": numeric_usage(data.get("usage")),
        }
        result.update(
            decision="allow",
            reason="safe_projection",
            projection=projection,
            projection_hash=stable_hash(projection),
        )
        return result
    except (ValueError, RecursionError, TypeError):
        result["complete"] = False
        result["reason"] = "response_parse_or_resource_error"
        return result
