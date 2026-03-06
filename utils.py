"""Shared utilities for the Elderly Scam Alert Assistant."""

import json
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


def load_environment(env_path: Path | str | None = None) -> None:
    """Load environment variables from .env file if present."""
    if env_path is None:
        env_path = Path.cwd() / ".env"
    load_dotenv(dotenv_path=env_path)


def get_required_env(key: str) -> str:
    """Return value for environment variable; raise if missing or empty."""
    value = os.environ.get(key, "").strip()
    if not value:
        raise ValueError(f"Missing or empty required environment variable: {key}")
    return value


def parse_json_safe(raw: str) -> dict[str, Any] | None:
    """Parse a string as JSON; return None on failure.

    This function only returns JSON objects (dict roots). It tolerates common
    model output wrappers such as Markdown code fences or extra text around a
    single JSON object.
    """
    if not raw:
        return None

    text = raw.strip()
    if not text:
        return None

    extracted = _extract_json_object(text) or text
    try:
        data = json.loads(extracted)
        if not isinstance(data, dict):
            return None
        return data
    except (json.JSONDecodeError, TypeError):
        return None


def _extract_json_object(text: str) -> str | None:
    """Extract the first JSON object found within a string."""
    fenced = _extract_from_code_fence(text)
    if fenced is not None:
        return fenced

    start = text.find("{")
    if start < 0:
        return None

    depth = 0
    in_string = False
    escape = False

    for i, ch in enumerate(text[start:], start=start):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]

    return None


def _extract_from_code_fence(text: str) -> str | None:
    """Extract JSON from a Markdown code fence if present."""
    fence = "```"
    start = text.find(fence)
    if start < 0:
        return None
    end = text.find(fence, start + len(fence))
    if end < 0:
        return None

    inside = text[start + len(fence) : end].strip()
    if inside.lower().startswith("json"):
        inside = inside[4:].lstrip()
    return inside or None


def clamp_score(score: float) -> int:
    """Clamp numeric score to 0–100 and return as integer."""
    clamped = max(0.0, min(100.0, float(score)))
    return int(round(clamped))
