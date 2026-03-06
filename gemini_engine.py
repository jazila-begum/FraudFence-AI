"""Gemini-based scam analysis engine for Elderly Scam Alert Assistant."""

from __future__ import annotations

import os
from typing import Final, TypedDict

from google import genai
from google.genai import types as genai_types
from pydantic import BaseModel, ValidationError, field_validator

from scam_rules import ScamCategory
from utils import clamp_score, parse_json_safe


class GeminiEngineError(Exception):
    """Raised when the Gemini analysis engine fails."""


class GeminiAnalysisResult(TypedDict):
    """Structured result returned by Gemini analysis."""

    gemini_score: int
    gemini_category: ScamCategory
    gemini_flags: list[str]
    explanation: str
    safe_response: str


_GEMINI_API_KEY_ENV_VARS: Final[tuple[str, ...]] = ("GEMINI_API_KEY", "GOOGLE_API_KEY")
_MODEL_CANDIDATES: Final[tuple[str, ...]] = (
    "gemini-3-flash-preview",
    "gemini-1.5-flash-latest",
    "gemini-2.0-flash",
)
_TEMPERATURE: Final[float] = 0.2


class _GeminiScamAnalysisModel(BaseModel):
    """Pydantic model for validating Gemini JSON response."""

    gemini_score: float
    gemini_category: ScamCategory
    gemini_flags: list[str]
    explanation: str
    safe_response: str

    @field_validator("gemini_flags", mode="before")
    @classmethod
    def _ensure_flags_list(cls, value: object) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, (list, tuple)):
            return [str(item) for item in value]
        raise TypeError("gemini_flags must be a string or a list of strings")

    @field_validator("explanation", "safe_response", mode="after")
    @classmethod
    def _strip_and_validate_text(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("text fields must not be empty")
        return stripped


def _resolve_api_key(api_key: str | None) -> str:
    """Resolve a usable Gemini API key from explicit input or environment."""
    if api_key is not None and api_key.strip():
        value = api_key.strip()
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1].strip()
        return value
    for env_var in _GEMINI_API_KEY_ENV_VARS:
        raw_value = os.environ.get(env_var, "")
        if raw_value.strip():
            value = raw_value.strip()
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1].strip()
            return value
    raise GeminiEngineError(
        "Gemini API key not configured. Set either GEMINI_API_KEY or GOOGLE_API_KEY."
    )


def _create_client(api_key: str | None) -> genai.Client:
    """Create a new Gemini client instance using provided configuration."""
    resolved = _resolve_api_key(api_key)
    return genai.Client(api_key=resolved)


def _resolve_model_name() -> str:
    """Resolve the Gemini model name, allowing overrides via environment."""
    override = os.environ.get("GEMINI_MODEL", "").strip()
    if override:
        return override
    return _MODEL_CANDIDATES[0]


def _build_prompt(message: str, web_evidence: str | None) -> str:
    """Build the prompt instructing Gemini to return structured JSON only."""
    web_block = ""
    if web_evidence is not None and web_evidence.strip():
        web_block = (
            "\n\nOptional web evidence (public snippets). Use it only as supporting "
            "context, and do not assume it is fully trustworthy:\n"
            f"{web_evidence.strip()}\n"
        )
    return (
        "You are an assistant helping elderly people detect scams.\n"
        "Analyze the message below for scam risk using common scam patterns.\n\n"
        "Return ONLY a single JSON object with this exact structure and nothing else:\n"
        "{\n"
        '  \"gemini_score\": <integer 0-100>,\n'
        '  \"gemini_category\": '
        '\"phishing\" | \"lottery\" | \"investment\" | \"impersonation\" | '
        '\"romance\" | \"unknown\",\n'
        '  \"gemini_flags\": [<string>, ...],\n'
        '  \"explanation\": <string>,\n'
        '  \"safe_response\": <string>\n'
        "}\n\n"
        "Requirements:\n"
        "- Base your decision ONLY on the message text. You cannot browse the web.\n"
        "- \"gemini_score\" is an integer where 0 means definitely not a scam and "
        "100 means almost certainly a scam.\n"
        "- Use this scoring guide:\n"
        "  - 0–20: ordinary, low-risk message\n"
        "  - 21–49: suspicious or unclear; caution advised\n"
        "  - 50–79: likely scam; multiple red flags\n"
        "  - 80–100: very likely scam; strong pressure + unusual requests\n"
        "- \"gemini_category\" must be one of: "
        "phishing, lottery, investment, impersonation, romance, unknown.\n"
        "- \"gemini_flags\" is a list of short, concrete red flags you see.\n"
        "- \"explanation\" must be in simple, reassuring language suitable for an "
        "elderly person.\n"
        "- \"safe_response\" must be clear advice on what the person should do "
        "next, in plain language.\n"
        "- Treat these as strong red flags: urgent pressure, threats of arrest/fines, "
        "requests for passwords or verification codes, links to sign in, gift cards, "
        "wire transfers/crypto, moving to another app, or secrecy.\n"
        "- Also treat misspelled or look-alike company names (for example 'rnicrosft' "
        "instead of 'microsoft') and unusual or non-official website addresses as "
        "strong signs of impersonation scams.\n"
        "- Do not include any extra keys.\n"
        "- Do not include any text before or after the JSON object.\n\n"
        f"Message to analyze:\n{message}"
        f"{web_block}"
    )


def _normalize_gemini_score(raw_score: float) -> int:
    """Normalize Gemini score to an integer between 0 and 100."""
    value = float(raw_score)
    if 0.0 <= value <= 1.0:
        value *= 100.0
    return clamp_score(value)


def analyze_message_with_gemini(
    message: str, *, api_key: str | None = None, web_evidence: str | None = None
) -> GeminiAnalysisResult:
    """Analyze a message using Gemini and return structured scam assessment.

    Raises:
        ValueError: If the input message is empty or whitespace only.
        GeminiEngineError: If the Gemini API call, JSON parsing, or validation fails.
    """
    message_stripped = message.strip()
    if not message_stripped:
        raise ValueError("Message to analyze must not be empty.")

    prompt = _build_prompt(message_stripped, web_evidence)

    client = _create_client(api_key)
    model_names = (_resolve_model_name(), *_MODEL_CANDIDATES)
    last_exc: Exception | None = None
    for model_name in model_names:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=genai_types.GenerateContentConfig(
                    temperature=_TEMPERATURE,
                    response_mime_type="application/json",
                ),
            )
            break
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            continue
    else:
        raise GeminiEngineError(
            f"Gemini API request failed for all candidate models: {last_exc}"
        ) from last_exc

    raw_text = getattr(response, "text", "") or ""
    data = parse_json_safe(raw_text)
    if data is None:
        raise GeminiEngineError("Gemini returned malformed or non-dict JSON.")

    try:
        validated = _GeminiScamAnalysisModel.model_validate(data)
    except ValidationError as exc:
        raise GeminiEngineError(
            "Gemini JSON did not match the expected schema."
        ) from exc

    normalized_score = _normalize_gemini_score(validated.gemini_score)

    return {
        "gemini_score": normalized_score,
        "gemini_category": validated.gemini_category,
        "gemini_flags": list(validated.gemini_flags),
        "explanation": validated.explanation,
        "safe_response": validated.safe_response,
    }

