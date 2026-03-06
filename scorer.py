"""Fusion and scoring logic for Elderly Scam Alert Assistant."""

from __future__ import annotations

from typing import Literal, TypedDict

from gemini_engine import (
    GeminiAnalysisResult,
    GeminiEngineError,
    analyze_message_with_gemini,
)
from scam_rules import RuleAnalysisResult, ScamCategory, analyze_message_with_rules
from utils import clamp_score
from web_search import WebSearchError, get_web_evidence


class ScamAssessment(TypedDict):
    """Final structured scam assessment returned to callers."""

    red_flags: list[str]
    scam_probability: int
    scam_category: ScamCategory
    explanation: str
    safe_response: str
    gemini_details: GeminiAnalysisResult | None
    gemini_error: str | None


def _combine_red_flags(rule_flags: list[str], gemini_flags: list[str]) -> list[str]:
    """Combine and deduplicate red flags while preserving order."""
    combined: list[str] = []
    seen: set[str] = set()
    for source in (rule_flags, gemini_flags):
        for flag in source:
            flag_normalized = flag.strip()
            if flag_normalized and flag_normalized not in seen:
                combined.append(flag_normalized)
                seen.add(flag_normalized)
    return combined


def _merge_categories(
    rule_category: ScamCategory | None,
    rule_score: int,
    gemini_category: ScamCategory,
    gemini_score: int,
) -> ScamCategory:
    """Merge categories using weighted confidence from rules and Gemini.

    If both sources agree on a non-unknown category, that category is used.
    Otherwise, a weighted score is computed for each non-unknown category,
    giving Gemini 60% weight and rules 40%, mirroring the probability fusion.
    """
    if gemini_category == rule_category and gemini_category != "unknown":
        return gemini_category

    weights: dict[ScamCategory, float] = {}

    if gemini_category != "unknown":
        weights[gemini_category] = weights.get(gemini_category, 0.0) + (
            gemini_score * 0.6
        )

    if rule_category is not None and rule_category != "unknown":
        weights[rule_category] = weights.get(rule_category, 0.0) + (
            rule_score * 0.4
        )

    if not weights:
        if gemini_category != "unknown":
            return gemini_category
        if rule_category is not None:
            return rule_category
        return "unknown"

    return max(weights.items(), key=lambda item: item[1])[0]


def _compute_final_score(rule_score: int, gemini_score: int) -> int:
    """Compute fused scam probability from rule and Gemini scores."""
    fused = (0.6 * float(gemini_score)) + (0.4 * float(rule_score))
    return clamp_score(fused)


def _build_rule_only_explanation(
    rule_result: RuleAnalysisResult,
) -> str:
    """Create a simple explanation when only rules are available."""
    score = rule_result["rule_score"]
    flags = rule_result["rule_red_flags"]

    if score <= 0:
        return (
            "Our basic checks did not find common signs of a scam in this message. "
            "Still, it is wise to be careful and never share personal or banking "
            "details unless you are sure who you are dealing with."
        )

    flags_text = ", ".join(flags) if flags else "possible warning signs"
    return (
        "Our basic checks found warning signs that this message may be a scam, "
        f"including: {flags_text}. Please treat it with caution."
    )


def _build_rule_only_safe_response(
    probability: int,
    category: ScamCategory | None,
) -> str:
    """Create safe response guidance using only rule-based information."""
    cat = category or "unknown"
    if probability >= 70:
        return (
            "This message is likely a scam. Do not reply, do not click on any "
            "links, and do not send money or gift cards. If it mentions your "
            "bank or an official organisation, call the number on the back of "
            "your card or from an official letter, not any number in the message."
        )
    if probability >= 40:
        return (
            "This message may be a scam. Be very careful. Do not share bank "
            "details, passwords, or codes. If you are unsure, ask a trusted "
            "family member or friend to look at the message with you."
        )
    if cat in ("phishing", "impersonation"):
        return (
            "The message may be safe, but it is still best not to share personal "
            "or banking information by text or email. If it claims to be from a "
            "company or government office, contact them using a phone number you "
            "already trust."
        )
    return (
        "This message does not clearly look like a scam, but stay cautious. "
        "Do not feel rushed, and never send money or personal details unless "
        "you are completely comfortable and have checked it with someone you trust."
    )


def assess_message(
    message: str,
    *,
    api_key: str | None = None,
    enable_web_search: bool = False,
    serper_api_key: str | None = None,
) -> ScamAssessment:
    """Assess a message using both rules and Gemini and return final JSON-ready data.

    This function orchestrates rule-based analysis, Gemini reasoning-based
    analysis, and deterministic fusion to produce a single, structured result.
    """
    rule_result: RuleAnalysisResult = analyze_message_with_rules(message)

    web_evidence_text: str | None = None
    if enable_web_search:
        try:
            evidence = get_web_evidence(message, api_key=serper_api_key)
            block = evidence.to_prompt_block()
            web_evidence_text = block if block.strip() else None
        except (WebSearchError, ValueError):
            web_evidence_text = None

    try:
        gemini_result = analyze_message_with_gemini(
            message,
            api_key=api_key,
            web_evidence=web_evidence_text,
        )
        gemini_error: str | None = None
    except GeminiEngineError as exc:
        gemini_error = str(exc)
        probability = rule_result["rule_score"]
        category = rule_result.get("preliminary_category") or "unknown"
        explanation = _build_rule_only_explanation(rule_result)
        safe_response = _build_rule_only_safe_response(probability, category)
        return {
            "red_flags": list(rule_result["rule_red_flags"]),
            "scam_probability": probability,
            "scam_category": category,
            "explanation": explanation,
            "safe_response": safe_response,
            "gemini_details": None,
            "gemini_error": gemini_error,
        }

    probability = _compute_final_score(
        rule_score=rule_result["rule_score"],
        gemini_score=gemini_result["gemini_score"],
    )

    category = _merge_categories(
        rule_category=rule_result.get("preliminary_category"),
        rule_score=rule_result["rule_score"],
        gemini_category=gemini_result["gemini_category"],
        gemini_score=gemini_result["gemini_score"],
    )

    red_flags = _combine_red_flags(
        rule_result["rule_red_flags"], gemini_result["gemini_flags"]
    )

    return {
        "red_flags": red_flags,
        "scam_probability": probability,
        "scam_category": category,
        "explanation": gemini_result["explanation"],
        "safe_response": gemini_result["safe_response"],
        "gemini_details": gemini_result,
        "gemini_error": None,
    }

