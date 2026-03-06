"""Rule-based scam detection engine for Elderly Scam Alert Assistant."""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from collections.abc import Iterable
from typing import Literal, TypedDict

from utils import clamp_score


ScamCategory = Literal[
    "phishing",
    "lottery",
    "investment",
    "impersonation",
    "romance",
    "unknown",
]


class RuleAnalysisResult(TypedDict):
    """Result of applying the rule-based scam detector."""

    rule_score: int
    rule_red_flags: list[str]
    preliminary_category: ScamCategory | None


@dataclass(frozen=True)
class KeywordRule:
    """Configuration for a simple keyword-based scam detection rule."""

    name: str
    keywords: tuple[str, ...]
    weight: float
    red_flag_label: str
    category_hint: ScamCategory | None


_KEYWORD_RULES: tuple[KeywordRule, ...] = (
    KeywordRule(
        name="urgent_language",
        keywords=(
            "act now",
            "urgent",
            "immediately",
            "right away",
            "within 24 hours",
            "do not delay",
            "final notice",
            "last chance",
            "limited time",
            "your account will be closed",
            "log in now",
        ),
        weight=10.0,
        red_flag_label="urgent language",
        category_hint="phishing",
    ),
    KeywordRule(
        name="lottery_winnings",
        keywords=(
            "you have won",
            "congratulations, you have been selected",
            "lottery",
            "jackpot",
            "winning prize",
            "claim your prize",
        ),
        weight=20.0,
        red_flag_label="lottery winnings claim",
        category_hint="lottery",
    ),
    KeywordRule(
        name="investment_promises",
        keywords=(
            "guaranteed returns",
            "risk-free investment",
            "high yield",
            "get rich quick",
            "double your money",
            "once-in-a-lifetime investment",
        ),
        weight=18.0,
        red_flag_label="unrealistic investment promises",
        category_hint="investment",
    ),
    KeywordRule(
        name="government_impersonation",
        keywords=(
            "social security administration",
            "social security office",
            "irs",
            "internal revenue service",
            "medicare",
            "government agency",
            "federal bureau of investigation",
            "fbi",
            "police department",
        ),
        weight=20.0,
        red_flag_label="government or authority impersonation",
        category_hint="impersonation",
    ),
    KeywordRule(
        name="romance_manipulation",
        keywords=(
            "soulmate",
            "true love",
            "love of my life",
            "i have fallen in love with you",
            "i cannot wait to meet you",
            "i have never felt this way",
        ),
        weight=16.0,
        red_flag_label="romance manipulation",
        category_hint="romance",
    ),
    KeywordRule(
        name="bank_verification",
        keywords=(
            "verify your account",
            "confirm your account",
            "your account has been locked",
            "account will be locked",
            "unusual activity on your account",
            "suspicious activity on your account",
            "update your billing information",
            "confirm your password",
            "verify your identity",
            "security alert",
            "fraud alert",
        ),
        weight=18.0,
        red_flag_label="bank or account verification request",
        category_hint="phishing",
    ),
    KeywordRule(
        name="gift_card_payment",
        keywords=(
            "gift card",
            "itunes card",
            "apple card",
            "amazon gift card",
            "steam card",
            "google play card",
            "pay using gift cards",
        ),
        weight=22.0,
        red_flag_label="gift card payment request",
        category_hint="impersonation",
    ),
    KeywordRule(
        name="password_or_code_request",
        keywords=(
            "one-time password",
            "otp",
            "verification code",
            "2fa code",
            "two factor code",
            "login code",
            "security code",
            "6-digit code",
            "passcode",
        ),
        weight=24.0,
        red_flag_label="request for a verification code or password",
        category_hint="phishing",
    ),
    KeywordRule(
        name="payment_pressure",
        keywords=(
            "pay now",
            "send money",
            "wire transfer",
            "bank transfer",
            "bitcoin",
            "crypto",
            "zelle",
            "cash app",
            "cashapp",
            "venmo",
            "western union",
            "moneygram",
        ),
        weight=18.0,
        red_flag_label="pressure to send money using unusual methods",
        category_hint="investment",
    ),
    KeywordRule(
        name="threats_or_legal",
        keywords=(
            "arrest",
            "warrant",
            "legal action",
            "court",
            "lawsuit",
            "fine",
            "penalty",
        ),
        weight=18.0,
        red_flag_label="threats or legal pressure",
        category_hint="impersonation",
    ),
    KeywordRule(
        name="secrecy_isolation",
        keywords=(
            "do not tell anyone",
            "keep this confidential",
            "secret",
            "don't tell your family",
        ),
        weight=14.0,
        red_flag_label="request for secrecy or isolation",
        category_hint="romance",
    ),
)


_URL_PATTERN = re.compile(r"https?://\\S+", flags=re.IGNORECASE)
_EMAIL_PATTERN = re.compile(r"\\b[\\w.+-]+@[\\w-]+\\.[\\w.-]+\\b", flags=re.IGNORECASE)
_PHONE_PATTERN = re.compile(
    r"(?:\\+?\\d{1,3}[\\s.-]?)?(?:\\(\\d{3}\\)|\\d{3})[\\s.-]?\\d{3}[\\s.-]?\\d{4}\\b"
)
_IP_URL_PATTERN = re.compile(r"https?://\\d{1,3}(?:\\.\\d{1,3}){3}(?::\\d+)?\\b")

_URL_SHORTENERS = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
)

_BRAND_NAMES: tuple[str, ...] = (
    "microsoft",
    "paypal",
    "apple",
    "amazon",
    "netflix",
    "google",
    "facebook",
    "instagram",
    "whatsapp",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "citibank",
    "revolut",
)

_BRAND_CONTEXT_WORDS: tuple[str, ...] = (
    "support",
    "account",
    "login",
    "log in",
    "sign in",
    "signin",
    "security",
    "verify",
    "verification",
    "update",
    "billing",
    "payment",
)


def _find_urls(message: str) -> list[str]:
    """Return a list of URLs present in the message."""
    return _URL_PATTERN.findall(message)


def _is_suspicious_url(url: str) -> bool:
    """Heuristic checks for suspicious URLs."""
    lowered = url.lower()
    if _IP_URL_PATTERN.search(lowered):
        return True
    if any(shortener in lowered for shortener in _URL_SHORTENERS):
        return True
    if "xn--" in lowered:
        return True
    return False


def _apply_keyword_rule(message_lower: str, rule: KeywordRule) -> bool:
    """Return True if any configured keyword is present in the message."""
    return any(keyword in message_lower for keyword in rule.keywords)


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein distance between two short strings."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current_row = [i]
        for j, cb in enumerate(b, start=1):
            insertions = previous_row[j] + 1
            deletions = current_row[j - 1] + 1
            substitutions = previous_row[j - 1] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _normalize_score(raw_score: float) -> int:
    """Map a raw risk score to a 0–100 probability using a saturating curve."""
    if raw_score <= 0.0:
        return 0
    k = 20.0
    scaled = 100.0 * (1.0 - math.exp(-raw_score / k))
    return clamp_score(scaled)


def _select_preliminary_category(
    category_scores: dict[ScamCategory, float],
) -> ScamCategory | None:
    """Choose the most likely scam category based on weighted scores."""
    if not category_scores:
        return None
    return max(category_scores.items(), key=lambda item: item[1])[0]


def _extend_unique(target: list[str], items: Iterable[str]) -> None:
    """Extend a list with new items, avoiding duplicates while preserving order."""
    existing = set(target)
    for item in items:
        if item not in existing:
            target.append(item)
            existing.add(item)


def analyze_message_with_rules(message: str) -> RuleAnalysisResult:
    """Analyze a message using static scam rules and return scoring details.

    The analysis identifies common scam patterns such as urgent language,
    lottery or investment promises, government impersonation, romance
    manipulation, bank verification requests, suspicious links, and
    gift card payment requests.
    """
    message_stripped = message.strip()
    if not message_stripped:
        return {
            "rule_score": 0,
            "rule_red_flags": [],
            "preliminary_category": None,
        }

    message_lower = message_stripped.lower()
    red_flags: list[str] = []
    raw_score = 0.0
    category_scores: dict[ScamCategory, float] = {}

    for rule in _KEYWORD_RULES:
        if _apply_keyword_rule(message_lower, rule):
            raw_score += rule.weight
            _extend_unique(red_flags, [rule.red_flag_label])
            if rule.category_hint is not None:
                category_scores[rule.category_hint] = category_scores.get(
                    rule.category_hint, 0.0
                ) + rule.weight

    urls = _find_urls(message_stripped)
    if urls:
        raw_score += 12.0
        _extend_unique(red_flags, ["link present"])
        category_scores["phishing"] = category_scores.get("phishing", 0.0) + 12.0

        if any(_is_suspicious_url(url) for url in urls):
            raw_score += 12.0
            _extend_unique(red_flags, ["suspicious link present"])
            category_scores["phishing"] = category_scores.get("phishing", 0.0) + 12.0

    if _EMAIL_PATTERN.search(message_stripped):
        raw_score += 6.0
        _extend_unique(red_flags, ["request to contact via email"])

    if _PHONE_PATTERN.search(message_stripped):
        raw_score += 6.0
        _extend_unique(red_flags, ["request to call a phone number"])

    if any(token in message_lower for token in ("log in", "login", "sign in", "signin")):
        if urls:
            raw_score += 10.0
            _extend_unique(red_flags, ["login link request"])
            category_scores["phishing"] = category_scores.get("phishing", 0.0) + 10.0

    if ("gift card" in message_lower) and urls:
        raw_score += 10.0

    tokens = re.findall(r"[a-z0-9]+", message_lower)
    brand_context = any(word in message_lower for word in _BRAND_CONTEXT_WORDS)
    for token in tokens:
        if len(token) < 5:
            continue
        for brand in _BRAND_NAMES:
            dist = _levenshtein(token, brand)
            if dist == 0:
                if brand_context:
                    raw_score += 18.0
                    _extend_unique(
                        red_flags,
                        [f"message mentions {brand} in an account or support context"],
                    )
                    category_scores["impersonation"] = category_scores.get(
                        "impersonation", 0.0
                    ) + 18.0
                continue
            if 1 <= dist <= 3:
                raw_score += 32.0
                _extend_unique(
                    red_flags,
                    [
                        "brand name looks misspelled or imitated "
                        f"(for example, '{token}' vs '{brand}')"
                    ],
                )
                category_scores["impersonation"] = category_scores.get(
                    "impersonation", 0.0
                ) + 32.0
                break

    rule_score = _normalize_score(raw_score)
    preliminary_category = _select_preliminary_category(category_scores)

    if preliminary_category is None and rule_score > 0:
        preliminary_category = "unknown"

    return {
        "rule_score": rule_score,
        "rule_red_flags": red_flags,
        "preliminary_category": preliminary_category,
    }

