"""Optional web search enrichment for FraudFence.

This module is intentionally dependency-free (stdlib only). It can call a
configured web search API to fetch public snippets that may help identify
known scam campaigns, domains, or message templates.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Final, Literal


SearchProvider = Literal["serper"]


class WebSearchError(Exception):
    """Raised when a web search request fails."""


@dataclass(frozen=True)
class WebSearchEvidence:
    """A compact set of web evidence snippets."""

    provider: SearchProvider
    query: str
    items: list[str]

    def to_prompt_block(self, *, max_chars: int = 1800) -> str:
        """Render evidence as a prompt-safe block of text."""
        header = f"Web search provider: {self.provider}\nQuery: {self.query}\n"
        joined = "\n".join(f"- {item}" for item in self.items if item.strip())
        text = (header + "\nTop results:\n" + joined).strip()
        return text[:max_chars]


_URL_PATTERN: Final[re.Pattern[str]] = re.compile(r"https?://\S+", flags=re.IGNORECASE)
_DOMAIN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^([a-z0-9-]+\.)+[a-z]{2,}$", flags=re.IGNORECASE
)


def _extract_domains(message: str) -> list[str]:
    """Extract domain names from URLs contained in the message."""
    domains: list[str] = []
    for url in _URL_PATTERN.findall(message):
        try:
            parsed = urllib.parse.urlparse(url)
        except ValueError:
            continue
        host = (parsed.hostname or "").strip().lower()
        if host.startswith("www."):
            host = host[4:]
        if host and _DOMAIN_PATTERN.match(host):
            if host not in domains:
                domains.append(host)
    return domains


def _build_query(message: str) -> str:
    """Build a search query from the message content."""
    domains = _extract_domains(message)
    if domains:
        return f"{domains[0]} scam text message"

    cleaned = " ".join(message.split())
    cleaned = cleaned[:160]
    return f"\"{cleaned}\" scam"


def _resolve_serper_api_key(api_key: str | None) -> str:
    if api_key is not None and api_key.strip():
        value = api_key.strip()
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1].strip()
        return value
    value = os.environ.get("SERPER_API_KEY", "").strip()
    if not value:
        raise WebSearchError("SERPER_API_KEY is not configured.")
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        value = value[1:-1].strip()
    return value


def _serper_search(query: str, *, api_key: str | None, timeout_s: float) -> WebSearchEvidence:
    key = _resolve_serper_api_key(api_key)
    url = "https://google.serper.dev/search"
    payload = json.dumps({"q": query, "num": 5}).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-API-KEY": key,
            "User-Agent": "FraudFence/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        raise WebSearchError("Web search request failed.") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WebSearchError("Web search response was not valid JSON.") from exc

    organic = data.get("organic")
    if not isinstance(organic, list):
        return WebSearchEvidence(provider="serper", query=query, items=[])

    items: list[str] = []
    for entry in organic[:5]:
        if not isinstance(entry, dict):
            continue
        title = str(entry.get("title") or "").strip()
        snippet = str(entry.get("snippet") or "").strip()
        link = str(entry.get("link") or "").strip()
        line = " — ".join(part for part in (title, snippet) if part)
        if link:
            line = f"{line} ({link})" if line else link
        if line:
            items.append(line)

    return WebSearchEvidence(provider="serper", query=query, items=items)


def get_web_evidence(
    message: str,
    *,
    provider: SearchProvider = "serper",
    api_key: str | None = None,
    timeout_s: float = 8.0,
) -> WebSearchEvidence:
    """Fetch compact web evidence for a suspicious message.

    Raises:
        ValueError: If message is empty.
        WebSearchError: If provider isn't configured or request fails.
    """
    stripped = message.strip()
    if not stripped:
        raise ValueError("message must not be empty.")

    query = _build_query(stripped)
    if provider == "serper":
        return _serper_search(query, api_key=api_key, timeout_s=timeout_s)
    raise WebSearchError(f"Unsupported provider: {provider}")

