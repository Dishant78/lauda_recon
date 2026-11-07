"""Rate-limit-respecting GitHub reference discovery.

The collector uses at most one token from an environment variable and returns
repository/path references only. It never fetches file blobs, prints matching
source text, rotates tokens, or validates a discovered credential.
"""

from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


API_ROOT = "https://api.github.com"
USER_AGENT = "Lauda-Recon/0.2 (authorized-security-assessment)"


def token_from_environment(env_name: str | None) -> str | None:
    if not env_name:
        return None
    value = os.environ.get(env_name, "").strip()
    return value or None


def _get_json(url: str, token: str, timeout: float) -> tuple[int, dict[str, Any], dict[str, str]]:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read(1_000_000).decode("utf-8", "replace"))
            return response.status, payload if isinstance(payload, dict) else {}, dict(response.headers.items())
    except HTTPError as exc:
        try:
            payload = json.loads(exc.read(100_000).decode("utf-8", "replace"))
        except (json.JSONDecodeError, OSError):
            payload = {}
        return exc.code, payload if isinstance(payload, dict) else {}, dict(exc.headers.items()) if exc.headers else {}


def search_code_references(domain: str, *, token: str | None, timeout: float = 12.0) -> tuple[list[dict[str, str]], list[str]]:
    """Return public code-location references for an approved domain.

    GitHub Code Search requires authentication. When a token is absent, this
    returns a notice instead of trying unauthenticated fallbacks or cycling
    through credential lists.
    """
    if not token:
        return [], ["GitHub reference search skipped: set one authorized token in GITHUB_TOKEN (or configure github_token_env)."]
    queries = (f'"{domain}"', f'"{domain}" extension:env', f'"{domain}" filename:config')
    found: dict[str, dict[str, str]] = {}
    notices: list[str] = []
    for query in queries:
        url = f"{API_ROOT}/search/code?q={quote(query)}&per_page=50"
        try:
            status, payload, headers = _get_json(url, token, timeout)
        except (URLError, TimeoutError, OSError) as exc:
            notices.append(f"GitHub reference search failed: {type(exc).__name__}.")
            break
        if status != 200:
            remaining = headers.get("X-RateLimit-Remaining", "unknown")
            notices.append(f"GitHub reference search returned HTTP {status} (rate-limit remaining: {remaining}); no token rotation was attempted.")
            break
        items = payload.get("items", [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            repository = item.get("repository") if isinstance(item.get("repository"), dict) else {}
            repo_name = str(repository.get("full_name") or "unknown")
            path = str(item.get("path") or "unknown")
            html_url = str(item.get("html_url") or "")
            if not html_url.startswith("https://github.com/"):
                continue
            found.setdefault(html_url, {"repository": repo_name[:300], "path": path[:1000], "url": html_url})
    return list(found.values()), notices
