"""Context-aware content candidates and endpoint normalization.

This module deliberately supplies short, reviewable path sets rather than a
blind mega-wordlist. Operators can explicitly add approved paths through a
configuration file when their rules of engagement allow it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from urllib.parse import urlsplit

from .parsing import sanitize_url


PATHS_BY_PROFILE: dict[str, tuple[str, ...]] = {
    "common": (
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/api",
        "/api/v1", "/openapi.json", "/swagger", "/swagger/index.html",
        "/graphql", "/health", "/status",
    ),
    "php": ("/wp-login.php", "/wp-admin/", "/wp-json/", "/phpinfo.php", "/wp-config.php"),
    "iis": ("/web.config", "/Trace.axd", "/elmah.axd", "/aspnet_client/"),
    "django": ("/admin/", "/__debug__/", "/api/schema/"),
    "node": ("/api/health", "/api/docs", "/_next/static/"),
}

# These paths have a separate structural-validation gate before an exposure is
# reported. Their mere status code is never considered a finding.
SENSITIVE_PATHS: tuple[str, ...] = (
    "/.env", "/.git/config", "/backup.sql", "/database.sql", "/site.bak",
)


def normalize_path(value: str) -> str | None:
    value = value.strip()
    if not value or "\x00" in value or "://" in value or "?" in value or "#" in value:
        return None
    if not value.startswith("/"):
        value = "/" + value
    if "//" in value or "/../" in value or value.endswith("/.."):
        return None
    return value


def load_approved_paths(path: Path | None, *, maximum: int = 300) -> list[str]:
    """Load bounded user-approved relative paths; comments are supported."""
    if path is None:
        return []
    values: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.lstrip().startswith("#"):
            continue
        candidate = normalize_path(raw)
        if candidate and candidate not in values:
            values.append(candidate)
        if len(values) >= maximum:
            break
    return values


def context_paths(profiles: Iterable[str], *, additional: Iterable[str] = ()) -> list[str]:
    """Build a stable, bounded path plan from verified technology evidence."""
    plan: list[str] = []
    for profile in profiles:
        for path in PATHS_BY_PROFILE.get(profile, ()):
            if path not in plan:
                plan.append(path)
    for path in SENSITIVE_PATHS:
        if path not in plan:
            plan.append(path)
    for raw in additional:
        path = normalize_path(raw)
        if path and path not in plan:
            plan.append(path)
    return plan[:350]


def scoped_endpoint_urls(urls: Iterable[str], *, host_allowed: Callable[[str], bool]) -> list[str]:
    """Normalize tool-discovered URLs and retain only host-scoped endpoints."""
    result: list[str] = []
    for raw in urls:
        url = sanitize_url(raw)
        if not url:
            continue
        host = urlsplit(url).hostname or ""
        if host_allowed(host) and url not in result:
            result.append(url)
    return result
