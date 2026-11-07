"""Safe endpoint extraction from robots.txt and sitemap XML.

Only normalized in-scope URLs are returned; page bodies are discarded as soon
as their links have been extracted. Redirects are deliberately not followed.
"""

from __future__ import annotations

import re
import ssl
from collections.abc import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from .parsing import sanitize_url
from .scope import Scope


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


_SITEMAP = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)
_ROBOTS_VALUE = re.compile(r"(?im)^\s*(?:sitemap|allow|disallow)\s*:\s*(\S+)")


def _fetch_text(url: str, timeout: float) -> tuple[int, str] | None:
    request = Request(url, headers={"User-Agent": "Lauda-Recon/0.2 (authorized assessment)"})
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(512_000).decode("utf-8", "replace")
    except HTTPError as exc:
        return exc.code, exc.read(512_000).decode("utf-8", "replace")
    except (URLError, TimeoutError, OSError, ValueError):
        return None


def _scoped_urls(values: Iterable[str], *, base_url: str, scope: Scope) -> list[str]:
    found: list[str] = []
    for raw in values:
        candidate = sanitize_url(urljoin(base_url, raw.strip()))
        if not candidate or not scope.allows(urlsplit(candidate).hostname or ""):
            continue
        if candidate not in found:
            found.append(candidate)
    return found


def extract_public_endpoints(base_url: str, *, scope: Scope, timeout: float = 8.0) -> list[dict[str, str]]:
    """Extract bounded public endpoint references from robots and sitemap files."""
    base = sanitize_url(base_url)
    if not base or not scope.allows(urlsplit(base).hostname or ""):
        return []
    output: list[dict[str, str]] = []
    for path, kind in (("robots.txt", "robots.txt"), ("sitemap.xml", "sitemap.xml")):
        source_url = urljoin(base.rstrip("/") + "/", path)
        result = _fetch_text(source_url, timeout)
        if not result:
            continue
        status, text = result
        if not 200 <= status < 300:
            continue
        values = _ROBOTS_VALUE.findall(text) if kind == "robots.txt" else _SITEMAP.findall(text)
        for url in _scoped_urls(values, base_url=base, scope=scope)[:200]:
            output.append({"url": url, "source": kind})
    return list({item["url"]: item for item in output}.values())[:300]
