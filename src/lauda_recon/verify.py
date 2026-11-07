"""Conservative active evidence checks for approved assets only.

No function validates a discovered credential against a provider API, claims a
cloud resource, follows redirects, or returns exposed file contents.
"""

from __future__ import annotations

from hashlib import sha256
import secrets
import socket
import ssl
from typing import Iterable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from .parsing import safe_text, sanitize_url
from .scope import Scope, normalize_hostname


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def resolve_host(hostname: str) -> dict[str, object]:
    try:
        host = normalize_hostname(hostname)
    except ValueError:
        return {"hostname": hostname, "addresses": [], "resolved": False, "error": "invalid hostname"}
    try:
        addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
        return {"hostname": host, "addresses": addresses, "resolved": bool(addresses), "error": ""}
    except socket.gaierror as exc:
        return {"hostname": host, "addresses": [], "resolved": False, "error": safe_text(exc, 160)}


def detect_wildcard_dns(scope: Scope, *, probes: int = 3) -> dict[str, object]:
    """Require a common answer across random labels before flagging wildcard DNS."""

    if not 2 <= probes <= 8:
        raise ValueError("probes must be between 2 and 8")
    hosts = [f"lauda-{secrets.token_hex(9)}.{scope.root_domain}" for _ in range(probes)]
    answers = [set(resolve_host(host)["addresses"]) for host in hosts]
    nonempty = [answer for answer in answers if answer]
    common = sorted(set.intersection(*nonempty)) if len(nonempty) >= 2 else []
    return {"root_domain": scope.root_domain, "probe_hosts": hosts, "answer_sets": [sorted(item) for item in answers], "wildcard_addresses": common, "detected": bool(common)}


def is_probable_wildcard(hostname: str, resolution: Mapping[str, object], profile: Mapping[str, object]) -> bool:
    try:
        host = normalize_hostname(hostname)
    except ValueError:
        return False
    wildcard = set(profile.get("wildcard_addresses", []))
    addresses = set(resolution.get("addresses", []))
    return bool(host != profile.get("root_domain") and wildcard and addresses and addresses.issubset(wildcard))


def _fetch(url: str, timeout: float) -> tuple[int, Mapping[str, str], bytes]:
    request = Request(url, headers={"User-Agent": "Lauda-Recon/1.0 (authorized assessment)"}, method="GET")
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.read(96_000)
    except HTTPError as exc:
        return exc.code, dict(exc.headers.items()) if exc.headers else {}, exc.read(96_000)


def _title(body: bytes) -> str:
    text = body.decode("utf-8", "replace")
    lower = text.lower()
    start = lower.find("<title")
    if start < 0:
        return ""
    start = lower.find(">", start)
    end = lower.find("</title>", start)
    return safe_text(text[start + 1:end] if start >= 0 and end >= 0 else "", 180)


def _technologies(headers: Mapping[str, str], body: bytes) -> list[str]:
    searchable = (" ".join(f"{key}:{value}" for key, value in headers.items()) + " " + body[:32_000].decode("utf-8", "replace")).lower()
    signatures = {"nginx": "Nginx", "microsoft-iis": "IIS", "x-powered-by: php": "PHP", "wp-content": "WordPress", "__next_data__": "Next.js", "react": "React (heuristic)", "django": "Django (heuristic)", "express": "Express (heuristic)"}
    return sorted({label for marker, label in signatures.items() if marker in searchable})


def _markers(path: str, body: bytes) -> tuple[list[str], list[str]]:
    """Return generic structural and provider indicators, never file contents."""

    text = body[:96_000].decode("utf-8", "replace").lower()
    structure: list[str] = []
    if path.endswith(".env") or "/.env" in path:
        structure = [item for item in ("db_host=", "database_url=", "app_key=", "mail_host=") if item in text]
    elif path.endswith(".git/config"):
        structure = [item for item in ("[core]", "repositoryformatversion", "[remote") if item in text]
    elif path.endswith("wp-config.php"):
        structure = [item for item in ("define( 'db_name'", "define('db_name'", "db_password") if item in text]
    elif path.endswith((".sql", ".bak", ".backup", ".zip", ".tar", ".gz")):
        structure = [item for item in ("create table", "insert into", "<?php", "pk\\x03\\x04") if item in text]
    provider = [label for label, phrase in (("github_pages_missing", "there isn't a github pages site here"), ("s3_missing_bucket", "nosuchbucket"), ("s3_missing_bucket", "the specified bucket does not exist"), ("heroku_missing_app", "no such app"), ("azure_site_missing", "404 web site not found")) if phrase in text]
    return structure, sorted(set(provider))


def probe_http(url: str, *, scope: Scope, timeout: float = 8.0) -> dict[str, object] | None:
    """Probe one in-scope URL; response content is reduced to non-sensitive metadata."""

    safe_url = sanitize_url(url)
    if not safe_url:
        return None
    host = urlsplit(safe_url).hostname or ""
    if not scope.allows(host):
        raise ValueError(f"refusing out-of-scope HTTP probe: {host}")
    try:
        status, headers, body = _fetch(safe_url, timeout)
    except (URLError, TimeoutError, OSError, ValueError):
        return None
    content_length = headers.get("Content-Length") or headers.get("content-length")
    try:
        length = int(content_length) if content_length is not None else len(body)
    except ValueError:
        length = len(body)
    structure, provider = _markers(urlsplit(safe_url).path.lower(), body)
    return {"url": safe_url, "hostname": host, "status_code": status, "title": _title(body), "content_length": length, "technologies": _technologies(headers, body), "webserver": safe_text(headers.get("Server") or headers.get("server"), 100), "page_digest": "sha256:" + sha256(body).hexdigest()[:16], "structural_markers": structure, "provider_signatures": provider, "source": "active_http"}


def build_soft_404_baseline(base_url: str, *, scope: Scope, timeout: float = 8.0) -> dict[str, object] | None:
    base = sanitize_url(base_url)
    if not base:
        return None
    if not scope.allows(urlsplit(base).hostname or ""):
        raise ValueError("refusing out-of-scope HTTP probe")
    results = [probe_http(f"{base.rstrip('/')}/__lauda_not_found_{secrets.token_hex(12)}", scope=scope, timeout=timeout) for _ in range(2)]
    if any(item is None for item in results):
        return None
    evidence = [item for item in results if item]
    return {"status_codes": [int(item["status_code"]) for item in evidence], "content_lengths": [int(item["content_length"]) for item in evidence], "page_digests": [str(item["page_digest"]) for item in evidence], "titles": [str(item["title"]).lower() for item in evidence if item["title"]]}


def resembles_soft_404(candidate: Mapping[str, object], baseline: Mapping[str, object] | None) -> bool:
    if not baseline or candidate.get("status_code") not in baseline.get("status_codes", []):
        return False
    if candidate.get("page_digest") in baseline.get("page_digests", []):
        return True
    length = int(candidate.get("content_length") or 0)
    if any(abs(length - int(item)) <= 96 for item in baseline.get("content_lengths", [])):
        return True
    title = str(candidate.get("title") or "").lower()
    return bool(title and title in baseline.get("titles", []))


def validate_exposure_structure(url: str, response: Mapping[str, object]) -> dict[str, object] | None:
    """Report a structurally valid exposed file only; never reveal its data."""

    path = urlsplit(url).path.lower()
    kind = ".env" if path.endswith(".env") or "/.env" in path else ".git/config" if path.endswith(".git/config") else "wp-config.php" if path.endswith("wp-config.php") else "backup artifact" if path.endswith((".sql", ".bak", ".backup", ".zip", ".tar", ".gz")) else ""
    markers = list(response.get("structural_markers", []))
    status = int(response.get("status_code") or 0)
    if not kind or not 200 <= status < 300 or len(markers) < 2:
        return None
    return {"category": "exposed_sensitive_file", "url": str(response.get("url") or url), "file_kind": kind, "status_code": status, "structural_markers": markers, "confidence": "structure_confirmed_no_contents_retained"}


_TAKEOVER = (("GitHub Pages", "github.io", "github_pages_missing"), ("AWS S3", "s3.amazonaws.com", "s3_missing_bucket"), ("Heroku", "herokudns.com", "heroku_missing_app"), ("Azure App Service", "azurewebsites.net", "azure_site_missing"))


def verify_takeover_signature(hostname: str, cname_targets: Iterable[str], response: Mapping[str, object]) -> dict[str, str] | None:
    """Correlate known CNAME and public provider error signature; do not claim it."""

    try:
        host = normalize_hostname(hostname)
    except ValueError:
        return None
    targets: list[str] = []
    for item in cname_targets:
        try:
            targets.append(normalize_hostname(item))
        except ValueError:
            continue
    signatures = set(response.get("provider_signatures", []))
    for provider, suffix, marker in _TAKEOVER:
        target = next((target for target in targets if target == suffix or target.endswith("." + suffix)), None)
        if target and marker in signatures:
            return {"hostname": host, "cname_target": target, "provider": provider, "signature": marker, "confidence": "needs_manual_review", "verification": "CNAME and public provider error signature observed; no claim attempted"}
    return None


def select_wordlist_profiles(technologies: Iterable[str]) -> list[str]:
    """Return safe wordlist profile labels, not a blind all-framework list."""

    tech = " ".join(technologies).lower()
    profiles = ["common"]
    if "php" in tech or "wordpress" in tech:
        profiles.append("php")
    if "iis" in tech or "asp.net" in tech:
        profiles.append("iis")
    if "django" in tech:
        profiles.append("django")
    if "express" in tech or "node" in tech or "next.js" in tech:
        profiles.append("node")
    return profiles
