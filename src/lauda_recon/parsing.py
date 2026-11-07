"""Redaction-first parsers for the optional external reconnaissance tools.

All public functions return plain dictionaries so the orchestrator can decide
how to render/store results. Secret-scanner output is converted to an opaque
fingerprint; credential values never leave this module.
"""

from __future__ import annotations

from hashlib import sha256
import ipaddress
import json
import re
from typing import Any, Iterable, Iterator, Mapping
from urllib.parse import urlsplit, urlunsplit

from .scope import normalize_hostname


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def safe_text(value: object, limit: int = 300) -> str:
    """Produce a bounded printable report field from untrusted tool output."""

    return _CONTROL.sub(" ", str(value or "")).strip()[:limit]


def hostname_or_none(value: object) -> str | None:
    try:
        text = str(value or "").strip()
        if "://" in text:
            text = urlsplit(text).hostname or ""
        # The scope module intentionally excludes IP literals as hostnames.
        ipaddress.ip_address(text.rstrip("."))
        return None
    except ValueError:
        pass
    try:
        return normalize_hostname(str(value or ""))
    except ValueError:
        return None


def sanitize_url(value: object) -> str | None:
    """Return a safe HTTP(S) URL without query strings, credentials or fragments."""

    try:
        parsed = urlsplit(str(value or "").strip())
        host = hostname_or_none(parsed.hostname or "")
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            return None
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        return None
    return urlunsplit((parsed.scheme.lower(), host + port, parsed.path or "/", "", ""))


def json_objects(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Yield well-formed objects from JSONL; malformed/oversized rows are ignored."""

    for raw in lines:
        line = raw.strip()
        if not line or len(line) > 5_000_000:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            yield item


def parse_subfinder_jsonl(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    for item in json_objects(lines):
        host = hostname_or_none(item.get("host") or item.get("input"))
        if host:
            yield {"hostname": host, "source": "subfinder", "cname_targets": []}


def parse_amass_jsonl(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    for item in json_objects(lines):
        host = hostname_or_none(item.get("name") or item.get("domain"))
        if not host:
            continue
        cnames: set[str] = set()
        addresses = item.get("addresses")
        if isinstance(addresses, list):
            for address in addresses:
                if not isinstance(address, Mapping):
                    continue
                if str(address.get("type", "")).upper() == "CNAME":
                    target = hostname_or_none(address.get("address"))
                    if target:
                        cnames.add(target)
        yield {"hostname": host, "source": "amass", "cname_targets": sorted(cnames)}


def parse_puredns_lines(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Parse common Puredns formats into DNS records without executing lookups."""

    for line in lines:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        host = hostname_or_none(parts[0])
        if not host:
            continue
        record_type = "A"
        value = parts[-1]
        if len(parts) >= 3 and parts[1].upper() in {"A", "AAAA", "CNAME"}:
            record_type, value = parts[1].upper(), parts[2]
        if record_type == "CNAME":
            target = hostname_or_none(value)
            if not target:
                continue
            yield {"hostname": host, "record_type": "CNAME", "value": target, "source": "puredns"}
            continue
        try:
            address = str(ipaddress.ip_address(value))
        except ValueError:
            continue
        yield {"hostname": host, "record_type": record_type, "value": address, "source": "puredns"}


def _strings(value: object, limit: int = 100) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        value = [value]
    return sorted({text for item in value if (text := safe_text(item, limit))})


def parse_httpx_jsonl(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    for item in json_objects(lines):
        url = sanitize_url(item.get("url") or item.get("final_url"))
        host = hostname_or_none(item.get("host") or item.get("input"))
        if not host and url:
            host = hostname_or_none(urlsplit(url).hostname)
        if not url or not host:
            continue
        try:
            status_code = int(item["status_code"]) if item.get("status_code") is not None else None
        except (TypeError, ValueError):
            status_code = None
        try:
            content_length = int(item["content_length"]) if item.get("content_length") is not None else None
        except (TypeError, ValueError):
            content_length = None
        yield {
            "url": url,
            "hostname": host,
            "status_code": status_code,
            "title": safe_text(item.get("title"), 180),
            "content_length": content_length,
            "technologies": _strings(item.get("tech") or item.get("technologies")),
            "webserver": safe_text(item.get("webserver") or item.get("server"), 100),
            "source": "httpx",
        }


def parse_url_lines(lines: Iterable[str], *, source: str) -> Iterator[dict[str, str]]:
    """Parse GAU plain-text or Katana JSONL URLs, dropping query parameters."""

    for line in lines:
        raw = line.strip()
        if not raw:
            continue
        value: object = raw
        if raw.startswith("{"):
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, Mapping):
                continue
            request = item.get("request")
            value = item.get("url") or item.get("endpoint")
            if not value and isinstance(request, Mapping):
                value = request.get("endpoint") or request.get("url")
        url = sanitize_url(value)
        if url:
            yield {"url": url, "source": source}


def parse_trufflehog_jsonl(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Create redacted indicators from TruffleHog JSONL.

    This intentionally ignores the tool's `Verified` field and never invokes
    provider APIs.  An indicator is a lead for secure manual triage, not proof
    that a credential is live.
    """

    for item in json_objects(lines):
        detector = safe_text(item.get("DetectorName") or item.get("DetectorType") or "unknown", 100)
        raw = item.get("Raw")
        if isinstance(raw, str) and raw:
            fingerprint = "sha256:" + sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]
            length = len(raw)
        else:
            source_id = json.dumps(item.get("SourceID") or item.get("SourceMetadata") or "unknown", sort_keys=True, default=str)
            fingerprint = "source:" + sha256(source_id.encode("utf-8", "replace")).hexdigest()[:16]
            length = 0
        # SourceMetadata can include an untrusted code snippet. Preserve a
        # stable triage reference without ever emitting its raw value.
        source_material = json.dumps(item.get("SourceMetadata") or item.get("SourceID") or "unknown", sort_keys=True, default=str)
        source = "source-sha256:" + sha256(source_material.encode("utf-8", "replace")).hexdigest()[:16]
        yield {
            "detector": detector or "unknown",
            "source": source,
            "fingerprint": fingerprint,
            "secret_length": length,
            "verification": "not_checked",
            "redacted": True,
        }


def unique_records(records: Iterable[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    """Stable deduplication for parser output."""

    seen: set[object] = set()
    result: list[dict[str, Any]] = []
    for record in records:
        value = record.get(key)
        if value not in seen:
            seen.add(value)
            result.append(record)
    return result
