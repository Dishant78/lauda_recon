"""Safe renderers for Lauda Recon reports.

The canonical scan data model lives in :mod:`lauda_recon.models`. This layer
only serializes observations for people and downstream tools, and redacts
credential-like material defensively before it reaches a terminal or file.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


_SENSITIVE_FIELD = re.compile(
    r"(?:secret|token|password|passphrase|authorization|credential|private[_-]?key|api[_-]?key)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?:\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9_]{20,}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)
_INLINE_CREDENTIAL = re.compile(
    r"\b(?:secret|token|password|passphrase|authorization|credential|private[_-]?key|api[_-]?key)\s*[:=]\s*[^\s,;]+",
    re.IGNORECASE,
)


def redact(value: Any, *, field_name: str = "") -> Any:
    """Remove likely credential material recursively before presentation."""

    if _SENSITIVE_FIELD.search(field_name):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(key): redact(item, field_name=str(key)) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        value = _SECRET_VALUE.sub("[REDACTED]", value)
        return _INLINE_CREDENTIAL.sub("[REDACTED]", value)
    return value


def report_to_dict(report: Any) -> dict[str, Any]:
    """Convert a RunReport-like object to a redacted JSON-compatible mapping."""

    if isinstance(report, Mapping):
        data = dict(report)
    elif hasattr(report, "to_dict"):
        data = report.to_dict()
    else:
        raise TypeError("scan result must be a mapping or expose to_dict()")
    if not isinstance(data, Mapping):
        raise TypeError("report to_dict() must return a mapping")
    return redact(dict(data))


def finish_report(report: Any) -> None:
    """Set a completion timestamp when the concrete report model supports it."""

    if hasattr(report, "finish") and getattr(report, "finished_at", None) is None:
        report.finish()


def _timestamp(value: Any) -> str:
    if value is None:
        return "in progress"
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def report_to_text(report: Any) -> str:
    """Render the canonical report in a portable human-readable format."""

    data = report_to_dict(report)
    lines = [
        "LAUDA RECON REPORT",
        f"Domain: {data.get('domain', 'unknown')}",
        f"Started (UTC): {_timestamp(data.get('started_at'))}",
        f"Finished (UTC): {_timestamp(data.get('finished_at'))}",
        "",
        "Every entry is an evidence-backed observation, not proof of an exploitable vulnerability.",
        "Validate results manually and handle sensitive material through an approved disclosure process.",
        "",
    ]
    summary = data.get("summary", {})
    if summary:
        lines.extend(
            (
                f"Summary: {summary.get('assets', 0)} asset(s), {summary.get('live_services', 0)} live service(s), {summary.get('findings', 0)} finding(s).",
                "",
            )
        )

    assets = data.get("assets", [])
    if assets:
        lines.append("## Assets")
        for asset in assets:
            hostname = asset.get("hostname", "unknown")
            sources = ", ".join(asset.get("sources", [])) or "unknown source"
            ips = ", ".join(asset.get("ips", []))
            lines.append(f"- {hostname} (sources: {sources}{'; IPs: ' + ips if ips else ''})")
            for service in asset.get("live_services", []):
                pieces = [service.get("url", "service")]
                if service.get("status_code") is not None:
                    pieces.append(f"HTTP {service['status_code']}")
                if service.get("title"):
                    pieces.append(f"title: {service['title']}")
                if service.get("technologies"):
                    pieces.append("tech: " + ", ".join(service["technologies"]))
                lines.append("  - " + " | ".join(pieces))
        lines.append("")

    findings = data.get("findings", [])
    if findings:
        lines.append("## Findings")
        for finding in findings:
            severity = str(finding.get("severity", "info")).upper()
            confidence = finding.get("confidence", "observed")
            title = finding.get("title", finding.get("target", "Untitled observation"))
            asset = finding.get("asset", finding.get("target", ""))
            lines.append(f"- [{severity}; {confidence}] {title} - {asset}")
            verification = finding.get("verification", finding.get("evidence", ""))
            if verification:
                lines.append(f"  Verification: {verification}")
            for evidence in finding.get("evidence", []):
                if isinstance(evidence, Mapping):
                    detail = evidence.get("detail", "")
                    source = evidence.get("source", "")
                    url = evidence.get("url")
                    suffix = f" ({url})" if url else ""
                    lines.append(f"  Evidence: {source}: {detail}{suffix}")
            metadata = finding.get("metadata")
            if metadata:
                lines.append("  Metadata: " + json.dumps(metadata, sort_keys=True, ensure_ascii=False))
        lines.append("")
    else:
        lines.extend(("No findings were recorded.", ""))

    tools = data.get("tools", {})
    if tools:
        lines.append("## Tool execution")
        for name, result in tools.items():
            if isinstance(result, Mapping):
                state = "ran" if result.get("ran") else "not run"
                availability = "available" if result.get("available") else "unavailable"
                message = result.get("message", "")
                lines.append(f"- {name}: {availability}; {state}" + (f" - {message}" if message else ""))
            else:
                lines.append(f"- {name}: {result}")
        lines.append("")

    notes = data.get("notes", data.get("notices", []))
    if notes:
        lines.append("## Notes")
        lines.extend(f"- {note}" for note in notes)
    return "\n".join(lines).rstrip() + "\n"


def report_to_json(report: Any) -> str:
    return json.dumps(report_to_dict(report), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_report(report: Any, *, text_path: Path | None = None, json_path: Path | None = None) -> None:
    """Persist optional report formats with UTF-8 encoding."""

    if text_path:
        text_path.parent.mkdir(parents=True, exist_ok=True)
        text_path.write_text(report_to_text(report), encoding="utf-8")
    if json_path:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(report_to_json(report), encoding="utf-8")
