"""Data contracts for Lauda Recon.

The report model intentionally separates what a tool observed from what a
reviewer has verified.  It never stores candidate secret values.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class Confidence(StrEnum):
    OBSERVED = "observed"
    VERIFIED = "verified"
    NEEDS_REVIEW = "needs_review"
    NOT_VERIFIED = "not_verified"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class HttpService:
    url: str
    status_code: int | None = None
    title: str | None = None
    content_length: int | None = None
    technologies: list[str] = field(default_factory=list)
    webserver: str | None = None
    final_url: str | None = None
    source: str = "httpx"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Asset:
    hostname: str
    sources: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    cname: str | None = None
    live_services: list[HttpService] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "sources": sorted(self.sources),
            "ips": sorted(self.ips),
            "cname": self.cname,
            "live_services": [service.to_dict() for service in self.live_services],
        }


@dataclass(slots=True)
class Evidence:
    source: str
    detail: str
    url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    category: str
    title: str
    asset: str
    severity: Severity
    confidence: Confidence
    verification: str
    evidence: list[Evidence] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "asset": self.asset,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "verification": self.verification,
            "evidence": [entry.to_dict() for entry in self.evidence],
            "tags": self.tags,
        }


@dataclass(slots=True)
class ToolResult:
    name: str
    available: bool
    ran: bool = False
    records: int = 0
    message: str = ""
    duration_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunReport:
    domain: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    assets: dict[str, Asset] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    tools: dict[str, ToolResult] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def asset(self, hostname: str, source: str | None = None) -> Asset:
        hostname = hostname.lower().rstrip(".")
        item = self.assets.setdefault(hostname, Asset(hostname=hostname))
        if source:
            item.sources.add(source)
        return item

    def add_finding(self, finding: Finding) -> None:
        # Dedupe identical observations while retaining independent evidence.
        key = (finding.category, finding.title, finding.asset, finding.confidence)
        for existing in self.findings:
            existing_key = (existing.category, existing.title, existing.asset, existing.confidence)
            if existing_key == key:
                for evidence in finding.evidence:
                    if evidence not in existing.evidence:
                        existing.evidence.append(evidence)
                return
        self.findings.append(finding)

    def finish(self) -> None:
        self.finished_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        severity_counts = Counter(finding.severity.value for finding in self.findings)
        confidence_counts = Counter(finding.confidence.value for finding in self.findings)
        return {
            "schema_version": "1.0",
            "domain": self.domain,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "assets": [asset.to_dict() for asset in sorted(self.assets.values(), key=lambda value: value.hostname)],
            "findings": [finding.to_dict() for finding in self.findings],
            "tools": {name: result.to_dict() for name, result in sorted(self.tools.items())},
            "notes": self.notes,
            "summary": {
                "assets": len(self.assets),
                "live_services": sum(len(asset.live_services) for asset in self.assets.values()),
                "findings": len(self.findings),
                "findings_by_severity": dict(sorted(severity_counts.items())),
                "findings_by_confidence": dict(sorted(confidence_counts.items())),
            },
        }
