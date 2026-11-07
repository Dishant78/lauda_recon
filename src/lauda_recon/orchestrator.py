"""Dependency-aware, concurrent reconnaissance orchestration.

Passive collectors run in parallel. Active DNS, HTTP, crawling, and bounded
content checks run only after explicit authorization and ``--active``. Every
stage records whether it actually ran, so missing tools are never confused
with a negative result.
"""

from __future__ import annotations

import concurrent.futures
import logging
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

from .cli import RunOptions
from .config import ConfigError, ScanConfig, load_config, merge
from .content import context_paths, load_approved_paths
from .endpoints import extract_public_endpoints
from .github import search_code_references, token_from_environment
from .models import Confidence, Evidence, Finding, HttpService, RunReport, Severity, ToolResult
from .mutations import generate_mutations
from .parsing import (
    parse_amass_jsonl,
    parse_httpx_jsonl,
    parse_puredns_lines,
    parse_subfinder_jsonl,
    parse_trufflehog_jsonl,
    parse_url_lines,
)
from .scope import Scope
from .tools import (
    BinaryRunner,
    ToolInvocation,
    amass_invocation,
    gau_invocation,
    httpx_invocation,
    katana_invocation,
    puredns_invocation,
    subfinder_invocation,
    trufflehog_git_invocation,
)
from .verify import (
    build_soft_404_baseline,
    detect_wildcard_dns,
    is_probable_wildcard,
    probe_http,
    resolve_host,
    resembles_soft_404,
    select_wordlist_profiles,
    validate_exposure_structure,
    verify_takeover_signature,
)


MAX_ACTIVE_HOSTS = 500
MAX_CONTENT_SERVICES = 80
MAX_ENDPOINTS = 750


class ReconOrchestrator:
    def __init__(self, options: RunOptions) -> None:
        self.options = options
        self.logger = logging.getLogger("lauda_recon")

    def run(self) -> RunReport:
        config = _runtime_config(self.options)
        scope = Scope.build(config.domain, config.extra_scope, config.exclude_scope)
        report = RunReport(domain=config.domain)
        report.notes.extend(
            [
                "Results are evidence-backed observations, not a guarantee of exploitability or complete coverage.",
                "Potential secret values are never retained or exercised; report locations are redacted leads for approved manual triage.",
                "Redirects are not followed, preventing scoped HTTP checks from silently leaving the approved hostname set.",
            ]
        )
        runner = BinaryRunner(config.tool_binaries)
        for name in config.enabled_tools:
            report.tools[name] = ToolResult(name=name, available=runner.available(name), message="available" if runner.available(name) else "optional binary not found")

        report.asset(config.domain, "input")
        if config.dry_run:
            report.notes.extend(
                [
                    "Dry run: configuration and scope were validated; no network requests or subprocesses were started.",
                    f"Active verification would be {'enabled' if config.active else 'disabled'}.",
                ]
            )
            return report
        self._passive_collection(config, scope, report, runner)
        self._github_references(config, report)
        self._history_scan(config, report, runner)

        if not config.active:
            report.notes.append("Active DNS, HTTP, crawling, and content checks were skipped; rerun with --active for approved active verification.")
            return report

        self._active_discovery(config, scope, report, runner)
        return report

    def _passive_collection(self, config: ScanConfig, scope: Scope, report: RunReport, runner: BinaryRunner) -> None:
        invocations: list[ToolInvocation] = []
        if "subfinder" in config.enabled_tools:
            invocations.append(subfinder_invocation(config.domain, timeout_seconds=config.tool_timeout))
        if "amass" in config.enabled_tools:
            invocations.append(amass_invocation(config.domain, timeout_seconds=max(config.tool_timeout, 360)))
        if "gau" in config.enabled_tools:
            invocations.append(gau_invocation(config.domain, timeout_seconds=config.tool_timeout))
        if not invocations:
            report.notes.append("No passive binary collectors are enabled.")
            return

        self._status("INFO", f"Running {len(invocations)} passive collector(s) concurrently.")
        for result in runner.run_many(invocations, workers=min(config.workers, len(invocations))):
            name = str(result["name"])
            _update_tool(report, result)
            output = str(result.get("stdout", ""))
            if not result.get("succeeded"):
                report.notes.append(_tool_failure_note(name, result))
                continue
            if name == "subfinder":
                records = parse_subfinder_jsonl(output.splitlines())
                self._add_asset_records(records, scope, report)
            elif name == "amass":
                records = parse_amass_jsonl(output.splitlines())
                self._add_asset_records(records, scope, report)
            elif name == "gau":
                self._add_endpoint_records(parse_url_lines(output.splitlines(), source="gau"), scope, report)

    def _github_references(self, config: ScanConfig, report: RunReport) -> None:
        """Collect code location references through one rate-limit-respecting token."""
        token = token_from_environment(config.github_token_env)
        references, notices = search_code_references(config.domain, token=token, timeout=config.timeout)
        report.notes.extend(notices)
        for item in references[:MAX_ENDPOINTS]:
            report.add_finding(
                Finding(
                    category="GitHub code reference",
                    title="Public code search reference requires manual review",
                    asset=config.domain,
                    severity=Severity.LOW,
                    confidence=Confidence.OBSERVED,
                    verification="Official GitHub Code Search returned a repository/path reference; source contents were not retrieved.",
                    evidence=[Evidence("GitHub Code Search", f"{item['repository']} - {item['path']}", item["url"])],
                    tags=["github", "redacted"],
                )
            )

    def _active_discovery(self, config: ScanConfig, scope: Scope, report: RunReport, runner: BinaryRunner) -> None:
        self._status("INFO", "Starting bounded active DNS verification.")
        wildcard_profile = detect_wildcard_dns(scope)
        wildcard_addresses = wildcard_profile.get("wildcard_addresses", [])
        if wildcard_profile.get("detected"):
            report.notes.append(f"Wildcard DNS detected for {config.domain} at {', '.join(map(str, wildcard_addresses))}; matching candidates will be filtered.")

        mutations = generate_mutations(report.assets, scope)
        for host in mutations:
            report.asset(host, "bounded_permutation")
        if mutations:
            report.notes.append(f"Generated {len(mutations)} bounded, in-scope DNS mutation candidate(s) for verification.")
        hosts = sorted(report.assets)
        puredns_resolved = self._run_puredns(config, scope, report, runner, hosts)
        resolutions = _parallel_map(resolve_host, hosts, workers=config.workers)
        viable_hosts: list[str] = []
        for resolution in resolutions:
            host = str(resolution.get("hostname", ""))
            if not host or not scope.allows(host):
                continue
            asset = report.asset(host)
            asset.ips.update(str(value) for value in resolution.get("addresses", []) if value)
            if not resolution.get("resolved") and host not in puredns_resolved:
                continue
            effective_resolution = dict(resolution)
            if not effective_resolution.get("addresses") and asset.ips:
                effective_resolution["addresses"] = list(asset.ips)
            if is_probable_wildcard(host, effective_resolution, wildcard_profile):
                report.notes.append(f"Filtered probable wildcard DNS candidate: {host}")
                continue
            viable_hosts.append(host)
        viable_hosts = viable_hosts[:MAX_ACTIVE_HOSTS]
        if len(report.assets) > len(viable_hosts):
            report.notes.append(f"Active host work is capped at {MAX_ACTIVE_HOSTS} resolved, non-wildcard hosts per run.")

        services = self._live_services(config, scope, report, runner, viable_hosts)
        if not services:
            report.notes.append("No live HTTP services were observed by the configured active probes.")
            return

        if config.verify_takeover_fingerprints:
            self._verify_takeovers(config, scope, report, services)
        discovered_endpoints = self._crawl_and_archives(config, scope, report, runner, services)
        self._content_checks(config, scope, report, services, discovered_endpoints)

    def _run_puredns(self, config: ScanConfig, scope: Scope, report: RunReport, runner: BinaryRunner, hosts: list[str]) -> set[str]:
        if "puredns" not in config.enabled_tools:
            return set()
        if not config.resolvers_file or not config.resolvers_file.is_file():
            report.notes.append("PureDNS skipped: configure resolvers_file with trusted public resolvers for optional resolver-backed validation.")
            return set()
        if not runner.available("puredns"):
            return set()
        resolved: set[str] = set()
        with tempfile.TemporaryDirectory(prefix="lauda-puredns-") as directory:
            root = Path(directory)
            candidates = root / "hosts.txt"
            output = root / "resolved.txt"
            candidates.write_text("\n".join(hosts) + "\n", encoding="utf-8")
            result = runner.run(puredns_invocation(candidates, config.resolvers_file, output, timeout_seconds=config.tool_timeout))
            _update_tool(report, result)
            if not result.get("succeeded"):
                report.notes.append(_tool_failure_note("puredns", result))
                return resolved
            if not output.is_file():
                report.notes.append("PureDNS completed without its expected output file.")
                return resolved
            for record in parse_puredns_lines(output.read_text(encoding="utf-8", errors="replace").splitlines()):
                host = str(record["hostname"])
                if not scope.allows(host):
                    continue
                resolved.add(host)
                asset = report.asset(host, "puredns")
                if record["record_type"] == "CNAME":
                    asset.cname = str(record["value"])
                else:
                    asset.ips.add(str(record["value"]))
        return resolved

    def _live_services(self, config: ScanConfig, scope: Scope, report: RunReport, runner: BinaryRunner, hosts: list[str]) -> list[dict[str, Any]]:
        services: list[dict[str, Any]] | None = None
        if "httpx" in config.enabled_tools and runner.available("httpx"):
            with tempfile.TemporaryDirectory(prefix="lauda-httpx-") as directory:
                source = Path(directory) / "hosts.txt"
                source.write_text("\n".join(hosts) + "\n", encoding="utf-8")
                result = runner.run(
                    httpx_invocation(
                        source,
                        ports=config.ports,
                        rate_limit=config.rate_limit_per_second,
                        timeout_seconds=config.tool_timeout,
                    )
                )
                _update_tool(report, result)
                if result.get("succeeded"):
                    services = [item for item in parse_httpx_jsonl(str(result.get("stdout", "")).splitlines()) if scope.allows(str(item["hostname"]))]
                else:
                    report.notes.append(_tool_failure_note("httpx", result))
        if services is None:
            report.notes.append("HTTPX was unavailable or failed; using conservative built-in HTTP probes for active hosts.")
            urls = _fallback_urls(hosts, config.ports)
            services = [item for item in _parallel_map(lambda url: probe_http(url, scope=scope, timeout=config.timeout), urls, workers=config.workers) if item]

        deduplicated: dict[str, dict[str, Any]] = {}
        for service in services:
            url = str(service.get("url", ""))
            host = str(service.get("hostname", ""))
            if not url or not host or not scope.allows(host):
                continue
            deduplicated[url] = service
        normalized = list(deduplicated.values())
        for service in normalized:
            asset = report.asset(str(service["hostname"]), str(service.get("source", "httpx")))
            asset.live_services.append(
                HttpService(
                    url=str(service["url"]),
                    status_code=_as_int(service.get("status_code")),
                    title=_text_or_none(service.get("title")),
                    content_length=_as_int(service.get("content_length")),
                    technologies=[str(value) for value in service.get("technologies", [])],
                    webserver=_text_or_none(service.get("webserver")),
                    source=str(service.get("source", "httpx")),
                )
            )
            report.add_finding(
                Finding(
                    category="Live web service",
                    title="HTTP service observed",
                    asset=str(service["url"]),
                    severity=Severity.INFO,
                    confidence=Confidence.VERIFIED,
                    verification=f"Observed HTTP {_as_int(service.get('status_code')) or 'response'} without following redirects.",
                    evidence=[Evidence(str(service.get("source", "httpx")), _service_evidence(service), str(service["url"]))],
                    tags=["http", "live"],
                )
            )
        self._status("SUCCESS", f"Observed {len(normalized)} live HTTP service(s).")
        return normalized

    def _verify_takeovers(self, config: ScanConfig, scope: Scope, report: RunReport, services: Iterable[dict[str, Any]]) -> None:
        # HTTPX does not retain response bodies. Re-probe only CNAME-bearing
        # services to correlate its public provider signature without claiming
        # or modifying a provider resource.
        candidates = [service for service in services if report.assets.get(str(service["hostname"]), None) and report.assets[str(service["hostname"])].cname]
        for response in _parallel_map(lambda service: probe_http(str(service["url"]), scope=scope, timeout=config.timeout), candidates, workers=config.workers):
            if not response:
                continue
            asset = report.assets.get(str(response["hostname"]))
            if not asset or not asset.cname:
                continue
            result = verify_takeover_signature(asset.hostname, [asset.cname], response)
            if result:
                report.add_finding(
                    Finding(
                        category="Subdomain takeover candidate",
                        title=f"{result['provider']} unclaimed-resource signature",
                        asset=asset.hostname,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.NEEDS_REVIEW,
                        verification=result["verification"],
                        evidence=[Evidence("active HTTP + DNS", f"CNAME {result['cname_target']}; signature {result['signature']}", str(response["url"]))],
                        tags=["takeover", "manual-review"],
                    )
                )

    def _crawl_and_archives(self, config: ScanConfig, scope: Scope, report: RunReport, runner: BinaryRunner, services: list[dict[str, Any]]) -> list[str]:
        existing = [finding.asset for finding in report.findings if finding.category == "Archived endpoint"]
        urls = [str(item["url"]) for item in services][:MAX_CONTENT_SERVICES]
        endpoints: list[str] = list(existing)
        public_records = _parallel_map(
            lambda url: extract_public_endpoints(url, scope=scope, timeout=config.timeout),
            urls,
            workers=config.workers,
        )
        for records in public_records:
            endpoints.extend(self._add_endpoint_records(records, scope, report))
        if "katana" not in config.enabled_tools or not runner.available("katana"):
            report.notes.append("Katana unavailable; JavaScript and live crawl endpoint extraction were skipped.")
            return endpoints[:MAX_ENDPOINTS]
        with tempfile.TemporaryDirectory(prefix="lauda-katana-") as directory:
            source = Path(directory) / "urls.txt"
            source.write_text("\n".join(urls) + "\n", encoding="utf-8")
            result = runner.run(katana_invocation(source, timeout_seconds=config.tool_timeout))
            _update_tool(report, result)
            if not result.get("succeeded"):
                report.notes.append(_tool_failure_note("katana", result))
                return endpoints[:MAX_ENDPOINTS]
            records = parse_url_lines(str(result.get("stdout", "")).splitlines(), source="katana")
            endpoints.extend(self._add_endpoint_records(records, scope, report))
        return list(dict.fromkeys(endpoints))[:MAX_ENDPOINTS]

    def _content_checks(self, config: ScanConfig, scope: Scope, report: RunReport, services: list[dict[str, Any]], endpoints: list[str]) -> None:
        try:
            additional_paths = load_approved_paths(config.paths_file)
        except OSError as exc:
            report.notes.append(f"Custom path list was not read: {exc}")
            additional_paths = []
        content_services = services[:MAX_CONTENT_SERVICES]
        baselines = _parallel_map(lambda service: build_soft_404_baseline(str(service["url"]), scope=scope, timeout=config.timeout), content_services, workers=config.workers)
        jobs: list[tuple[str, str, dict[str, object] | None]] = []
        for service, baseline in zip(content_services, baselines):
            profiles = select_wordlist_profiles(service.get("technologies", []))
            base_url = str(service["url"]).rstrip("/")
            for path in context_paths(profiles, additional=additional_paths):
                jobs.append((base_url + path, path, baseline))
        # Katana/GAU URL discoveries are already evidence-based endpoints, not
        # blind paths. Re-probe a bounded subset to avoid claiming stale URLs.
        for endpoint in endpoints[:150]:
            jobs.append((endpoint, urlsplit(endpoint).path, None))

        def check(job: tuple[str, str, dict[str, object] | None]) -> tuple[str, str, dict[str, object] | None, dict[str, object] | None]:
            url, path, baseline = job
            return url, path, baseline, probe_http(url, scope=scope, timeout=config.timeout)

        for url, path, baseline, response in _parallel_map(check, jobs[:3000], workers=config.workers):
            if not response or resembles_soft_404(response, baseline):
                continue
            status = _as_int(response.get("status_code")) or 0
            if not 200 <= status < 400:
                continue
            exposure = validate_exposure_structure(url, response) if config.validate_exposed_file_structure else None
            if exposure:
                confirmation = probe_http(url, scope=scope, timeout=config.timeout)
                confirmed_exposure = (
                    validate_exposure_structure(url, confirmation)
                    if confirmation and config.validate_exposed_file_structure
                    else None
                )
                if not confirmed_exposure:
                    # A single anomalous response is intentionally not emitted
                    # as an exposure finding.
                    continue
                report.add_finding(
                    Finding(
                        category="Potential exposed sensitive file",
                        title=f"Structurally valid {exposure['file_kind']} response",
                        asset=str(exposure["url"]),
                        severity=Severity.HIGH,
                        confidence=Confidence.VERIFIED,
                        verification="Two independent HTTP responses passed structural signature checks; no file contents or credential values were retained.",
                        evidence=[Evidence("active HTTP", f"HTTP {confirmed_exposure['status_code']}; structural markers: {', '.join(confirmed_exposure['structural_markers'])}", str(confirmed_exposure["url"]))],
                        tags=["exposure", "redacted"],
                    )
                )
                continue
            report.add_finding(
                Finding(
                    category="Interesting endpoint",
                    title="Non-soft-404 endpoint observed",
                    asset=str(response["url"]),
                    severity=Severity.INFO,
                    confidence=Confidence.VERIFIED,
                    verification="Status/content fingerprint differs from two randomized not-found baselines.",
                    evidence=[Evidence("active HTTP", _service_evidence(response), str(response["url"]))],
                    tags=["content", "soft-404-filtered"],
                )
            )

    def _history_scan(self, config: ScanConfig, report: RunReport, runner: BinaryRunner) -> None:
        if "trufflehog" not in config.enabled_tools:
            return
        if not config.github_repositories:
            report.notes.append("Commit-history secret indicator scan skipped: explicitly configure github_repositories for repositories you are authorized to assess.")
            return
        invocations = [
            replace(trufflehog_git_invocation(repository, timeout_seconds=config.tool_timeout), name=f"trufflehog-history-{index}")
            for index, repository in enumerate(config.github_repositories, start=1)
        ]
        for result in runner.run_many(invocations, workers=min(config.workers, len(invocations))):
            _update_tool(report, result, key="trufflehog")
            if not result.get("succeeded"):
                report.notes.append(_tool_failure_note(str(result["name"]), result))
                continue
            for indicator in parse_trufflehog_jsonl(str(result.get("stdout", "")).splitlines()):
                report.add_finding(
                    Finding(
                        category="Potential secret indicator",
                        title=f"{indicator['detector']} indicator in authorized repository history",
                        asset=config.domain,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.NEEDS_REVIEW,
                        verification="Detector output was redacted and provider validation was not attempted.",
                        evidence=[Evidence("TruffleHog git history", f"{indicator['fingerprint']}; location reference: {indicator['source']}")],
                        tags=["github", "history", "redacted", "manual-review"],
                    )
                )

    def _add_asset_records(self, records: Iterable[dict[str, Any]], scope: Scope, report: RunReport) -> None:
        for record in records:
            host = str(record.get("hostname", ""))
            if not scope.allows(host):
                continue
            asset = report.asset(host, str(record.get("source", "collector")))
            for cname in record.get("cname_targets", []):
                asset.cname = str(cname)

    def _add_endpoint_records(self, records: Iterable[dict[str, Any]], scope: Scope, report: RunReport) -> list[str]:
        endpoints: list[str] = []
        for record in records:
            url = str(record.get("url", ""))
            host = urlsplit(url).hostname or ""
            if not url or not scope.allows(host):
                continue
            report.asset(host, str(record.get("source", "endpoint")))
            endpoints.append(url)
            report.add_finding(
                Finding(
                    category="Archived endpoint" if record.get("source") == "gau" else "Discovered endpoint",
                    title="Endpoint reference observed",
                    asset=url,
                    severity=Severity.INFO,
                    confidence=Confidence.OBSERVED,
                    verification="Collected from a passive archive or scoped crawler; not yet treated as live.",
                    evidence=[Evidence(str(record.get("source", "collector")), "Normalized URL reference", url)],
                    tags=["endpoint"],
                )
            )
        return endpoints

    def _status(self, level: str, message: str) -> None:
        self.logger.info(message, extra={"status": level})


def run_scan(options: RunOptions) -> RunReport:
    """CLI-facing entry point."""
    return ReconOrchestrator(options).run()


def _runtime_config(options: RunOptions) -> ScanConfig:
    base = load_config(options.config_path)
    file_scope: list[str] = []
    if options.scope_file:
        try:
            file_scope = options.scope_file.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ConfigError(f"cannot read scope file: {exc}") from exc
    config = merge(
        base,
        domain=options.domain,
        authorized=options.authorized,
        active=options.active,
        workers=options.workers,
        extra_scope=tuple(base.extra_scope) + tuple(file_scope),
        dry_run=options.dry_run,
    )
    return config.validate()


def _parallel_map(function: Callable[[Any], Any], values: Iterable[Any], *, workers: int) -> list[Any]:
    items = list(values)
    if not items:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max(1, workers), len(items))) as pool:
        return list(pool.map(function, items))


def _fallback_urls(hosts: Iterable[str], ports: Iterable[int]) -> list[str]:
    urls: list[str] = []
    for host in hosts:
        for port in ports:
            scheme = "https" if port in {443, 8443} else "http"
            suffix = "" if (scheme, port) in (("https", 443), ("http", 80)) else f":{port}"
            urls.append(f"{scheme}://{host}{suffix}/")
    return urls


def _update_tool(report: RunReport, result: dict[str, object], *, key: str | None = None) -> None:
    name = key or str(result["name"])
    return_code = int(result.get("return_code", -127))
    report.tools[name] = ToolResult(
        name=name,
        available=return_code != -127,
        ran=return_code != -127,
        records=0,
        message="completed" if result.get("succeeded") else _tool_failure_note(name, result),
        duration_seconds=float(result.get("duration_seconds", 0.0)),
    )


def _tool_failure_note(name: str, result: dict[str, object]) -> str:
    if result.get("timed_out"):
        return f"{name} timed out; no negative conclusion was inferred."
    # Upstream tools can include response snippets in diagnostics. Keep the
    # report redaction-first by never copying untrusted stderr into it.
    had_diagnostic = bool(str(result.get("stderr", "")).strip())
    suffix = "; diagnostic output suppressed" if had_diagnostic else ""
    return f"{name} did not complete successfully (exit {result.get('return_code')}){suffix}."


def _as_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _text_or_none(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _service_evidence(service: dict[str, Any]) -> str:
    status = _as_int(service.get("status_code"))
    title = _text_or_none(service.get("title"))
    tech = ", ".join(map(str, service.get("technologies", [])))
    values = [f"HTTP {status}" if status else "HTTP response"]
    if title:
        values.append(f"title: {title}")
    if tech:
        values.append(f"tech: {tech}")
    return "; ".join(values)
