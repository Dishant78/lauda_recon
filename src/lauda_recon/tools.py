"""Safe adapters for optional reconnaissance binaries.

Commands are argv tuples passed with ``shell=False``.  Output is bounded and
callers should only retain parsed, redacted records in final reports.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import time
from typing import Iterable, Mapping, Sequence


@dataclass(frozen=True, slots=True)
class ToolInvocation:
    name: str
    argv: tuple[str, ...]
    timeout_seconds: float = 300.0
    cwd: Path | None = None

    def __post_init__(self) -> None:
        if not self.argv or self.timeout_seconds <= 0:
            raise ValueError("tool invocations need an executable and positive timeout")


def find_binary(name: str, configured_path: str | Path | None = None) -> str | None:
    if configured_path:
        candidate = Path(configured_path).expanduser()
        return str(candidate.resolve()) if candidate.is_file() else None
    return shutil.which(name)


class BinaryRunner:
    """Bounded, shell-free runner with concurrent execution for independent tools."""

    def __init__(self, binary_paths: Mapping[str, str | Path] | None = None, max_output_bytes: int = 12_000_000) -> None:
        self.binary_paths = dict(binary_paths or {})
        self.max_output_bytes = max_output_bytes

    def available(self, tool: str) -> bool:
        return find_binary(tool, self.binary_paths.get(tool)) is not None

    def run(self, invocation: ToolInvocation) -> dict[str, object]:
        binary = find_binary(invocation.argv[0], self.binary_paths.get(invocation.argv[0]))
        if not binary:
            return _result(invocation, -127, "", f"optional binary not found: {invocation.argv[0]}", 0.0)
        argv = (binary, *invocation.argv[1:])
        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                cwd=str(invocation.cwd) if invocation.cwd else None,
                check=False,
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=invocation.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            return _result(invocation, -1, _limit(exc.stdout, self.max_output_bytes), _limit(exc.stderr, self.max_output_bytes), time.monotonic() - started, timed_out=True)
        except OSError as exc:
            # Keep a bounded diagnostic for internal control flow; report
            # rendering deliberately suppresses raw tool diagnostics.
            return _result(invocation, -126, "", _limit(str(exc), self.max_output_bytes), time.monotonic() - started)
        return _result(invocation, completed.returncode, _limit(completed.stdout, self.max_output_bytes), _limit(completed.stderr, self.max_output_bytes), time.monotonic() - started)

    def run_many(self, invocations: Iterable[ToolInvocation], *, workers: int = 4) -> list[dict[str, object]]:
        jobs = list(invocations)
        if not 1 <= workers <= 32:
            raise ValueError("workers must be between 1 and 32")
        with ThreadPoolExecutor(max_workers=min(workers, len(jobs) or 1)) as pool:
            futures = {pool.submit(self.run, job): job for job in jobs}
            result = [future.result() for future in as_completed(futures)]
        return sorted(result, key=lambda item: str(item["name"]))


def _result(invocation: ToolInvocation, code: int, stdout: str, stderr: str, duration: float, *, timed_out: bool = False) -> dict[str, object]:
    return {"name": invocation.name, "argv": list(invocation.argv), "return_code": code, "stdout": stdout, "stderr": stderr, "duration_seconds": round(duration, 3), "timed_out": timed_out, "succeeded": code == 0 and not timed_out}


def _limit(value: bytes | str | None, maximum: int) -> str:
    if isinstance(value, bytes):
        return value[:maximum].decode("utf-8", "replace")
    return str(value or "")[:maximum]


def subfinder_invocation(domain: str, *, timeout_seconds: float = 180.0) -> ToolInvocation:
    return ToolInvocation("subfinder", ("subfinder", "-d", domain, "-silent", "-json"), timeout_seconds)


def amass_invocation(domain: str, *, timeout_seconds: float = 360.0) -> ToolInvocation:
    return ToolInvocation("amass", ("amass", "enum", "-passive", "-d", domain, "-json", "-"), timeout_seconds)


def puredns_invocation(candidates_file: Path, resolvers_file: Path, output_file: Path, *, timeout_seconds: float = 300.0) -> ToolInvocation:
    return ToolInvocation("puredns", ("puredns", "resolve", str(candidates_file), "-r", str(resolvers_file), "--write", str(output_file)), timeout_seconds)


def httpx_invocation(hosts_file: Path, *, ports: Sequence[int] = (80, 443, 8080, 8443), rate_limit: int = 20, timeout_seconds: float = 300.0) -> ToolInvocation:
    if not ports or any(not 1 <= port <= 65535 for port in ports) or rate_limit < 1:
        raise ValueError("ports and rate_limit must be positive")
    return ToolInvocation("httpx", ("httpx", "-l", str(hosts_file), "-silent", "-json", "-no-color", "-ports", ",".join(map(str, ports)), "-status-code", "-title", "-content-length", "-tech-detect", "-rl", str(rate_limit)), timeout_seconds)


def katana_invocation(urls_file: Path, *, depth: int = 2, timeout_seconds: float = 300.0) -> ToolInvocation:
    if not 0 <= depth <= 5:
        raise ValueError("Katana depth must be between 0 and 5")
    return ToolInvocation("katana", ("katana", "-list", str(urls_file), "-silent", "-jsonl", "-jc", "-depth", str(depth)), timeout_seconds)


def gau_invocation(domain: str, *, timeout_seconds: float = 180.0) -> ToolInvocation:
    return ToolInvocation("gau", ("gau", "--subs", domain), timeout_seconds)


def trufflehog_git_invocation(repository: str, *, timeout_seconds: float = 600.0) -> ToolInvocation:
    """Scan an authorized repository/history without exercising found secrets."""

    return ToolInvocation("trufflehog", ("trufflehog", "git", repository, "--json", "--no-verification"), timeout_seconds)
