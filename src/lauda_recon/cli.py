"""Command-line interface for the authorized Lauda Recon workflow."""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .reporting import finish_report, report_to_text, write_report


TOOL_NAMES = ("subfinder", "amass", "puredns", "httpx", "katana", "gau", "trufflehog")
_COLOURS = {
    "INFO": "\033[36m",
    "SUCCESS": "\033[32m",
    "CRITICAL": "\033[31m",
    "VULNERABLE": "\033[35m",
}
_RESET = "\033[0m"


@dataclass(frozen=True, slots=True)
class RunOptions:
    """Validated options passed from CLI to the orchestration layer."""

    domain: str
    authorized: bool
    active: bool | None
    workers: int | None
    config_path: Path | None
    scope_file: Path | None
    output_path: Path | None
    json_path: Path | None
    dry_run: bool | None


class StatusFormatter(logging.Formatter):
    """Compact console logging with optional ANSI colour."""

    def __init__(self, *, use_colour: bool) -> None:
        super().__init__("%(message)s")
        self.use_colour = use_colour

    def format(self, record: logging.LogRecord) -> str:
        label = getattr(record, "status", record.levelname).upper()
        message = super().format(record)
        prefix = f"[{label}]"
        if self.use_colour and label in _COLOURS:
            prefix = f"{_COLOURS[label]}{prefix}{_RESET}"
        return f"{prefix} {message}"


class StatusLogger:
    """Small status façade shared by CLI and the future orchestration layer."""

    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    def emit(self, status: str, message: str) -> None:
        value = str(status).upper()
        level = logging.ERROR if value in {"CRITICAL", "VULNERABLE"} else logging.INFO
        self.logger.log(level, message, extra={"status": value})

    def info(self, message: str) -> None:
        self.emit("INFO", message)

    def success(self, message: str) -> None:
        self.emit("SUCCESS", message)

    def critical(self, message: str) -> None:
        self.emit("CRITICAL", message)

    def vulnerable(self, message: str) -> None:
        self.emit("VULNERABLE", message)


def configure_logger(*, use_colour: bool | None = None) -> logging.Logger:
    logger = logging.getLogger("lauda_recon")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(StatusFormatter(use_colour=sys.stderr.isatty() if use_colour is None else use_colour))
    logger.addHandler(handler)
    return logger


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lauda-recon",
        description="Scope-aware recon orchestration for targets you are authorized to assess.",
    )
    parser.add_argument("-d", "--domain", required=True, help="Approved root domain, for example example.com")
    parser.add_argument("--authorized", action="store_true", help="Confirm you have authorization for this target")
    parser.add_argument("-o", "--output", type=Path, help="Write a human-readable text report")
    parser.add_argument("-oJ", "--json", dest="json_output", type=Path, help="Write a structured JSON report")
    parser.add_argument("--scope-file", type=Path, help="Additional explicitly approved hostname patterns")
    parser.add_argument("--config", type=Path, help="YAML module configuration")
    parser.add_argument("--active", action="store_true", default=None, help="Enable bounded active DNS, HTTP, and content verification")
    parser.add_argument("--workers", type=int, default=None, help="Concurrent tool/process limit (1-32; config/default: 8)")
    parser.add_argument("--dry-run", action="store_true", default=None, help="Validate configuration and show the planned workflow without network activity")
    parser.add_argument("--check-tools", action="store_true", help="Show availability of supported external binaries and exit")
    parser.add_argument("--no-colour", action="store_true", help="Disable ANSI status colours")
    return parser


def check_tools() -> dict[str, str]:
    """Return a deterministic binary availability map without executing tools."""

    return {name: (shutil.which(name) or "not found") for name in TOOL_NAMES}


def _validate_domain(value: str) -> str:
    normalized = value.strip().lower().rstrip(".")
    labels = normalized.split(".")
    valid_label = lambda label: bool(label) and len(label) <= 63 and label[0].isalnum() and label[-1].isalnum() and all(ch.isalnum() or ch == "-" for ch in label)
    if len(normalized) > 253 or len(labels) < 2 or not all(valid_label(label) for label in labels):
        raise argparse.ArgumentTypeError("domain must be a valid root hostname, such as example.com")
    return normalized


def options_from_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> RunOptions:
    if not args.authorized and not args.check_tools:
        parser.error("--authorized is required. Use only targets you are permitted to assess.")
    if args.workers is not None and not 1 <= args.workers <= 32:
        parser.error("--workers must be between 1 and 32")
    domain = _validate_domain(args.domain)
    return RunOptions(
        domain=domain,
        authorized=args.authorized,
        active=args.active,
        workers=args.workers,
        config_path=args.config,
        scope_file=args.scope_file,
        output_path=args.output,
        json_path=args.json_output,
        dry_run=args.dry_run,
    )


def _run_scan(options: RunOptions) -> Any:
    """Load and call the core scan function only for a real scan."""

    try:
        from .orchestrator import run_scan
    except ImportError as exc:  # pragma: no cover - only useful while developing a module
        raise RuntimeError("The orchestration module is not installed or could not be imported.") from exc
    return run_scan(options)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logger = configure_logger(use_colour=False if args.no_colour else None)
    status = StatusLogger(logger)
    options = options_from_args(args, parser)

    if args.check_tools:
        for name, location in check_tools().items():
            status.success(f"{name}: {location}") if location != "not found" else status.info(f"{name}: not found (optional)")
        return 0

    status.info(f"Authorized scope acknowledged for {options.domain}.")
    try:
        report = _run_scan(options)
    except Exception as exc:  # errors are reported cleanly; detailed traces are not exposed by default
        status.critical(f"Run failed: {exc}")
        return 2

    finish_report(report)
    write_report(report, text_path=options.output_path, json_path=options.json_path)
    if options.output_path:
        status.success(f"Text report saved to {options.output_path.resolve()}")
    if options.json_path:
        status.success(f"JSON report saved to {options.json_path.resolve()}")
    if not options.output_path and not options.json_path:
        print(report_to_text(report), end="")
    findings = getattr(report, "findings", [])
    status.success(f"Completed with {len(findings)} evidence-backed observation(s).")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
