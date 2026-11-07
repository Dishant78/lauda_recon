"""Fail-closed configuration for the Lauda Recon orchestration pipeline."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit


DEFAULT_BINARIES = {
    "subfinder": "subfinder",
    "amass": "amass",
    "puredns": "puredns",
    "httpx": "httpx",
    "katana": "katana",
    "gau": "gau",
    "trufflehog": "trufflehog",
}
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class ConfigError(ValueError):
    """Raised before a malformed or unsafe run can start."""


@dataclass(frozen=True)
class ScanConfig:
    """Normalized runtime settings.

    ``github_token_env`` is an environment-variable *name*, never a token
    value. A single token is used only with documented provider limits; token
    rotation and credential validation are intentionally unsupported.
    """

    domain: str = ""
    authorized: bool = False
    active: bool = False
    output_text: Path | None = None
    output_json: Path | None = None
    workers: int = 8
    timeout: float = 12.0
    tool_timeout: int = 180
    rate_limit_per_second: int = 4
    ports: tuple[int, ...] = (80, 443, 8080, 8443)
    extra_scope: tuple[str, ...] = ()
    exclude_scope: tuple[str, ...] = ()
    resolvers_file: Path | None = None
    paths_file: Path | None = None
    github_token_env: str | None = "GITHUB_TOKEN"
    github_repositories: tuple[str, ...] = ()
    enabled_tools: tuple[str, ...] = tuple(DEFAULT_BINARIES)
    tool_binaries: Mapping[str, str] = field(default_factory=dict)
    verify_takeover_fingerprints: bool = True
    validate_exposed_file_structure: bool = True
    dry_run: bool = False

    def validate(self) -> "ScanConfig":
        if not _valid_hostname(self.domain):
            raise ConfigError("domain must be a valid root DNS hostname, such as example.com")
        if self.authorized is not True:
            raise ConfigError("--authorized is required for an assessment run")
        if not isinstance(self.active, bool) or not isinstance(self.dry_run, bool):
            raise ConfigError("active and dry_run must be true or false")
        if not isinstance(self.workers, int) or isinstance(self.workers, bool) or not 1 <= self.workers <= 32:
            raise ConfigError("workers must be an integer between 1 and 32")
        if not isinstance(self.timeout, (int, float)) or isinstance(self.timeout, bool) or self.timeout <= 0:
            raise ConfigError("timeout must be a positive number")
        if not isinstance(self.tool_timeout, int) or isinstance(self.tool_timeout, bool) or self.tool_timeout < 1:
            raise ConfigError("tool_timeout must be a positive integer")
        if not isinstance(self.rate_limit_per_second, int) or isinstance(self.rate_limit_per_second, bool) or self.rate_limit_per_second < 1:
            raise ConfigError("rate_limit_per_second must be a positive integer")
        if not self.ports or any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in self.ports):
            raise ConfigError("ports must be a non-empty list of valid TCP ports")
        if self.output_text is not None and self.output_json is not None and self.output_text.resolve() == self.output_json.resolve():
            raise ConfigError("output_text and output_json must be different files")
        if self.github_token_env is not None and not _ENV_NAME.fullmatch(self.github_token_env):
            raise ConfigError("github_token_env must name an environment variable, not contain a token")
        if any(not item.strip() or len(item) > 2048 for item in self.github_repositories):
            raise ConfigError("github_repositories must contain non-empty repository references")
        for repository in self.github_repositories:
            parsed = urlsplit(repository)
            if parsed.scheme and "@" in parsed.netloc:
                raise ConfigError("github_repositories must not embed credentials in repository URLs")
        invalid_tools = set(self.enabled_tools).difference(DEFAULT_BINARIES)
        invalid_binaries = set(self.tool_binaries).difference(DEFAULT_BINARIES)
        if invalid_tools or invalid_binaries:
            values = ", ".join(sorted(invalid_tools | invalid_binaries))
            raise ConfigError(f"unsupported tool configuration: {values}")
        if any(not isinstance(path, str) or not path.strip() or "\x00" in path for path in self.tool_binaries.values()):
            raise ConfigError("tool binary paths must be non-empty strings")
        for entry in (*self.extra_scope, *self.exclude_scope):
            candidate = entry.lower().strip().removeprefix("*.").rstrip(".")
            if not _valid_hostname(candidate):
                raise ConfigError(f"invalid scope entry: {entry}")
        if not isinstance(self.verify_takeover_fingerprints, bool) or not isinstance(self.validate_exposed_file_structure, bool):
            raise ConfigError("finding policy controls must be true or false")
        return self


def load_config(path: str | Path | None = None) -> ScanConfig:
    """Load a YAML or JSON file; CLI values are merged separately."""
    if path is None:
        return ScanConfig()
    source = Path(path)
    try:
        if source.suffix.lower() == ".json":
            raw = json.loads(source.read_text(encoding="utf-8"))
        else:
            try:
                import yaml
            except ImportError as exc:
                raise ConfigError("PyYAML is required for YAML configuration; use JSON or install project dependencies") from exc
            with source.open("r", encoding="utf-8") as handle:
                raw = yaml.safe_load(handle) or {}
    except OSError as exc:
        raise ConfigError(f"cannot read config {source}: {exc}") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise ConfigError(f"invalid configuration {source}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ConfigError("configuration root must be a mapping")
    return _from_mapping(raw)


def merge(base: ScanConfig, overrides: Mapping[str, Any] | None = None, /, **kwargs: Any) -> ScanConfig:
    """Apply non-``None`` values while rejecting unrecognized settings."""
    values = dict(overrides or {})
    values.update(kwargs)
    unknown = set(values).difference(ScanConfig.__dataclass_fields__)
    if unknown:
        raise ConfigError(f"unknown scan configuration: {', '.join(sorted(unknown))}")
    updates = {name: value for name, value in values.items() if value is not None}
    for name in ("output_text", "output_json", "resolvers_file", "paths_file"):
        if name in updates:
            updates[name] = _path_or_none(updates[name], name)
    for name in ("extra_scope", "exclude_scope", "github_repositories"):
        if name in updates:
            updates[name] = _strings(updates[name], name)
    if "enabled_tools" in updates:
        updates["enabled_tools"] = _tool_names(updates["enabled_tools"])
    if "ports" in updates:
        updates["ports"] = _ports(updates["ports"])
    if "tool_binaries" in updates:
        updates["tool_binaries"] = _binary_mapping(updates["tool_binaries"])
    if "domain" in updates and isinstance(updates["domain"], str):
        updates["domain"] = updates["domain"].lower().strip().rstrip(".")
    return replace(base, **updates)


def _from_mapping(raw: Mapping[str, Any]) -> ScanConfig:
    scope = _mapping(raw.get("scope"), "scope")
    network = _mapping(raw.get("network"), "network")
    tools = _mapping(raw.get("tools"), "tools")
    github = _mapping(raw.get("github"), "github")
    policy = _mapping(raw.get("finding_policy"), "finding_policy")
    unknown_tools = set(tools).difference(DEFAULT_BINARIES)
    if unknown_tools:
        raise ConfigError(f"unsupported tool configuration: {', '.join(sorted(unknown_tools))}")
    for name, value in tools.items():
        if not isinstance(value, Mapping):
            raise ConfigError(f"tools.{name} must be a mapping")
        if "enabled" in value and not isinstance(value["enabled"], bool):
            raise ConfigError(f"tools.{name}.enabled must be true or false")
        if "binary" in value and not isinstance(value["binary"], str):
            raise ConfigError(f"tools.{name}.binary must be a string")
    if raw.get("enabled_tools") is not None:
        enabled = _tool_names(raw.get("enabled_tools"))
    elif tools:
        enabled = tuple(name for name, value in tools.items() if isinstance(value, Mapping) and value.get("enabled", False))
    else:
        enabled = tuple(DEFAULT_BINARIES)
    binary_overrides = {
        name: value["binary"]
        for name, value in tools.items()
        if isinstance(value, Mapping) and value.get("binary") is not None
    }
    if policy.get("store_secret_values", False) or policy.get("verify_secret_credentials", False):
        raise ConfigError("storing or validating discovered credentials is not supported")
    return ScanConfig(
        domain=_string(raw.get("domain", ""), "domain").lower().strip().rstrip("."),
        authorized=_boolean(raw.get("authorized", False), "authorized"),
        active=_boolean(raw.get("active", False), "active"),
        output_text=_path_or_none(raw.get("output_text"), "output_text"),
        output_json=_path_or_none(raw.get("output_json"), "output_json"),
        workers=_positive_int(raw.get("workers", network.get("max_workers")), "workers", 8),
        timeout=_positive_number(raw.get("timeout", network.get("timeout_seconds")), "timeout", 12.0),
        tool_timeout=_positive_int(raw.get("tool_timeout"), "tool_timeout", 180),
        rate_limit_per_second=_positive_int(raw.get("rate_limit_per_second", network.get("rate_limit_per_second")), "rate_limit_per_second", 4),
        ports=_ports(network.get("ports", raw.get("ports", [80, 443, 8080, 8443]))),
        extra_scope=_strings(raw.get("extra_scope", scope.get("include", ())), "extra_scope"),
        exclude_scope=_strings(raw.get("exclude_scope", scope.get("exclude", ())), "exclude_scope"),
        resolvers_file=_path_or_none(raw.get("resolvers_file"), "resolvers_file"),
        paths_file=_path_or_none(raw.get("paths_file"), "paths_file"),
        github_token_env=_optional_string(raw.get("github_token_env", github.get("token_env", "GITHUB_TOKEN")), "github_token_env"),
        github_repositories=_strings(raw.get("github_repositories", github.get("repositories", ())), "github_repositories"),
        enabled_tools=enabled,
        tool_binaries=_binary_mapping(binary_overrides),
        verify_takeover_fingerprints=_boolean(policy.get("verify_takeover_fingerprints", True), "finding_policy.verify_takeover_fingerprints"),
        validate_exposed_file_structure=_boolean(policy.get("validate_exposed_file_structure", True), "finding_policy.validate_exposed_file_structure"),
        dry_run=_boolean(raw.get("dry_run", False), "dry_run"),
    )


def _valid_hostname(value: str) -> bool:
    return bool(value) and len(value) <= 253 and "." in value and not value.replace(".", "").isdigit() and all(_HOST_LABEL.fullmatch(label) is not None for label in value.split("."))


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigError(f"{name} must be a mapping")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a string")
    return value


def _optional_string(value: Any, name: str) -> str | None:
    if value is None:
        return None
    return _string(value, name)


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be true or false")
    return value


def _path_or_none(value: Any, name: str) -> Path | None:
    if value in (None, ""):
        return None
    if not isinstance(value, (str, Path)):
        raise ConfigError(f"{name} must be a file path")
    return Path(value)


def _strings(value: Any, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{name} must be a list of strings")
    return tuple(dict.fromkeys(item.strip() for item in value if item.strip()))


def _tool_names(value: Any) -> tuple[str, ...]:
    return tuple(item.lower() for item in _strings(value, "enabled_tools"))


def _ports(value: Any) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ConfigError("ports must be a non-empty list of TCP ports")
    if any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in value):
        raise ConfigError("ports must contain valid TCP port numbers")
    return tuple(dict.fromkeys(value))


def _binary_mapping(value: Any) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise ConfigError("tool_binaries must be a mapping")
    result: dict[str, str] = {}
    for name, path in value.items():
        if not isinstance(name, str) or not isinstance(path, str) or not path.strip() or "\x00" in path:
            raise ConfigError("tool_binaries must map tool names to non-empty binary paths")
        result[name.lower()] = path.strip()
    return result


def _positive_int(value: Any, name: str, default: int) -> int:
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ConfigError(f"{name} must be a positive integer")
    return value


def _positive_number(value: Any, name: str, default: float) -> float:
    if value is None:
        return default
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"{name} must be a positive number")
    return float(value)
