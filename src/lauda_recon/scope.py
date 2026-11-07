"""Scope controls and conservative DNS helpers.

These helpers prevent tool output from becoming an implicit authorization
boundary. Every hostname is normalized and checked before an active module can
use it.
"""

from __future__ import annotations

import secrets
import socket
import string
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable
from urllib.parse import urlparse


_LABEL_CHARS = set(string.ascii_lowercase + string.digits + "-")


def normalize_hostname(value: str) -> str:
    """Return a lowercase FQDN or raise ``ValueError`` for unsafe input."""
    value = value.strip().lower().rstrip(".")
    if "://" in value:
        value = urlparse(value).hostname or ""
    if not value or len(value) > 253 or "." not in value:
        raise ValueError("a fully qualified domain name is required")
    labels = value.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise ValueError("hostname contains an invalid label")
    if any(label[0] == "-" or label[-1] == "-" or not set(label) <= _LABEL_CHARS for label in labels):
        raise ValueError("hostname contains unsupported characters")
    return value


@dataclass(frozen=True, slots=True)
class Scope:
    root_domain: str
    additional_patterns: tuple[str, ...] = ()
    excluded_patterns: tuple[str, ...] = ()

    @classmethod
    def build(
        cls,
        root_domain: str,
        patterns: Iterable[str] = (),
        exclusions: Iterable[str] = (),
    ) -> "Scope":
        root = normalize_hostname(root_domain)
        def normalize_patterns(values: Iterable[str]) -> tuple[str, ...]:
            normalized: list[str] = []
            for raw in values:
                value = raw.strip().lower().rstrip(".")
                if not value or value.startswith("#"):
                    continue
                prefix = "*." if value.startswith("*.") else ""
                normalized.append(prefix + normalize_hostname(value.removeprefix("*.")))
            return tuple(normalized)

        return cls(root, normalize_patterns(patterns), normalize_patterns(exclusions))

    @staticmethod
    def _matches(host: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            return host.endswith("." + pattern[2:])
        return host == pattern

    def allows(self, hostname: str) -> bool:
        try:
            host = normalize_hostname(hostname)
        except ValueError:
            return False
        if any(self._matches(host, pattern) for pattern in self.excluded_patterns):
            return False
        if host == self.root_domain or host.endswith("." + self.root_domain):
            return True
        return any(self._matches(host, pattern) for pattern in self.additional_patterns)


@lru_cache(maxsize=8192)
def resolve_addresses(hostname: str) -> tuple[str, ...]:
    """Resolve A/AAAA records through the operating-system resolver.

    Failed answers are intentionally represented by an empty tuple, not a
    positive inference about the hostname's existence.
    """
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return ()
    return tuple(sorted({record[4][0] for record in records}))


def wildcard_addresses(scope: Scope, probes: int = 3) -> tuple[str, ...]:
    """Return only addresses shared by all random labels under the root.

    Requiring intersection across multiple random labels avoids treating a
    transient DNS answer as a wildcard configuration.
    """
    if probes < 2:
        raise ValueError("wildcard detection needs at least two random probes")
    answers: list[set[str]] = []
    for _ in range(probes):
        label = "lauda-" + secrets.token_hex(10)
        resolved = set(resolve_addresses(f"{label}.{scope.root_domain}"))
        if not resolved:
            return ()
        answers.append(resolved)
    return tuple(sorted(set.intersection(*answers)))


def is_probable_wildcard(hostname: str, wildcard_ips: Iterable[str]) -> bool:
    wildcard = set(wildcard_ips)
    return bool(wildcard and wildcard.intersection(resolve_addresses(hostname)))
