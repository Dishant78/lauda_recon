"""Small, bounded DNS permutation set for explicitly approved scopes."""

from __future__ import annotations

from collections.abc import Iterable

from .scope import Scope


PREFIXES = ("api", "app", "auth", "cdn", "dev", "staging", "stage", "test", "beta", "portal", "admin")
ENVIRONMENT_SUFFIXES = ("dev", "staging", "stage", "test", "beta")


def generate_mutations(hostnames: Iterable[str], scope: Scope, *, maximum: int = 300) -> list[str]:
    """Generate predictable, in-scope DNS candidates from discovered labels.

    This is intentionally a compact augmentation to passive discovery, not an
    unbounded guessing engine. Callers must still resolve and wildcard-filter
    each candidate before using it downstream.
    """
    candidates: list[str] = []
    existing = {host.lower().rstrip(".") for host in hostnames if scope.allows(host)}
    proposed = [f"{prefix}.{scope.root_domain}" for prefix in PREFIXES]
    for host in sorted(existing):
        if host == scope.root_domain:
            continue
        relative = host[: -(len(scope.root_domain) + 1)]
        first = relative.split(".")[0]
        for suffix in ENVIRONMENT_SUFFIXES:
            if first:
                proposed.extend((f"{first}-{suffix}.{scope.root_domain}", f"{suffix}-{first}.{scope.root_domain}"))
    for candidate in proposed:
        if candidate not in existing and scope.allows(candidate) and candidate not in candidates:
            candidates.append(candidate)
        if len(candidates) >= maximum:
            return candidates
    return candidates
