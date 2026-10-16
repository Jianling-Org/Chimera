"""Validated policy for handling unknown scalar stack allocation sizes."""

from __future__ import annotations


CONSERVATIVE = "conservative"
ASSUME_SCALAR_INDEPENDENT = "assume-scalar-independent"
UNKNOWN_STACK_SIZE_POLICIES = frozenset(
    {CONSERVATIVE, ASSUME_SCALAR_INDEPENDENT}
)

UNKNOWN_SCALAR_INDEPENDENCE_ASSUMPTION = (
    "Unknown scalar stack allocation sizes, including values that may depend "
    "on memory, external calls, or caller inputs, are assumed independent of "
    "hardware VLEN for this conditional analysis. This assumption is not proof."
)

CONSERVATIVE_SCOPE_DESCRIPTION = (
    "Unknown scalar stack allocation sizes remain conservatively VLEN-sensitive."
)


def normalize_unknown_stack_size_policy(value: str | None = None) -> str:
    """Normalize the shared policy vocabulary and reject unknown values."""

    normalized = CONSERVATIVE if value is None else value
    if not isinstance(normalized, str) or normalized not in UNKNOWN_STACK_SIZE_POLICIES:
        choices = ", ".join(sorted(UNKNOWN_STACK_SIZE_POLICIES))
        raise ValueError(
            "unknown_stack_size_policy must be one of: " + choices
        )
    return normalized


def assumption_for_policy(policy: str) -> str:
    if policy == ASSUME_SCALAR_INDEPENDENT:
        return UNKNOWN_SCALAR_INDEPENDENCE_ASSUMPTION
    return CONSERVATIVE_SCOPE_DESCRIPTION


def is_conditional_policy(policy: str) -> bool:
    return policy == ASSUME_SCALAR_INDEPENDENT


__all__ = [
    "ASSUME_SCALAR_INDEPENDENT",
    "CONSERVATIVE",
    "UNKNOWN_STACK_SIZE_POLICIES",
    "UNKNOWN_SCALAR_INDEPENDENCE_ASSUMPTION",
    "assumption_for_policy",
    "is_conditional_policy",
    "normalize_unknown_stack_size_policy",
]
