"""Cache validity of a prepare run.

Identity and cache validity answer different questions and must not be
conflated:

* **identity** (:mod:`.identity`) -- "is this the ELF these artifacts belong
  to?"  Cross-machine, one ELF one Workspace.
* **fingerprint** (this module) -- "were the recorded artifacts produced from
  exactly these inputs?"  Covers every input the prepare run selected, so the
  answer is no as soon as a dependency, the scalar base or the target routing
  changes even though the input ELF is untouched.

Reuse therefore requires both: a matching identity *and* a matching
fingerprint.
"""

from __future__ import annotations

import hashlib
import json
from typing import Iterable


def input_fingerprint(items: Iterable[tuple[str, str]]) -> str:
    """Hash the labelled inputs of a prepare run.

    *items* pairs a human-readable label with a value digest; labels must be
    unique, because a repeated label would let one input silently replace
    another.  The result is order-independent so callers may collect items
    while probing inputs in whatever order is convenient.
    """

    collected: dict[str, str] = {}
    for label, value in items:
        if not isinstance(label, str) or not label:
            raise ValueError(f"fingerprint label must be a non-empty string: {label!r}")
        if not isinstance(value, str) or not value:
            raise ValueError(
                f"fingerprint value for {label!r} must be a non-empty string"
            )
        if label in collected:
            raise ValueError(f"duplicate fingerprint label: {label!r}")
        collected[label] = value
    payload = json.dumps(
        sorted(collected.items()),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


__all__ = ["input_fingerprint"]
