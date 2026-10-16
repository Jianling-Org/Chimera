#!/usr/bin/env python3
"""Merge per-ELF check decisions into one union decision, and verify a source.

Two subcommands, both pure JSON readers -- neither re-runs an analysis, writes
a check credential or relaxes a safety criterion:

``merge``
    Union the gate lists of several ``*.check.json`` reports (or of already
    exported decision files) into one decision file, keeping the orthogonal
    switches.  The previous decision is read only to *diff* against: the union
    is written to a fresh path and the old decision is never overwritten.

``verify-source``
    Check that one function (the experiment target) reached the gate candidate
    list *because the fix made it reachable*, not merely because its name is
    there.  Four facts are required, and any missing one stops the run:

    1. the function is on the candidate list;
    2. the inheritance report carries its coverage accounting
       (``has_metadata_section``, ``access_mode``, ``mode_reason``, the two
       counts and the uncovered addresses) -- an empty report is not evidence;
    3. that accounting is self-consistent: the mode agrees with the section's
       presence and with ``mode_reason``, the covered count plus the uncovered
       addresses equals the sensitive count, and a fallback lists at least one
       uncovered access.  A contradictory record stops the run -- it cannot be
       read as "the fallback happened";
    4. the mode is ``binary-incomplete-coverage``: the section existed and this
       function was *not* covered, which is what this round is about
       (``--no-require-fallback`` relaxes it to any binary mode);
    5. a local source exists: a seed call site carrying local active objects,
       or a finding whose structured origins (or ``origin_status``) describe
       this function's own activity.  A pure-inherited finding says the live
       state belongs to an upstream frame and does not qualify.

    Exits non-zero (2 = not a candidate, 4 = the name is there but the
    evidence is not) so a caller stops and keeps the evidence instead of
    hand-adding a name and rebuilding on a guess.

Usage:
    python tools/merge_gate_decision.py merge \
        --report xgcc.check.json --report cc1.check.json \
        --baseline gate2.decision.json --out gate3.decision.json \
        [--summary gate3.decision-diff.md]
    python tools/merge_gate_decision.py verify-source \
        --report xgcc.check.json --inheritance-report xgcc.inheritance.json \
        --function <mangled-name> [--json out.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

SCHEMA = "chimera-gate-decision-union-v1"

#: Exit codes: 0 = verified/completed, 2 = the target did not reach the list,
#: 4 = the name is on the list but the evidence behind it is missing.
EXIT_OK = 0
EXIT_NOT_A_CANDIDATE = 2
EXIT_BAD_INPUT = 3
EXIT_INSUFFICIENT_EVIDENCE = 4

#: The coverage accounting a function entry must carry to be evidence at all.
COVERAGE_FIELDS = (
    "has_metadata_section",
    "sensitive_access_count",
    "metadata_covered_count",
    "uncovered_sensitive_addresses",
    "access_mode",
    "mode_reason",
)

#: Modes in which metadata did *not* cover the function, i.e. binary recovery
#: ran.  ``metadata-complete-coverage`` is the only mode that disqualifies the
#: "uncovered access" explanation.
BINARY_MODES = frozenset({"binary-no-section", "binary-incomplete-coverage"})
#: The mode the fix is about: the section exists but this function is uncovered.
FALLBACK_MODE = "binary-incomplete-coverage"
#: ``access_mode`` -> the only ``mode_reason`` that may accompany it.
MODE_REASONS = {
    "binary-no-section": "no-stackobj-section",
    "binary-incomplete-coverage": "incomplete-metadata-coverage",
    "metadata-complete-coverage": "complete-metadata-coverage",
}

#: Structured activity origins that describe *this* function's own activity
#: (a VLEN frame, a conservative degradation, an irreducible object, resolved
#: vector stack data).  ``inherited`` is deliberately absent: live state that
#: belongs to an upstream frame is not a local source.
LOCAL_ORIGINS = frozenset(
    {
        "local-vlen-frame",
        "local-vlen-setup",
        "conservative",
        "irreducible",
        "local-vector-data",
    }
)
#: ``origin_status`` values that name local evidence.  ``unproven`` counts: it
#: is a local stack adjustment whose size is not established yet, which is
#: still a local source -- just not one the gate may claim to have removed.
LOCAL_ORIGIN_STATUSES = frozenset({"vlen-source", "unproven", "mixed"})
#: The finding kind and status that mean "nothing local was found".
INHERITED_KIND = "inherited"
INHERITED_STATUS = "inherited"


def sha256_of(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_report(path: Path) -> dict:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path}: not a JSON object")
    return document


def decision_of(document: dict) -> dict:
    """Accept a check report or an already exported decision file."""

    decision = document.get("decision")
    if isinstance(decision, dict):
        return decision
    if "gate" in document and "strategy" in document:
        return document
    raise ValueError("document carries neither a decision block nor decision keys")


def check_versions(document: dict) -> list[int]:
    return sorted(
        {
            int(check["version"])
            for check in document.get("checks", [])
            if isinstance(check, dict) and "version" in check
        }
    )


def merge(reports: list[Path], baseline: Path | None) -> dict:
    """Union the gate lists; diff the union against an earlier decision."""

    sources: list[dict] = []
    names: set[str] = set()
    strategies: set[str] = set()
    stack_object = False
    function_pointer = False
    for path in reports:
        document = load_report(path)
        decision = decision_of(document)
        strategies.add(decision.get("strategy"))
        stack_object = stack_object or bool(decision.get("stack_object_plugin"))
        function_pointer = function_pointer or bool(
            decision.get("function_pointer_plugin")
        )
        gate = decision.get("gate") or {}
        gate_names = set(gate.get("names") or ())
        names |= gate_names
        sources.append(
            {
                "path": str(Path(path).resolve()),
                "sha256": sha256_of(path),
                "check_versions": check_versions(document),
                "gate_count": len(gate_names),
            }
        )
    if len(strategies) != 1:
        raise ValueError(
            f"refusing to merge decisions with different strategies: {sorted(strategies)}"
        )
    strategy = strategies.pop()
    merged = {
        "strategy": strategy,
        "vector_gate": {
            "enabled": strategy == "gate",
            "names_source": "union of the per-ELF report gate lists",
        },
        "function_pointer_plugin": function_pointer,
        # Sticky: once any report needs the stack-object metadata, the union
        # keeps it, so a rebuild cannot oscillate between the two routes.
        "stack_object_plugin": stack_object,
        "gate": {
            "enabled": strategy == "gate",
            "names": sorted(names),
        },
    }
    payload = {
        "schema": SCHEMA,
        "decision": merged,
        "provenance": {
            "sources": sources,
            "union_count": len(names),
        },
    }
    if baseline is not None:
        old = decision_of(load_report(baseline))
        old_names = set((old.get("gate") or {}).get("names") or ())
        payload["provenance"]["baseline"] = {
            "path": str(Path(baseline).resolve()),
            "sha256": sha256_of(baseline),
            "gate_count": len(old_names),
        }
        added = sorted(names - old_names)
        removed = sorted(old_names - names)
        payload["provenance"]["added"] = added
        payload["provenance"]["removed"] = removed
        payload["provenance"]["added_count"] = len(added)
        payload["provenance"]["removed_count"] = len(removed)
    return payload


def render_summary(payload: dict) -> str:
    provenance = payload["provenance"]
    lines = [
        "# gate decision union",
        "",
        f"schema: {payload['schema']}",
        f"strategy: {payload['decision']['strategy']}",
        f"union gate count: {provenance['union_count']}",
        f"stack_object_plugin: {payload['decision']['stack_object_plugin']}",
        f"function_pointer_plugin: {payload['decision']['function_pointer_plugin']}",
        "",
        "## sources",
        "",
    ]
    for source in provenance["sources"]:
        lines.append(
            f"- {source['path']} (sha256 {source['sha256'][:16]}…, "
            f"check versions {source['check_versions']}, "
            f"gate names {source['gate_count']})"
        )
    baseline = provenance.get("baseline")
    if baseline is not None:
        lines.extend(
            [
                "",
                "## difference against the previous decision",
                "",
                f"- baseline: {baseline['path']} ({baseline['gate_count']} names)",
                f"- added: {provenance['added_count']}",
                f"- removed: {provenance['removed_count']}",
                "",
                "### added names (first 50)",
                "",
            ]
        )
        lines.extend(f"- {name}" for name in provenance["added"][:50])
        lines.extend(["", "### removed names (first 50)", ""])
        lines.extend(f"- {name}" for name in provenance["removed"][:50])
        lines.append("")
        lines.append(
            "The previous decision file was read only; this union is written "
            "to its own path and never replaces it."
        )
    return "\n".join(lines) + "\n"


def _function_entry(inherited: dict, function: str) -> dict | None:
    for entry in inherited.get("functions", ()):
        if entry.get("name") == function:
            return entry
    return None


def _seed_evidence(inherited: dict, function: str) -> dict:
    """Seed call sites of ``function`` and the local objects they carry.

    ``seed_edges`` reference functions by index; the function table is ordered
    by the same index, so ``caller_function_ref`` resolves through it.
    """

    table = list(inherited.get("functions", ()))
    edges = [
        edge
        for edge in inherited.get("seed_edges", ())
        if 0 <= int(edge.get("caller_function_ref", -1)) < len(table)
        and table[int(edge["caller_function_ref"])].get("name") == function
    ]
    return {
        "seed_call_sites": [
            edge.get("call_site") for edge in edges
        ],
        "seed_count": len(edges),
        "seed_local_active_objects": sum(
            len(edge.get("local_active_objects") or ()) for edge in edges
        ),
    }


def _finding_is_local(finding: dict) -> bool:
    """Whether one finding is evidence of *this* function's own activity.

    A pure-inherited finding says the opposite: the live state belongs to an
    upstream frame and merely stopped propagating here.  Accepting it as a
    local source would let a host with no source of its own satisfy the
    verification -- which is precisely the failure the fix exists to prevent.

    The structured origins are read first; only they can overrule an
    ``inherited`` kind.
    """

    for origin in finding.get("activity_origins") or ():
        if isinstance(origin, dict) and str(origin.get("origin", "")) in LOCAL_ORIGINS:
            return True
    status = str(finding.get("origin_status", ""))
    if status in LOCAL_ORIGIN_STATUSES:
        return True
    kind = str(finding.get("kind", ""))
    return bool(kind) and kind != INHERITED_KIND and status != INHERITED_STATUS


def coverage_consistency(coverage: dict) -> list[str]:
    """Contradictions inside one function's coverage accounting.

    The fields are only evidence when they agree with each other: a mode of
    ``binary-no-section`` next to ``has_metadata_section=true``, or a fallback
    mode with an empty uncovered-address list, describes a state that cannot
    occur -- and must therefore stop the verification instead of being read as
    "the fallback happened".
    """

    problems: list[str] = []
    if not coverage:
        return ["no coverage fields at all"]
    mode = coverage.get("access_mode")
    reason = coverage.get("mode_reason")
    has_section = coverage.get("has_metadata_section")
    sensitive = coverage.get("sensitive_access_count")
    covered = coverage.get("metadata_covered_count")
    uncovered = coverage.get("uncovered_sensitive_addresses") or ()

    expected_reason = MODE_REASONS.get(mode)
    if expected_reason is None:
        problems.append(f"unknown access_mode: {mode!r}")
    elif reason != expected_reason:
        problems.append(f"mode_reason {reason!r} contradicts access_mode {mode!r}")

    if has_section is True and mode == "binary-no-section":
        # The section exists, so "no section" is not a state this function can
        # be in -- and it is not the fallback either.
        problems.append(
            "has_metadata_section=true but access_mode is "
            f"{'binary-no-section'!r}"
        )
    if has_section is False and mode != "binary-no-section":
        # Without the section no record can exist, so no coverage claim and no
        # coverage fallback is possible.
        problems.append(
            f"has_metadata_section=false but access_mode is {mode!r}"
        )
    if isinstance(sensitive, int) and isinstance(covered, int):
        if covered > sensitive:
            problems.append(
                f"metadata_covered_count {covered} exceeds "
                f"sensitive_access_count {sensitive}"
            )
        if covered + len(uncovered) != sensitive:
            problems.append(
                f"metadata_covered_count {covered} + uncovered "
                f"{len(uncovered)} != sensitive_access_count {sensitive}"
            )
    if mode == FALLBACK_MODE and not uncovered:
        problems.append("coverage fallback with no uncovered sensitive access")
    if mode == "metadata-complete-coverage" and uncovered:
        problems.append("complete coverage with uncovered sensitive accesses")
    return problems


def verify_source(
    report: Path, inheritance: Path | None, function: str,
    *, require_fallback: bool = True,
) -> tuple[dict, int]:
    """Did ``function`` reach the list *because* its coverage was incomplete?"""

    document = load_report(report)
    decision = decision_of(document)
    gate_names = list((decision.get("gate") or {}).get("names") or ())
    diagnostics = {}
    for check in document.get("checks", []):
        if isinstance(check, dict) and check.get("diagnostics"):
            diagnostics = check["diagnostics"]
            break
    findings = [
        finding
        for finding in (diagnostics.get("findings") or ())
        if finding.get("function") == function
    ]

    coverage: dict = {}
    entry: dict | None = None
    evidence: dict = {"seed_call_sites": [], "seed_count": 0,
                      "seed_local_active_objects": 0}
    if inheritance is not None:
        inherited = load_report(inheritance)
        entry = _function_entry(inherited, function)
        if entry is not None:
            coverage = {
                key: entry.get(key) for key in COVERAGE_FIELDS if key in entry
            }
            evidence = _seed_evidence(inherited, function)

    candidate = function in gate_names
    # 2. the coverage accounting must be complete -- an empty inheritance
    #    report is not evidence, and must never be read as "fully covered".
    coverage_complete = all(key in coverage for key in COVERAGE_FIELDS)
    # 2b. and it must be self-consistent: mode, section, counts and the
    #     uncovered addresses have to describe one possible state.
    problems = coverage_consistency(coverage) if coverage_complete else []
    # 3. metadata must not have covered the function -- and this round demands
    #    the fallback itself, not merely "some binary mode".
    access_mode = coverage.get("access_mode")
    if not coverage_complete or access_mode is None:
        metadata_uncovered = False
        fallback = False
    else:
        metadata_uncovered = access_mode in BINARY_MODES
        fallback = access_mode == FALLBACK_MODE
    # 4. a local source must exist: a seed carrying local objects, or a finding
    #    that is *this function's own* -- a pure-inherited finding is not one.
    local_findings = [
        {
            "kind": finding.get("kind"),
            "origin_status": finding.get("origin_status"),
            "local": _finding_is_local(finding),
        }
        for finding in findings
    ]
    has_local_source = bool(
        evidence["seed_local_active_objects"]
        or any(item["local"] for item in local_findings)
    )

    if not candidate:
        verdict = "not-a-candidate"
        code = EXIT_NOT_A_CANDIDATE
    elif not coverage_complete:
        verdict = "missing-coverage-evidence"
        code = EXIT_INSUFFICIENT_EVIDENCE
    elif problems:
        verdict = "inconsistent-coverage"
        code = EXIT_INSUFFICIENT_EVIDENCE
    elif not metadata_uncovered:
        # The most informative verdict first: metadata really did cover it, so
        # this function is not an instance of the bug at all.
        verdict = "covered-by-metadata"
        code = EXIT_INSUFFICIENT_EVIDENCE
    elif require_fallback and not fallback:
        verdict = "no-coverage-fallback"
        code = EXIT_INSUFFICIENT_EVIDENCE
    elif not has_local_source:
        verdict = "no-local-source"
        code = EXIT_INSUFFICIENT_EVIDENCE
    else:
        verdict = "verified"
        code = EXIT_OK

    payload = {
        "schema": "chimera-gate-source-verification-v1",
        "report": str(Path(report).resolve()),
        "inheritance_report": (
            str(Path(inheritance).resolve()) if inheritance is not None else None
        ),
        "function": function,
        "gate_candidate": candidate,
        "gate_names_count": len(gate_names),
        "findings_of_function": findings,
        "coverage": coverage,
        "coverage_fields_complete": coverage_complete,
        "coverage_consistency_problems": problems,
        "coverage_consistent": not problems,
        "metadata_did_not_cover_function": metadata_uncovered,
        "coverage_fallback_applied": fallback,
        "require_fallback": bool(require_fallback),
        "uncovered_sensitive_count": len(
            coverage.get("uncovered_sensitive_addresses") or ()
        ),
        "local_source_evidence": {
            **evidence,
            "findings_of_function": len(findings),
            "local_findings": local_findings,
            "frame_origins": len((entry or {}).get("frame_origins") or ()),
        },
        "has_local_source": has_local_source,
        "local_source_rule": (
            "a seed call site carrying local active objects, or a finding "
            "whose structured origins (or origin_status) describe this "
            "function's own activity; a pure-inherited finding is not one"
        ),
        "verdict": verdict,
        "note": (
            "the candidate list is produced by the propagation chain of the "
            "check itself; a name is never added here"
        ),
    }
    return payload, code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    merge_parser = sub.add_parser("merge", help="union several gate lists")
    merge_parser.add_argument(
        "--report", action="append", default=[], required=True, type=Path
    )
    merge_parser.add_argument("--baseline", type=Path, default=None)
    merge_parser.add_argument("--out", type=Path, required=True)
    merge_parser.add_argument("--summary", type=Path, default=None)

    verify_parser = sub.add_parser(
        "verify-source", help="verify one function reached the candidate list"
    )
    verify_parser.add_argument("--report", type=Path, required=True)
    verify_parser.add_argument("--inheritance-report", type=Path, default=None)
    verify_parser.add_argument("--function", required=True)
    verify_parser.add_argument("--json", type=Path, default=None)
    verify_parser.add_argument(
        "--no-require-fallback",
        action="store_true",
        help=(
            "accept any binary mode instead of demanding "
            f"{FALLBACK_MODE!r}; off by default because this round's "
            "verification exists to prove the fallback happened"
        ),
    )

    args = parser.parse_args(argv)

    try:
        if args.command == "merge":
            payload = merge(args.report, args.baseline)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            if args.summary is not None:
                args.summary.parent.mkdir(parents=True, exist_ok=True)
                args.summary.write_text(
                    render_summary(payload), encoding="utf-8"
                )
            print(f"union gate count: {payload['provenance']['union_count']}")
            print(f"wrote {args.out}")
            return EXIT_OK
        payload, code = verify_source(
            args.report,
            args.inheritance_report,
            args.function,
            require_fallback=not args.no_require_fallback,
        )
        text = json.dumps(payload, indent=2, ensure_ascii=False)
        if args.json is not None:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(text, encoding="utf-8")
        print(text)
        if code == EXIT_NOT_A_CANDIDATE:
            print(
                f"{args.function} did NOT reach the gate candidate list; "
                "keeping the evidence instead of adding the name by hand",
                file=sys.stderr,
            )
        elif code == EXIT_INSUFFICIENT_EVIDENCE:
            print(
                f"{args.function} is on the list but the evidence behind it is "
                f"missing ({payload['verdict']}); stopping rather than "
                "rebuilding on a guess",
                file=sys.stderr,
            )
        return code
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"input error: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
