"""Static checks on the modules a prepare run is about to analyse.

These are the checks that a content digest cannot express.  A digest answers
"are these the bytes the artifacts were computed for"; the checks here answer
"will the loader actually find *these* files at run time".  Both have to hold,
and neither implies the other.

They run at prepare time on purpose.  The alternative is discovering the problem
on the target machine, where the symptom is not an error but a silently
different library -- this project's worst failure mode.
"""

from __future__ import annotations

from ..core.data_model import DELIVERY_TARGET


def reject_target_loader_redirection(platform, modules) -> None:
    """Fail when a target-resolved module carries ``DT_RPATH``.

    ``run`` starts the application with an explicit loader and controls this
    launch's search path through ``--library-path``.  That control has exactly
    one hole: ``DT_RPATH`` is consulted **before** the command-line search path,
    so a dependency carrying it can pull in a file we never recorded and never
    verified -- while the manifest still claims the recorded set is what runs.

    ``DT_RUNPATH`` is *not* a problem: it is consulted **after** the
    command-line search path, so ``--library-path`` still decides.  Rejecting it
    too would fail builds for no reason; missing it would silently defeat the
    verification.  The two tags are deliberately distinguished.

    Package-delivered modules are not checked here: they are rewritten into a
    flat directory during packing, where workspack verifies that their own
    search paths cannot escape.  Only files we do not control the bytes of need
    a prepare-time verdict.
    """

    offenders: list[str] = []
    for module in modules:
        if module.delivery != DELIVERY_TARGET:
            continue
        declared = platform.dynamic_search_paths(module.selected_path)
        rpaths = declared.get("DT_RPATH")
        if not rpaths:
            continue
        offenders.append(
            f"{module.selected_path} (module {module.module_id}) declares "
            "DT_RPATH=" + ":".join(rpaths)
        )
    if offenders:
        raise ValueError(
            "target-resolved modules must not declare DT_RPATH: the loader "
            "searches it before --library-path, so the file that would actually "
            "be loaded cannot be verified against the manifest.  Either rebuild "
            "the module with --enable-new-dtags (DT_RUNPATH) or supply a "
            "package-delivered build of it:\n  " + "\n  ".join(offenders)
        )


__all__ = ["reject_target_loader_redirection"]
