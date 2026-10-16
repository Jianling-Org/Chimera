"""Keep a prepared scalar-leaf proof bound to the actual launch files."""
from __future__ import annotations

import json
import os
from pathlib import Path

from chimera.preprocess.offline.analysis.safety.external_leaf import (
    CONTRACT_CAPABILITY, CONTRACT_FORMAT, file_sha256,
)
from chimera.preprocess.offline.analysis.safety.external_leaf_binding import (
    dynamic_definitions, plt_import,
)
from elftools.elf.elffile import ELFFile


def leaf_artifacts(manifest):
    return tuple(artifact for artifact in getattr(manifest, "artifacts", ())
                 if artifact.capability == CONTRACT_CAPABILITY)


def reject_leaf_interposers(manifest, *, environment=None,
                            system_preload=Path("/etc/ld.so.preload")) -> bool:
    if not leaf_artifacts(manifest):
        return False
    environment = os.environ if environment is None else environment
    for key in ("LD_PRELOAD", "LD_AUDIT", "LD_PROFILE"):
        if environment.get(key):
            raise ValueError(f"scalar leaf contracts cannot be used with {key}")
    if system_preload.is_file() and any(
            line.split("#", 1)[0].strip()
            for line in system_preload.read_text(encoding="utf-8").splitlines()):
        raise ValueError("scalar leaf contracts cannot be used with a system preload")
    return True


def validate_leaf_launch(root, manifest, resolved, *, environment=None,
                         system_preload=Path("/etc/ld.so.preload")) -> bool:
    artifacts = leaf_artifacts(manifest)
    if not artifacts:
        return False
    reject_leaf_interposers(manifest, environment=environment, system_preload=system_preload)
    if len(artifacts) != 1:
        raise ValueError("ambiguous external scalar leaf artifacts")
    artifact = artifacts[0]
    modules = {module.module_id: module for module in manifest.modules}
    main = next((module for module in manifest.modules if module.role == "main"), None)
    if (main is None or artifact.owner_kind != "module" or artifact.owner_id != main.module_id
            or artifact.abi != 1 or artifact.representation != "json"):
        raise ValueError("invalid scalar leaf artifact owner or ABI")
    path = (Path(root) / artifact.path).resolve()
    if not path.is_relative_to(Path(root).resolve()) or file_sha256(path) != artifact.sha256:
        raise ValueError("scalar leaf artifact identity differs from the Manifest")
    document = json.loads(path.read_text(encoding="utf-8"))
    if (document.get("format") != CONTRACT_FORMAT or document.get("elf_sha256") != main.sha256
            or not document.get("proofs") or document.get("rejections")):
        raise ValueError("incomplete or mismatched scalar leaf evidence")
    for name, module in modules.items():
        if name not in resolved:
            raise ValueError("scalar leaf binding has an unresolved module: " + name)
        if file_sha256(resolved[name]) != module.sha256:
            raise ValueError("scalar leaf module identity changed: " + name)
    names = {proof["symbol"] for proof in document["proofs"]}
    files = {Path(path).resolve() for path in resolved.values()}
    # These DSOs are loaded by the injected Runtime too. Checking just the
    # native provider would miss symbol preemption by a translated body.
    for extra in manifest.artifacts:
        if extra.representation == "elf":
            extra_path = (Path(root) / extra.path).resolve()
            if not extra_path.is_relative_to(Path(root).resolve()) or file_sha256(extra_path) != extra.sha256:
                raise ValueError("scalar leaf supporting artifact identity changed")
            files.add(extra_path)
    exports = {path: dynamic_definitions(path, names) for path in files}
    with Path(resolved[main.module_id]).open("rb") as stream:
        elf = ELFFile(stream)
        for proof in document["proofs"]:
            symbol, provider_id = proof["symbol"], proof["provider_module"]
            provider = modules.get(provider_id)
            if (provider is None or provider.runtime_name != proof["library"]
                    or provider.sha256 != proof["sha256"] or proof["status"] != "verified-scalar-leaf"):
                raise ValueError("scalar leaf provider identity is not bound")
            implementations = [(path, item) for path in files for item in exports[path][symbol]]
            if len(implementations) != 1:
                raise ValueError("scalar leaf symbol is missing or interposed: " + symbol)
            path, definition = implementations[0]
            if (path != Path(resolved[provider_id]).resolve() or definition["type"] != "STT_FUNC"
                    or definition["binding"] not in {"STB_GLOBAL", "STB_WEAK"}
                    or definition["value"] != proof["provider_address"] or definition["size"] != proof["size"]
                    or definition["version"] != proof["version"] or definition["hidden_version"]):
                raise ValueError("scalar leaf implementation differs from its proof")
            imported = plt_import(elf, proof["target"])
            if (imported["symbol"] != symbol or imported["got"] != proof["got"]
                    or imported["version"] not in (None, proof["version"])):
                raise ValueError("scalar leaf import differs from its proof")
    return True
