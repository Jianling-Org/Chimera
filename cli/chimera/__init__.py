"""Chimera package metadata."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
import importlib
import sys


try:
    __version__ = version("chimera")
except PackageNotFoundError:
    __version__ = "0+unknown"


# The editable/source checkout keeps preprocessing code under the historical
# ``preprocessing/`` tree, while built wheels install it as
# ``chimera.preprocess``.  Register the source namespace when the wheel layout
# is not present so CLI and unit-test imports behave the same in both modes.
try:
    importlib.import_module("chimera.preprocess")
except ModuleNotFoundError:
    try:
        _source_preprocess = importlib.import_module("preprocessing")
    except ModuleNotFoundError:
        pass
    else:
        sys.modules.setdefault("chimera.preprocess", _source_preprocess)
        # ``sys.modules`` registration alone is not enough for callers that
        # access ``chimera.preprocess`` as an attribute (for example
        # ``unittest.mock.patch``); mirror normal package import semantics.
        setattr(sys.modules[__name__], "preprocess", _source_preprocess)

try:
    importlib.import_module("chimera.runtime")
except ModuleNotFoundError:
    try:
        _source_runtime = importlib.import_module("runtime")
    except ModuleNotFoundError:
        pass
    else:
        sys.modules.setdefault("chimera.runtime", _source_runtime)
        setattr(sys.modules[__name__], "runtime", _source_runtime)


# The CMake project stores runtime Python packages below their install
# prefixes.  Mirror the wheel package names for direct source-tree imports.
_SOURCE_RUNTIME_MODULES = {
    "chimera.runtime.manifest": "runtime.artifacts.manifest.chimera.manifest",
    "chimera.runtime.manifest.codec": "runtime.artifacts.manifest.chimera.manifest.codec",
    "chimera.runtime.manifest.model": "runtime.artifacts.manifest.chimera.manifest.model",
    "chimera.runtime.scene_contracts": "runtime.artifacts.scene_contracts.chimera.scene_contracts",
    "chimera.runtime.scene_contracts.composition": "runtime.artifacts.scene_contracts.chimera.scene_contracts.composition",
    "chimera.runtime.bpf": "runtime.bpf.loader.chimera.bpf",
    "chimera.runtime.bpf.registry": "runtime.bpf.loader.chimera.bpf.registry",
    "chimera.runtime.bpf.transaction": "runtime.bpf.loader.chimera.bpf.transaction",
    "chimera.runtime.bpf.syscall": "runtime.bpf.loader.chimera.bpf.syscall",
    "chimera.runtime.env_verify": "runtime.env.verify.chimera.env_verify",
    "chimera.runtime.env_verify.host": "runtime.env.verify.chimera.env_verify.host",
    "chimera.runtime.validate": "runtime.artifacts.validate.chimera.validate",
    "chimera.runtime.validate.workspace": "runtime.artifacts.validate.chimera.validate.workspace",
    "chimera.runtime.validate.capabilities": "runtime.artifacts.validate.chimera.validate.capabilities",
    "chimera.runtime.validate.scenes": "runtime.artifacts.validate.chimera.validate.scenes",
    "chimera.runtime.preload": "runtime.launcher.preload.chimera.preload",
    "chimera.runtime.preload.preload": "runtime.launcher.preload.chimera.preload.preload",
    "chimera.runtime.launcher": "runtime.launcher.run.chimera.launcher",
    "chimera.runtime.launcher.run": "runtime.launcher.run.chimera.launcher.run",
    "chimera.runtime.launcher.adapters": "runtime.launcher.run.chimera.launcher.adapters",
    "chimera.runtime.launcher.migration": "runtime.launcher.run.chimera.launcher.migration",
}
for _public_name, _source_name in _SOURCE_RUNTIME_MODULES.items():
    try:
        _source_module = importlib.import_module(_source_name)
    except ModuleNotFoundError:
        continue
    # Importing a source submodule can first create a namespace package at the
    # public wheel name (because ``chimera.runtime`` aliases ``runtime``).
    # Replace that placeholder with the actual install-prefix module.
    sys.modules[_public_name] = _source_module
    _parent_name, _, _child_name = _public_name.rpartition(".")
    _parent_module = sys.modules.get(_parent_name)
    if _parent_module is not None:
        setattr(_parent_module, _child_name, _source_module)


__all__ = ["__version__"]
