"""Rebind machine-proven native call closures before loading a Workspace."""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

from elftools.elf.elffile import ELFFile

from chimera.preprocess.offline.analysis.safety.external_leaf_binding import plt_import
from chimera.preprocess.offline.analysis.safety.native_call_binding import (
    NATIVE_CLOSURE_FORMAT, NATIVE_CLOSURE_STATUS, NativeClosureEnvironment,
)


def validate_native_call_proofs(proofs, *, main, modules, resolved, files, exports):
    environment = NativeClosureEnvironment(resolved[main.module_id],
        [SimpleNamespace(module_id=mid, selected_path=path) for mid, path in resolved.items()],
        'not-used-at-launch')
    environment._initialize()
    expected_hashes = {mid: module.sha256 for mid, module in modules.items()}
    with Path(resolved[main.module_id]).open('rb') as stream:
        main_elf = ELFFile(stream)
        for proof in proofs:
            if (proof.get('format') != NATIVE_CLOSURE_FORMAT
                    or proof.get('status') != NATIVE_CLOSURE_STATUS
                    or proof.get('modules') != expected_hashes):
                raise ValueError('native call closure format or module identities differ')
            symbol, provider_id = proof['symbol'], proof['provider_module']
            if provider_id not in modules or provider_id == main.module_id:
                raise ValueError('native closure provider is not a selected dependency')
            candidates = [(path, item) for path in files for item in exports[path][symbol]
                          if not item['hidden_version']]
            if len(candidates) != 1:
                raise ValueError('native closure symbol is missing or interposed: '+symbol)
            path, definition = candidates[0]
            if (path != Path(resolved[provider_id]).resolve()
                    or definition != proof.get('provider_definition')
                    or definition['type'] != 'STT_FUNC'
                    or definition['value'] != proof.get('provider_address')):
                raise ValueError('native closure provider definition changed')
            environment.code_bytes(main.module_id, proof['target'], 16)
            imported = plt_import(main_elf, proof['target'])
            if (imported['symbol'] != symbol or imported['got'] != proof.get('got')
                    or imported['version'] != proof.get('imported_version')):
                raise ValueError('native closure PLT binding changed')
            nodes = proof.get('functions')
            if not isinstance(nodes, list) or not 0 < len(nodes) <= 64:
                raise ValueError('native closure has no bounded function proof')
            keys = {(node['module'], node['address']) for node in nodes}
            if len(keys) != len(nodes) or (provider_id, definition['value']) not in keys:
                raise ValueError('native closure root or function identities differ')
            for node in nodes:
                mid, address, size = node['module'], node['address'], node['size']
                if (mid not in modules or mid == main.module_id or not isinstance(address, int)
                        or not isinstance(size, int) or not 0 < size <= 4096
                        or not node.get('proven_returns')
                        or any(not address <= site < address+size for site in node['proven_returns'])
                        or any(tuple(callee) not in keys for callee in node['callees'])):
                    raise ValueError('native closure graph has an open or invalid function')
                code = environment.code_bytes(mid, address, size)
                if hashlib.sha256(code).hexdigest() != node.get('code_sha256'):
                    raise ValueError('native closure body bytes changed')
            for record in proof.get('object_bindings', []):
                source, address = record['source_module'], record['source_address']
                if source not in modules:
                    raise ValueError('native closure object import has no selected module')
                environment.load(None, ('address', source, address), 8)
                if environment.objects.get((source, address)) != record:
                    raise ValueError('native closure object/TLS binding changed')
                name = record['symbol']
                implementations = [(path, item) for path in files for item in exports[path][name]
                                   if not item['hidden_version']]
                if len(implementations) != 1:
                    raise ValueError('native closure object is missing or interposed: '+name)
                path, definition = implementations[0]
                if path != Path(resolved[record['provider_module']]).resolve() or any(
                    definition.get(key) != record.get(key) for key in
                    ('value', 'size', 'type', 'binding', 'section', 'version', 'hidden_version')):
                    raise ValueError('native closure object provider changed')
