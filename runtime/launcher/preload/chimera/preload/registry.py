"""Publish verified bootstrap registry records with atomic replacement."""
from __future__ import annotations
import fcntl
from hashlib import sha256
import os
from chimera.runtime.manifest.file_identity import cached_sha256
from pathlib import Path
import tempfile

HEADER = "chimera-registry-v1\n"

def publish_receipt(workspace, program, manifest):
    from chimera.runtime.manifest import variant_fingerprint
    from chimera.runtime.manifest.file_identity import identity_row
    paths = {Path(program).resolve(): next(m.sha256 for m in manifest.modules if m.role == 'main')}
    for artifact in manifest.artifacts:
        paths[workspace / artifact.path] = artifact.sha256
    if any(m.role != 'main' for m in manifest.modules):
        from chimera.runtime.launcher.run import _select_loader, _search_paths, resolved_module_paths
        if any(m.runtime_name.startswith('ld-') and m.delivery == 'package' for m in manifest.modules):
            loader = _select_loader(workspace, program, manifest)
        else:
            from elftools.elf.elffile import ELFFile
            with program.open('rb') as source:
                loader = next(Path(segment.get_interp_name()) for segment in ELFFile(source).iter_segments() if segment['p_type'] == 'PT_INTERP')
        resolved = resolved_module_paths(loader, program, _search_paths(workspace, program), manifest)
        for module in manifest.modules:
            if module.role == 'main': continue
            if module.module_id not in resolved: raise ValueError('unresolved receipt module: '+module.module_id)
            paths[resolved[module.module_id]] = module.sha256
    (workspace / 'artifacts').mkdir(exist_ok=True)
    fingerprints = workspace / 'artifacts/verified-variants.tsv'
    content = ''.join(v.variant_id+'\t'+variant_fingerprint(manifest, v.variant_id)+'\n' for v in getattr(manifest, 'variants', ()))
    _atomic_text(fingerprints, content)
    manifest_file = workspace / 'artifacts/modules.tsv'
    for extra in (fingerprints, manifest_file):
        if extra.exists(): paths[extra] = cached_sha256(extra)
    receipt = ''.join(identity_row(path, digest) for path, digest in sorted(paths.items()))
    receipt_path = workspace / 'artifacts/verified-files.tsv'
    _atomic_text(receipt_path, receipt)
    if getattr(manifest, 'variants', ()):
        runtime_record = next(a for a in manifest.artifacts if a.capability == 'runtime' and a.owner_kind == 'workspace')
        verify_tables(workspace, program, workspace/runtime_record.path, receipt_path)

def verify_tables(workspace, program, runtime, receipt_path):
    import subprocess
    st = receipt_path.stat()
    proof = '\t'.join(map(str, ('tables-v1',st.st_dev,st.st_ino,st.st_size,
        st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9)))
    destination = workspace/'artifacts/verified-tables.tsv'
    if destination.exists() and destination.read_text() == proof: return
    from chimera.runtime.preload.bootstrap_launch import bootstrap_tunables
    env = dict(os.environ)
    for key in ('LD_PRELOAD','CHIMERA_REGISTRY','CHIMERA_RESOURCES','CHIMERA_AUTOMIGRATE'):
        env.pop(key,None)
    env.update(LD_PRELOAD=str(runtime), CHIMERA_WORKSPACE=str(workspace), CHIMERA_VERIFY_TABLES_ONLY='1',
        GLIBC_TUNABLES=bootstrap_tunables(env.get('GLIBC_TUNABLES','')))
    subprocess.run([str(program)],env=env,check=True,timeout=120)
    after = receipt_path.stat()
    if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) != (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns):
        raise ValueError('receipt changed during table verification')
    _atomic_text(destination,proof)

def _atomic_text(path, text):
    if path.exists() and path.read_text() == text: return
    fd, name = tempfile.mkstemp(prefix=path.name+'.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(text); output.flush(); os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)

def publish_registry(registry: Path, program: Path, workspace: Path, manifest) -> None:
    registry, program, workspace = Path(registry).absolute(), Path(program).resolve(), Path(workspace).resolve()
    mains = [m for m in manifest.modules if m.role == "main"]
    if len(mains) != 1 or cached_sha256(program) != mains[0].sha256:
        raise ValueError("registry executable does not match workspace main")
    runtimes = [a for a in manifest.artifacts if a.owner_kind == "workspace"
                and a.owner_id == "root" and a.capability == "runtime" and a.representation == "elf"]
    if len(runtimes) != 1:
        raise ValueError("workspace requires exactly one runtime")
    artifact = runtimes[0]
    runtime = (workspace / artifact.path).resolve()
    runtime.relative_to(workspace)
    if cached_sha256(runtime) != artifact.sha256:
        raise ValueError("registry runtime does not match manifest")
    fields = (str(program), mains[0].sha256, str(workspace), str(runtime), artifact.sha256)
    if any(any(c in f for c in "\t\n\r") for f in fields):
        raise ValueError("registry fields cannot contain tabs or newlines")
    registry.parent.mkdir(parents=True, exist_ok=True)
    publish_receipt(workspace, program, manifest)
    with open(str(registry) + ".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        rows = []
        if registry.exists():
            text = registry.read_text()
            if not text.startswith(HEADER):
                raise ValueError("invalid bootstrap registry header")
            records = text[len(HEADER):].splitlines()
            if any(len(line.split("\t")) != 5 for line in records):
                raise ValueError("malformed bootstrap registry record")
            rows = [line for line in records
                    if line.split("\t", 1)[0] != str(program)]
        rows.append("\t".join(fields))
        fd, temporary = tempfile.mkstemp(prefix=registry.name + ".", dir=registry.parent)
        try:
            with os.fdopen(fd, "w") as output:
                output.write(HEADER + "\n".join(sorted(rows)) + "\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, registry)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
