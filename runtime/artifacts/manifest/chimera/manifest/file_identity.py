"""Offline-only content verification, shared across registration processes."""
from pathlib import Path
import hashlib
import os
import sqlite3

def cached_sha256(path: Path) -> str:
    path = Path(path)
    cache = Path(os.environ.get('CHIMERA_SHA_CACHE', str(Path.home()/'.cache/chimera/file-sha256.sqlite')))
    cache.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(cache, timeout=600) as db:
        db.execute('CREATE TABLE IF NOT EXISTS digests (identity TEXT PRIMARY KEY, digest TEXT NOT NULL)')
        # Serialize cache misses as well: concurrent registrars hash once.
        db.execute('BEGIN IMMEDIATE')
        with path.open('rb') as source:
            st = os.fstat(source.fileno())
            key = repr((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns))
            row = db.execute('SELECT digest FROM digests WHERE identity=?', (key,)).fetchone()
            if row: return row[0]
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
            after = os.fstat(source.fileno())
            if (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('file changed during verification: '+str(path))
            db.execute('INSERT INTO digests VALUES (?,?)', (key, digest))
            return digest

def identity_row(path: Path, expected: str) -> str:
    path = Path(path).resolve()
    before = path.stat()
    if cached_sha256(path) != expected: raise ValueError('file digest mismatch: '+str(path))
    st = path.stat()
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) != (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns):
        raise ValueError('file changed during registration: '+str(path))
    if any(c in str(path) for c in '\t\r\n'): raise ValueError('invalid receipt path')
    return '\t'.join(map(str, (path, expected, st.st_dev, st.st_ino, st.st_size,
        st.st_mtime_ns//10**9, st.st_mtime_ns%10**9, st.st_ctime_ns//10**9, st.st_ctime_ns%10**9)))+'\n'
