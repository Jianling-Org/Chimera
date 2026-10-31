from pathlib import Path
import tempfile,os,unittest,hashlib
from unittest.mock import patch
from chimera.runtime.manifest.file_identity import cached_sha256, identity_row

class FileIdentityTests(unittest.TestCase):
    def test_reuses_identity_across_hardlinks_and_invalidates_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);a=root/'a';b=root/'b';a.write_bytes(b'old');os.link(a,b)
            with patch.dict(os.environ, {'CHIMERA_SHA_CACHE':str(root/'cache.sqlite')}):
                with patch('hashlib.file_digest', wraps=hashlib.file_digest) as hashed:
                    first=cached_sha256(a)
                    self.assertEqual(cached_sha256(b),first)
                    self.assertEqual(cached_sha256(a),first)
                    self.assertEqual(hashed.call_count,1)
                    old=a.stat();a.write_bytes(b'new');os.utime(a,ns=(old.st_atime_ns,old.st_mtime_ns))
                    self.assertNotEqual(cached_sha256(a),first)
                    self.assertEqual(hashed.call_count,2)
                    with self.assertRaises(ValueError):identity_row(a,first)

    def test_replaced_file_needs_new_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);a=root/'a';a.write_bytes(b'one')
            with patch.dict(os.environ, {'CHIMERA_SHA_CACHE':str(root/'cache.sqlite')}):
                first=cached_sha256(a);replacement=root/'replacement';replacement.write_bytes(b'two');replacement.replace(a)
                self.assertNotEqual(cached_sha256(a),first)
