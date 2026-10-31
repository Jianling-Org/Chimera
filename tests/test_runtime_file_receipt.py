from pathlib import Path
import os,subprocess,tempfile,unittest,shutil,hashlib
from chimera.runtime.manifest.file_identity import identity_row

class RuntimeReceiptTests(unittest.TestCase):
    def test_metadata_validation_never_opens_payload_and_rejects_changes(self):
        cc=shutil.which('cc')
        if not cc:self.skipTest('C compiler required')
        runtime=Path(__file__).resolve().parents[1]/'runtime'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'artifacts').mkdir();payload=root/'payload';payload.write_bytes(b'original')
            digest=hashlib.sha256(payload.read_bytes()).hexdigest()
            receipt=root/'artifacts/verified-files.tsv';receipt.write_text(identity_row(payload,digest))
            source=root/'check.c';exe=root/'check'
            source.write_text(r'''
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "integrity.h"
FILE *__real_fopen(const char *, const char *);
FILE *__wrap_fopen(const char *path, const char *mode) {
    if (strstr(path, "/payload")) { errno=EACCES; return NULL; }
    return __real_fopen(path,mode);
}
int main(int argc,char **argv) {
    if(argc==4)return chimera_verified_tables(argv[1]) ? 0 : 1;
    if(argc!=3)return 2;
    struct chimera_manifest_artifact artifact={0};
    strcpy(artifact.path,"payload");strcpy(artifact.sha256,argv[2]);
    return chimera_artifact_matches(argv[1],&artifact) ? 0 : 1;
}
''')
            subprocess.run([cc,'-Wall','-Wextra','-Werror','-I'+str(runtime/'interfaces/abi'),'-I'+str(runtime/'artifacts/manifest/linux_riscv64_rvv_v1'),str(source),str(runtime/'artifacts/manifest/linux_riscv64_rvv_v1/integrity.c'),'-Wl,--wrap=fopen','-o',str(exe)],check=True)
            def run():return subprocess.run([str(exe),str(root),digest],check=False).returncode
            self.assertEqual(run(),0) # Payload fopen is prohibited by the wrapper.
            def tables():return subprocess.run([str(exe),str(root),digest,'tables'],check=False).returncode
            self.assertEqual(tables(),1)
            st=receipt.stat()
            proof='\t'.join(map(str,('tables-v1',st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9)))
            (root/'artifacts/verified-tables.tsv').write_text(proof)
            self.assertEqual(tables(),0)
            receipt.write_text(receipt.read_text()+'\n')
            self.assertEqual(tables(),1)
            old=payload.stat();payload.write_bytes(b'modified');os.utime(payload,ns=(old.st_atime_ns,old.st_mtime_ns))
            self.assertEqual(run(),1)
            replacement=root/'new';replacement.write_bytes(b'original');replacement.replace(payload)
            self.assertEqual(run(),1)
            receipt.unlink();self.assertEqual(run(),1)
