#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir_one(path) _mkdir(path)
#else
#include <sys/stat.h>
#define mkdir_one(path) mkdir(path, 0700)
#endif

#include "manifest_v1.h"
#include "integrity.h"

/* A module record carries where its file comes from and what that file is:
   "package" ships inside the Workspace, "target" is resolved on the machine
   the application is installed on. */
#define MAIN_MODULE "module\tmain\tmain\tapp\toriginal\ttarget\t" \
    "0000000000000000000000000000000000000000000000000000000000000000\n"
#define PACKAGED_MODULE "module\tdep\tdependency\tlibdep.so\tscalar\tpackage\t" \
    "0000000000000000000000000000000000000000000000000000000000000000\n"
#define HEADERS \
    "# chimera-workspace-manifest-v2\n" \
    "# runtime_abi=1\n# target_os=linux\n# target_arch=riscv64\n" \
    "# target_arch_extension=rvv\n# runtime_scene="
#define ZERO_SHA "0000000000000000000000000000000000000000000000000000000000000000"

static FILE *fixture(void) {
    FILE *output;
    (void)mkdir_one("manifest-v1-fixture");
    (void)mkdir_one("manifest-v1-fixture/artifacts");
    output = fopen("manifest-v1-fixture/artifacts/modules.tsv", "w");
    assert(output); return output;
}

int main(void) {
    const char *root = "manifest-v1-fixture";
    FILE *output = fixture();
    struct chimera_manifest manifest;
    const struct chimera_manifest_variant_property *property;
    char fingerprint[CHIMERA_SHA256_TEXT_SIZE];
    fputs(HEADERS "linux_riscv64_rvv_v1\n"
          MAIN_MODULE
          "variant\tmain_v1024_v256\tmain\n"
          "variant-property\tmain_v1024_v256\tinput\tarchitecture\ttoken\triscv64\n"
          "variant-property\tmain_v1024_v256\tinput\tarchitecture_extension\ttoken\trvv\n"
          "variant-property\tmain_v1024_v256\tinput\tvector_vlen_bits\tu64\t1024\n"
          "variant-property\tmain_v1024_v256\toutput\tarchitecture\ttoken\triscv64\n"
          "variant-property\tmain_v1024_v256\toutput\tarchitecture_extension\ttoken\trvv\n"
          "variant-property\tmain_v1024_v256\toutput\tvector_vlen_bits\tu64\t256\n"
          "artifact\trisk\tmodule\tmain\tcontrol-flow-risk\tjson\t1\t-\tcustom/risk.json\t" ZERO_SHA "\n",
          output);
    fclose(output);
    assert(chimera_manifest_v1_read(root, &manifest));
    assert(manifest.module_count == 1 && manifest.variant_count == 1);
    assert(!strcmp(manifest.modules[0].delivery, "target"));
    assert(!strcmp(manifest.runtime_scene, "linux_riscv64_rvv_v1"));
    property = chimera_manifest_property_find(
        &manifest, "main_v1024_v256", "input", "vector_vlen_bits");
    assert(property && !strcmp(property->value, "1024"));
    assert(chimera_variant_fingerprint(
        &manifest, &manifest.variants[0], fingerprint));
    assert(!strcmp(
        fingerprint,
        "55061f6476f527472e025168d4ee025648465fceadceb7b6d114d308ec8b40bf"));
    assert(!chimera_manifest_artifact_requires(&manifest.artifacts[0], "runtime"));
    chimera_manifest_v1_destroy(&manifest);

    output = fixture();
    fputs(HEADERS "another_scene\n" MAIN_MODULE PACKAGED_MODULE, output);
    fclose(output);
    assert(chimera_manifest_v1_read(root, &manifest));
    assert(manifest.module_count == 2);
    assert(!strcmp(manifest.modules[1].delivery, "package"));
    chimera_manifest_v1_destroy(&manifest);

    /* The application is never packaged: it must run from where it is
       installed so its own path derivation keeps working. */
    output = fixture();
    fputs(HEADERS "linux_riscv64_rvv_v1\n"
          "module\tmain\tmain\tapp\toriginal\tpackage\t" ZERO_SHA "\n",
          output);
    fclose(output);
    assert(!chimera_manifest_v1_read(root, &manifest));

    output = fixture();
    fputs(HEADERS "linux_riscv64_rvv_v1\n"
          MAIN_MODULE "module\tmain\tmain\tapp\toriginal\telsewhere\t" ZERO_SHA "\n",
          output);
    fclose(output);
    assert(!chimera_manifest_v1_read(root, &manifest));

    output = fixture();
    fputs(HEADERS "linux_riscv64_rvv_v1\n"
          MAIN_MODULE "module\tdep\tdependency\tlibdep.so\tscalar\tpackage\tshort\n",
          output);
    fclose(output);
    assert(!chimera_manifest_v1_read(root, &manifest));

    output = fixture();
    fputs(HEADERS "linux_riscv64_rvv_v1\n"
          MAIN_MODULE
          "variant\tv\tmain\n"
          "variant-property\tv\tinput\tvector_vlen_bits\tu64\t01024\n",
          output);
    fclose(output);
    assert(!chimera_manifest_v1_read(root, &manifest));

    /* An artifact may not overwrite a packaged module's file. */
    output = fixture();
    fputs(HEADERS "linux_riscv64_rvv_v1\n"
          MAIN_MODULE PACKAGED_MODULE
          "artifact\tbad\tworkspace\troot\toptional\tjson\t1\t-\tscalar/libdep.so\t"
          ZERO_SHA "\n",
          output);
    fclose(output);
    assert(!chimera_manifest_v1_read(root, &manifest));

    /* A target-resolved module has no file inside the package, so its name is
       free in there. */
    output = fixture();
    fputs(HEADERS "linux_riscv64_rvv_v1\n"
          MAIN_MODULE
          "artifact\tcopy\tworkspace\troot\toptional\tjson\t1\t-\tscalar/app\t"
          ZERO_SHA "\n",
          output);
    fclose(output);
    assert(chimera_manifest_v1_read(root, &manifest));
    chimera_manifest_v1_destroy(&manifest);

    output = fixture();
    fputs(HEADERS "linux_riscv64_rvv_v1\n"
          "module\tmain\tmain\t..\toriginal\ttarget\t" ZERO_SHA "\n",
          output);
    fclose(output);
    assert(!chimera_manifest_v1_read(root, &manifest));

    output = fixture();
    fputs(HEADERS "linux_riscv64_rvv_v1\n"
          MAIN_MODULE
          "variant\tv\tmain\n"
          "variant-property\tv\tinput\tvector_vlen_bits\tu64\t+1024\n",
          output);
    fclose(output);
    assert(!chimera_manifest_v1_read(root, &manifest));

    output = fixture();
    fputs(HEADERS "linux_riscv64_rvv_v1\n"
          MAIN_MODULE
          "artifact\trisk\tmodule\tmain\tcontrol-flow-risk\tjson\t1\t-\tcustom/risk.json\t" ZERO_SHA "\textra\n",
          output);
    fclose(output);
    assert(!chimera_manifest_v1_read(root, &manifest));

    /* A module record with the old five fields no longer parses. */
    output = fixture();
    fputs(HEADERS "linux_riscv64_rvv_v1\n"
          "module\tmain\tmain\tapp\toriginal\n",
          output);
    fclose(output);
    assert(!chimera_manifest_v1_read(root, &manifest));

    output = fixture();
    fputs("# chimera-workspace-manifest-v1\n"
          "# runtime_abi=1\n# target_os=linux\n# target_arch=riscv64\n"
          "# target_arch_extension=rvv\n# runtime_scene=linux_riscv64_rvv_v1\n"
          MAIN_MODULE,
          output);
    fclose(output);
    assert(!chimera_manifest_v1_read(root, &manifest));

    output = fixture();
    fputs("# chimera-workspace-manifest-v7\n", output);
    fclose(output);
    assert(!chimera_manifest_v1_read(root, &manifest));

    output = fixture();
    fputs("# chimera-workspace-manifest-v8\n", output);
    fclose(output);
    assert(!chimera_manifest_v1_read(root, &manifest));
    return 0;
}
