# Bootstrap across fork and exec

Final acceptance (2026-10-15): passed on
`6.18.3-chimera-bootstrap-exec`, branch
`feature/chimera-bootstrap-exec-inheritance`. The make-launched matrix passed
all seven thread counts; ten 16-thread rounds passed; the mixed-size loop
passed 49 cases over 7295.72 seconds. All 66 cases exited successfully, stayed
within the 0.1% PPL tolerance (native 29.7254; observed 29.7239-29.7296;
maximum relative error 0.01413%), and left zero assigned/pending/reservation
counts. Aggregate commits were 126 X100-to-A100 and 2106 A100-to-X100.
There were no migration timeouts or kernel warning-scan alerts. The separate
reduced RVV test passed 90 child exits/checksums, and rebuilt make itself
was observed migrating. `acceptance-offline-no-crt-v2/final-audit.json`
records the completed audit; `results.json` contains every case.

This acceptance uses scalar control code with explicit RVV ggml kernels,
OpenMP enabled and OpenSSL disabled for the local model/text workload.
It does not establish safe native reentry for arbitrary VLEN-derived live
caller scalars, nor support for arbitrary unprocessed executables.

The following sections include implementation details and earlier diagnostic runs.

The generic `libchimera-bootstrap.so` remains in `LD_PRELOAD` across ordinary
dynamic ELF exec. Each new image selects its own workspace from
`CHIMERA_REGISTRY`; the parent's workspace is not reused. Programs absent from
the registry, including shells and build helpers, run without migration readiness.

Build the bootstrap independently of a workspace:

```sh
cmake -S runtime -B build/bootstrap -DCHIMERA_BUILD_BOOTSTRAP=ON
cmake --build build/bootstrap -j8
```

Publish each prepared child after installing its verified workspace:

```sh
chimera-user bootstrap-register --input /absolute/path/child \
  --workspace /absolute/path/child-workspace \
  --registry /run/chimera/workspaces.tsv
```

Launch the final test through make:

```sh
chimera-user run --registry /run/chimera/workspaces.tsv \
  --bootstrap /absolute/path/libchimera-bootstrap.so --automigrate \
  make -j8 -C /absolute/path/project
```

`--automigrate` requires the matching kernel's `inherit:TID` proc interface.
`ready:TID` publishes a prepared image only for current-process-group threads
whose kernel preference is already enabled; it cannot re-enable disabled
policy. The kernel flag is authoritative, without another inherited opt-in
environment flag. Threads created by earlier constructors are also enumerated.
Omit `--automigrate` for initialization tests from an unmarked launcher.
The runtime is loaded only after
the executable and runtime hashes match. It checks all recorded modules against
the actual native loader images before installing migration handlers. A
workspace prepared against different libc/loader files must be prepared again.
Bootstrap mode executes the application with its native interpreter; it cannot
retroactively substitute packaged libc after the loader has already loaded it.
Prepare with a native profile whose `scalar_root` points to an empty directory:
all dependencies must describe their actual target files. Re-running prepare
with a populated scalar root still selects those replacement files.

The launcher retains unrelated `GLIBC_TUNABLES` and reserves at least 64 KiB of
optional static TLS per thread. The current runtime requires 8384 bytes and
translated DSOs use initial-exec TLS relocations; loading them later with glibc's
default 512-byte reserve fails. A direct launch outside the Chimera launcher
must set `GLIBC_TUNABLES=glibc.rtld.optional_static_tls=65536` before exec as well.

Registry v1 starts with `chimera-registry-v1`, followed by five tab-separated
columns: absolute executable path, executable SHA-256, absolute workspace path,
absolute runtime path, runtime SHA-256. Publication is locked and atomically
replaced. Duplicate matches, malformed records, stale hashes, and initialization
failures leave the image unready. Only one runtime may initialize an image.
Use `CHIMERA_BOOTSTRAP_TRACE=1` to report successful initialization.
Registry publication verifies the complete workspace and artifact hashes but
does not require the legacy pinned BPF map. Runtime initialization and the
proc readiness API provide the bootstrap path's admission gate.

The constructor does not run after fork without exec. Such children inherit
the existing image's mappings and signal dispositions; kernel proposal and
reservation state is separately reset. vfork executes no bootstrap until exec.
An exec that fails before the point of no return preserves the old image.
Static ELF, secure-exec and launches that discard the environment do not provide
preload inheritance; the matching kernel keeps inherited policy unready.
Applications must preserve the runtime's reserved signal dispositions.

## Implementation and evidence, 2026-10-13

User and kernel branches: `feature/chimera-bootstrap-exec-inheritance`.
User implementation starts at the automigration branch and merges user mainline
through `865d6ca7d` (2026-10-14); original uncommitted changes remain separate. Kernel
implementation starts at `b3c91312b` and carries the scheduler-only unfrozen
changes, excluding Windows case-collision changes.

Passed: bootstrap/real runtime builds, 11 C contract tests, and 27 launcher,
notification, CLI and bootstrap Python tests. The make lifecycle fixture uses
a stub runtime and proves constructor re-registration, not RVV migration.
The native hello workspace was regenerated without scalar substitutions, and
make and its real RVV child both logged successful runtime initialization with
matching checksums after the TLS reservation fix.

System `/usr/bin/make` failed `safety.stack-liveness` (three local unproven
functions and inherited findings). GNU make 4.4.1 was rebuilt with the bundled
heap alloca fallback and the patches under `examples/applications/gnu-make`.
That make passed the conservative safety check, completed bidirectional native
prepare, and passed 1431 upstream tests in 133 categories as an unprivileged
user. The original root-run suite's two permission-test failures were caused
by root bypassing inaccessible temporary-directory permissions. The old hello
workspace was rejected because
its libc/loader hashes differ from the current system. A correct application
checksum alone does not prove bootstrap initialization.

Matching kernel objects and full Image/modules builds passed in an isolated
board tree, using the separate `6.18.3-chimera-bootstrap-exec` release. Fork
first placement keeps its source VLEN group, and expired reservation owner
references remain visible to cleanup checks.
The approved deployment booted `6.18.3-chimera-bootstrap-exec` successfully.
The exec inheritance selftest passed. Rebuilt make itself committed one X100
to A100 migration and then launched the registered RVV child with a matching
checksum. A separate nine-child reduced test launched through make committed
two A100 to X100 migrations and one X100 to A100 migration; all nine checksums
matched, with no NACK or timeout. Assigned, pending and reservation counts
returned to zero after exit, and no kernel BUG/WARNING was found. The eleven C
tests and twenty-seven focused Python tests passed on the new kernel, including
registry publication when the legacy pinned BPF map is absent.

The real llama native workspace completed conservative safety analysis and
bidirectional preparation. The make-launched 2/4/8/12/16/24/32-thread matrix
passed, with PPL 29.7239 through 29.7280, clean ledgers/reservations after every
exit, no timeout and no new kernel alerts. This is not bit-identical PPL across
thread counts. Ten 16-thread rounds also passed. The two-hour mixed loop
stopped at its second case with a llama output-count assertion; a diagnostic
repeat captured a core showing retained VLEN-derived scalar control state.
See `BOOTSTRAP-NATIVE-BASELINE.md`. That earlier baseline did not pass acceptance. The corrected scalar
control baseline subsequently passed the complete sequence recorded above. Keep make as the outer
test entry point.

The corrected scalar-control llama passed the conservative check. Subsequent
preparation and reduced tests exposed two additional issues, now fixed:
stripped internal labels containing `@plt+offset` must not be classified as PLT
entries, and generated translated DSOs must omit CRT initialization/finalization
callbacks (`-nostartfiles`). The latter prevented reverse translated loader
shutdown from rejecting a generated opposite-variant finalizer. Cross-variant
rejection remains enabled. Translator regression: 1586 passed, 287 skipped;
both offset-label fixtures also assembled as RISC-V shared objects. Ten reduced
nine-child rounds passed (90 exits/checksums, 20 A100-to-X100 and 13 reverse
migrations), with all inheritance/readiness gates set, final ledgers and
reservations zero, and no kernel warnings. Final offline/OpenMP llama safety
and preparation completed with these fixes. Native reference PPL is 29.7254;
the full 2/4/8/12/16/24/32 matrix and ten 16-thread rounds passed, with all exits
and cleanup checks passing, no timeout and no new kernel warnings. The two-hour
mixed loop and final audit subsequently passed, including the 4-thread stage
that failed in the previous baseline. See `BOOTSTRAP-NATIVE-BASELINE.md`
for the scalar-control compilation constraint and offline dependency scope.
