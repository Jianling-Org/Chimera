# Native bootstrap acceptance baseline

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

The 2026-10-14 native llama acceptance exposed a bidirectional reentry limit:
automatically vectorized control code can retain scalar values derived from
`vlenb` across calls. Returning from a translated callee to original code on
the other CPU group does not recompute those values.

Evidence: two 4-thread runs aborted at `llama-context.cpp:1898`. The captured
core contains total outputs 768 and current microbatch outputs 1020. Decode's
saved stride is 16 (`vlenb / 2`, corresponding to 256 bits), while the main
thread's vector core note records `vlenb=128` (1024 bits). Its vectorized
counting loop uses hardware VLMAX with that retained scalar stride. The native
control run without automigration passed with PPL 29.7254. The three debug
runs passed; their 33 initial vector-save records did not demonstrate a
queued/frame VL mismatch. Treat the latter as a separate protocol audit,
not as a proven cause of the abort.

For this acceptance baseline, disable automatic loop/SLP vectorization while
retaining the explicit RVV math kernels and all existing application fixes:

```sh
cmake -S llama-source -B llama-build \
  -DCMAKE_BUILD_TYPE=Release -DGGML_RVV=ON -DGGML_OPENMP=ON -DLLAMA_OPENSSL=OFF \
  -DCMAKE_C_COMPILER=/path/to/patched/clang \
  -DCMAKE_CXX_COMPILER=/path/to/patched/clang++ \
  '-DCMAKE_C_FLAGS=-march=rv64gcv -fpass-plugin=/path/to/ChimeraStackObject.so' \
  '-DCMAKE_CXX_FLAGS=-march=rv64gcv -fpass-plugin=/path/to/ChimeraStackObject.so' \
  '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fno-vectorize -fno-slp-vectorize' \
  '-DCMAKE_CXX_FLAGS_RELEASE=-O3 -DNDEBUG -fno-vectorize -fno-slp-vectorize' \
  '-DOpenMP_C_FLAGS=-fopenmp -isystem /path/to/system-openmp/include' \
  '-DOpenMP_CXX_FLAGS=-fopenmp -isystem /path/to/system-openmp/include' \
  -DOpenMP_C_LIB_NAMES=omp -DOpenMP_CXX_LIB_NAMES=omp \
  -DOpenMP_omp_LIBRARY=/usr/lib/riscv64-linux-gnu/libomp.so.5
```

The flag-only build still failed the conservative check with 28 local-root
findings (615 including inherited findings). Flags alone are insufficient.
For the next candidate, append this after target creation in the application
root CMakeLists, then configure and build again:

```cmake
foreach(chimera_control_target llama llama-common llama-common-base cpp-httplib llama-perplexity-impl llama-perplexity)
    if(TARGET ${chimera_control_target})
        target_compile_options(${chimera_control_target} PRIVATE -march=rv64gc)
    endif()
endforeach()
```

This leaves ggml-cpu's explicit RVV kernels enabled. This candidate is not yet
accepted; it must pass the conservative check before workspace preparation.
The reusable fragment is `examples/applications/llama-cpp/scalar-control.cmake`.
The first scalar-control build omitted cpp-httplib and still had five findings
(two local roots, three inherited); the corrected target list includes it.

Option order matters: a later optimization flag re-enabled vectorization in
the observed toolchain. Verify that decode no longer reads `vlenb`, then run
conservative `check-elf`, full bidirectional native `prepare`, and registry
publication again. Never reuse a workspace after changing the executable.

This compilation configuration addresses the observed control loop. It does
not establish general safety for native reentry with arbitrary live
VLEN-derived scalar values in callers. General support needs scalar-liveness
or frame guards before permitting that reentry. Keep this limitation visible
when reviewing the bootstrap feature.

2026-10-14 continuation: user mainline `865d6ca7d` was merged before new
workspace generation; kernel mainline remains `2838fbc3c`. Source translator
regression: 1584 passed, 287 skipped. Eleven C contracts and 27 focused
launcher/bootstrap tests passed. Updated carried PLT tests require resolved
IFUNC GOT slots rather than inferring public names from resolver names, and
assert the actual fail-closed trap instead of its former comment text.
`make-scalar-865d` preparation completed. Its standalone make smoke committed
one X100-to-A100 migration, with one prepare/safepoint NACK, no timeout and
zero assigned/pending/reservation counts after exit. The initial scalar-control
llama check failed on the omitted cpp-httplib module; the corrected v2 check
is running. Board evidence `fix-httplib-control.py` runs it,
requires every check to pass, then prepares fresh hello/llama workspaces and
runs reduced, matrix, ten-round and two-hour tests in new evidence paths.
The original pipeline stopped at its safety assertion. The v2 pipeline is
launched only after the corrected safety report passes. An independent
`reduced-scalar-preflight.py` waits for fresh hello preparation to test the
nine-child inheritance chain while llama analysis runs.

The corrected v2 scalar-control binary passed the conservative safety check.
Its first preparation stopped on libcrypto's stripped `.text` labels: GNU
objdump prints names such as `dlclose@plt+0x17a2` for ordinary internal code.
PLT classification now requires an exact `@plt` suffix, preserving offset
labels as internal code. Both-direction regression tests cover the real label
shape; translator regression is now 1586 passed, 287 skipped.

The first new hello test exposed an independent shutdown failure. The reverse
translated loader's finalizer call at translated ELF offset `0x117e` rejected
a cross-variant callback. Generated translated DSOs carried CRT-provided
`__do_global_dtors_aux` callbacks inside their classified translated ranges.
Generated code/provenance libraries now link with `-nostartfiles`; application
constructors/destructors and fail-closed cross-variant checks are unchanged.
Six rebuilt hello variants have no INIT/FINI/INIT_ARRAY/FINI_ARRAY tags.
Ten nine-child rounds then passed: 90 successful exits with matching checksums,
20 A100-to-X100 and 13 X100-to-A100 migrations, no timeout, final ledgers and
reservations zero, and no kernel warnings. This is the reduced test, not the
required ten rounds of 16-thread llama.

`no-crt-acceptance-pipeline.py` is rebuilding make and llama using both fixes
before repeating final acceptance. Full acceptance is still open. Old llama
generated assembly/dumps are archived with per-file SHA verification under
`bootstrap-evidence/llama-native-verified-intermediates.tar.gz`; restore them
to the old workspace before using those diagnostic producer intermediates.
Old binaries, runtime artifacts, core and logs remain available.

The new `make-no-crt` workspace completed and its own smoke test committed one
X100-to-A100 migration with no NACK/timeout and zero final ledger/reservation
counts. `llama-no-crt` preparation is running; the queued complete acceptance
uses `no-crt-registry.tsv` and `acceptance-no-crt`, preserving earlier failures.

2026-10-15 continuation: restored the local board SSH stunnel (the board itself
remained on the test kernel). The no-CRT llama preparation stopped while
assembling libcrypto: its stripped/system disassembly includes versioned
symbol-offset branches and non-reassemblable data/instruction fragments.
Do not treat the earlier PLT-label regression fix as general libcrypto support.
The original remediated acceptance binary has no OpenSSL dependency. The
replacement `llama-offline-scalar` build explicitly uses `LLAMA_OPENSSL=OFF`,
appropriate to this local model/text workload, and keeps explicit RVV math.
Its separate pipeline `build-offline-scalar.py` rebuilds, checks that SSL/crypto
are absent from DT_NEEDED, runs conservative safety, prepares the fresh
`llama-offline-no-crt` workspace, then repeats complete make-launched acceptance
under `acceptance-offline-no-crt` with `offline-no-crt-registry.tsv`.
The unsuccessful TLS-enabled binary and preparation logs remain preserved.
User mainline `b8c6b7c72` was merged; the intervening change/revert pair has no
net tree change from `865d6ca7d`. Kernel mainline remains `2838fbc3c`.
The first offline configure silently set `GGML_OPENMP_ENABLED=OFF` despite the
requested `GGML_OPENMP=ON`. That binary/cache were preserved separately and its
check stopped. The rebuild explicitly supplies the original baseline's OpenMP
header/runtime paths and requires both `GGML_OPENMP_ENABLED=ON` and libomp in
DT_NEEDED. `enable-offline-openmp.py` runs the corrected build/check/preparation
and acceptance. Acceptance now first runs a non-migrating reference pinned to
A100 CPUs 8-15, then requires migrated PPL within 0.1% of that reference in
addition to exit/bootstrap, cleanup, timeout and kernel-warning checks.
The corrected offline/OpenMP executable SHA256 is
`5a383f0849675d64a07dfa63060aab70e30a752889ad25ed80e65cea020add46`.
Code-generation verification found zero `vlenb` reads in decode, while retaining
2319 `vsetvli`, 351 `vle32.v` and 86 `vfmacc.vv` instructions in the binary.
Conservative safety analysis and the complete acceptance sequence subsequently
passed; code-generation inspection alone was not used as acceptance.

The corrected binary subsequently passed conservative safety and completed
`llama-offline-no-crt` preparation. The make-launched reduced test also passed.
The first full-acceptance attempt stopped before inference because a regular
group launcher could not set affinity directly to CPUs 8-15. The harness now
selects A100 with `/proc/set_ai_thread` before taskset; no migration-policy
or runtime guard was relaxed. New evidence is `acceptance-offline-no-crt-v2`.
Native reference PPL is 29.7254, with all sampled threads pinned to 8-15 and
Prefer_a100=0. The first make-launched 2-thread case passed in 322.93 seconds,
PPL 29.7254 (relative error zero), 31 A100-to-X100 and 12 X100-to-A100 commits,
no timeout, zero final ledgers/reservations and no new kernel alerts. Its sampled
threads all had preference, runtime-ready and strict exec-ready gates enabled.
All remaining cases subsequently passed. `audit-after-runner.py` waits for this runner and
invokes `audit-final-acceptance.py`; the latter verifies all matrix/ten-round
cases, the two-hour loop, PPL tolerance, both migration directions, cleanup and
kernel warnings before writing `final-audit.json`.

Current complete-prefix evidence: all seven matrix cases and all ten 16-thread
rounds passed. PPL range through the first mixed case is 29.7244-29.7285;
maximum relative deviation from the native reference is approximately 0.01043%,
below the declared 0.1% bound. All recorded exits and post-exit ledgers passed,
with no timeout or new kernel alert. The mixed loop's second case (4 threads),
which failed in the old baseline, now passed in 187.31 seconds at PPL 29.7254,
38 A100-to-X100 and eight X100-to-A100 commits, zero final ledger/reservations.
The remainder of the two-hour loop and final audit subsequently passed, as recorded above.
