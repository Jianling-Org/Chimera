# GNU make as the final bootstrap and migration test

Build GNU make 4.4.1 from its official source archive. Apply both patches with
`patch -p1`; keep `heap-alloca.h` available at an absolute path. The first patch
gives archive/load name buffers explicit ownership; the second enables GNU's
bundled automatically reclaimed heap alloca fallback, with one chain per thread.
OOM/size overflow aborts rather than calling the fallback's missing callback.

Configure with ordinary flags so forced headers do not contaminate Autoconf
preprocessor probes:

```sh
ac_cv_working_alloca_h=no ac_cv_func_alloca_works=no \
CC=/path/to/patched/clang CFLAGS='-O2 -g -march=rv64gcv -mabi=lp64d' \
  ./configure --without-guile
task_make_cflags='-O2 -g -march=rv64gcv -mabi=lp64d'
task_make_cflags+=' -fno-vectorize -fno-slp-vectorize'
task_make_cflags+=' -DCHIMERA_MAKE_HEAP_ALLOCA -DSTACK_DIRECTION=-1'
task_make_cflags+=' -include /absolute/path/heap-alloca.h'
task_make_cflags+=' -fpass-plugin=/path/to/ChimeraStackObject.so'
make -j8 CFLAGS="$task_make_cflags"
```

Use `check-elf` and `prepare` with a bidirectional native profile that disables
scalar replacement by selecting an empty `scalar_root`. Never use the
`--allow-problematic` override for this acceptance target. Publish make and
every prepared recipe program to the same bootstrap registry. The final command
uses the rebuilt make path, so recursive `$(MAKE)` also re-enters bootstrap.

Run GNU's tests as an unprivileged user from the `tests` directory:

```sh
perl ./run_make_tests.pl -srcdir /absolute/path/make-source \
  -make /absolute/path/rebuilt/make
```

On K3 the rebuilt make passed the conservative safety check and 1431 upstream
tests in 133 categories, and both make and its RVV child completed actual
bootstrap initialization. Their physical migration and kernel lifecycle tests
were exercised after booting the matching kernel. The scalar-control rebuild
also passed 1431 upstream tests; its final migration acceptance is recorded in
`docs/BOOTSTRAP-EXEC-INHERITANCE.md`.

Keep the disable options after the optimization option: the patched Clang's
later `-O2`/`-O3` option can re-enable automatic vectorization. Explicit RVV
intrinsics are unaffected. This avoids control code caching a VLEN-derived
stride across a callee that changes the physical VLEN before native reentry.
