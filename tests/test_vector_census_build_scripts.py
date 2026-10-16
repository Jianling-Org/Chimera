from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = (
    ROOT / "examples" / "scripts" / "build" / "build_llamacpp.sh",
    ROOT / "examples" / "scripts" / "build" / "build_llamacpp_stats.sh",
)


class VectorCensusBuildScriptTests(unittest.TestCase):
    def test_stats_owns_clean_first_census_report(self):
        text = SCRIPTS[1].read_text(encoding="utf-8")
        self.assertIn("--clean-first", text)
        self.assertIn("vector_census_report.py", text)
        self.assertIn("implicit_vector_census.tsv", text)

    def test_main_build_has_no_novec_or_final_census_phase(self):
        text = SCRIPTS[0].read_text(encoding="utf-8")
        for retired in (
            "BUILD_NOVEC",
            "ELF_NOVEC",
            "相位A",
            "相位C",
            "_final_gate_census",
            "FINAL_GATE_CENSUS",
            "FINAL_GATE_NAMES",
            "--clean-census",
            "vector_census_report.py",
            "implicit_vector_census.tsv",
        ):
            self.assertNotIn(retired, text, retired)

    def test_main_build_orders_vanilla_repair_then_prepare(self):
        text = SCRIPTS[0].read_text(encoding="utf-8")
        vanilla_check = text.index('$CHIMERA_PKG check-elf --profile "$SAFETY_PROFILE" --input "$ELF_VANILLA"')
        remediation = text.index('_remediate_loop "$BUILD_REMEDIATED"', vanilla_check)
        gate_checked = text.index('echo "[$phase] Gate 复检 -> CHECKED"')
        prepare = text.index('echo "prepare [$scenario]')
        self.assertLess(vanilla_check, remediation)
        self.assertLess(gate_checked, prepare)
        self.assertLess(remediation, prepare)
        self.assertNotIn('cmake --build "$BUILD_REMEDIATED"', text[gate_checked:])
        self.assertNotIn("最终 gate census", text)
        self.assertIn('d.get("stack_object_plugin")', text)

    def test_release_components_stop_before_prepare_and_force_static_libraries(self):
        text = SCRIPTS[0].read_text(encoding="utf-8")
        self.assertIn('RELEASE_COMPONENT="${CHIMERA_RELEASE_COMPONENT:-}"', text)
        release_end = text.index("# ---------------------------------------------------------------\n# 迁移场景 workspace")
        self.assertLess(text.index('RELEASE_COMPONENT" == "system"'), release_end)
        self.assertLess(text.index('RELEASE_COMPONENT" == "remediated"'), release_end)
        self.assertIn("-DBUILD_SHARED_LIBS=OFF", text)
        self.assertIn("-DLLAMA_BUILD_SHARED_LIBS=OFF", text)
        self.assertIn("-DGGML_STATIC=ON", text)
        self.assertIn("-DGGML_SHARED=OFF", text)

    def test_release_system_exits_before_workflow_check(self):
        text = SCRIPTS[0].read_text(encoding="utf-8")
        delivery = text.index('echo "release system ELF: $RELEASE_OUTPUT"')
        early_exit = text.index('exit 0', delivery)
        check = text.index('$CHIMERA_PKG check-elf --profile "$SAFETY_PROFILE" --input "$ELF_VANILLA"')
        self.assertLess(early_exit, check)
        self.assertNotIn('for scenario_profile in', text)

    def test_old_multi_face_reports_are_gone(self):
        retired = (
            "跨面对照",
            "插件汇总",
            "二进制 v 指令差分",
            "vectorizer-census",
            "memop-census",
            "merge-census",
            "gate_stats.jsonl",
        )
        for path in SCRIPTS:
            text = path.read_text(encoding="utf-8")
            for marker in retired:
                with self.subTest(path=path.name, marker=marker):
                    self.assertNotIn(marker, text)

    def test_patched_clang_builds_isolate_system_llvm_openmp_header(self):
        common = (ROOT / "examples" / "scripts" / "build" / "_common.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("detect_chimera_openmp", common)
        self.assertIn("OpenMP_omp_LIBRARY", common)
        self.assertNotIn("-idirafter", common)
        self.assertIn("CHIMERA_OPENMP_INCLUDE_DIR", common)
        self.assertIn('ln -sfn -- "$header" "$include_dir/omp.h"', common)
        self.assertIn("-isystem $include_dir", common)
        self.assertIn("-DGGML_OPENMP=ON", common)
        self.assertIn("CHIMERA_OPENMP_LIBRARY", common)
        self.assertIn("CHIMERA_OPENMP_RUNTIME_PACKAGE", common)
        self.assertIn('dpkg-query -L "$runtime_package"', common)
        self.assertIn('if [[ -z "$header" || -z "$library" ]]', common)
        self.assertNotIn("/usr/lib/llvm-21", common)
        self.assertNotIn("/usr/lib/riscv64-linux-gnu", common)
        for path in SCRIPTS:
            text = path.read_text(encoding="utf-8")
            self.assertIn("detect_chimera_openmp", text)
            self.assertIn('"${CHIMERA_OPENMP_CMAKE_ARGS[@]}"', text)

    def test_both_scripts_run_toolchain_probe_before_build(self):
        common = (ROOT / "examples" / "scripts" / "build" / "_common.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("verify_chimera_implicit_vector_census_toolchain", common)
        self.assertIn("implicit-vector-census\\tLV\\tchimera_probe_lv\\tblocked", common)
        self.assertIn("implicit-vector-census\\tMEMOP\\tchimera_probe_memop\\tblocked", common)
        for path in SCRIPTS:
            text = path.read_text(encoding="utf-8")
            self.assertIn("verify_chimera_implicit_vector_census_toolchain", text)

    def test_main_build_does_not_retry_gate_after_failed_check(self):
        text = SCRIPTS[0].read_text(encoding="utf-8")
        self.assertNotIn("CHIMERA_MAX_ROUNDS", text)
        self.assertNotIn("while : ; do", text)
        self.assertIn("单轮 gate", text)

    def test_bootstrap_is_shared_and_runs_before_openmp_detection(self):
        common = (ROOT / "examples" / "scripts" / "build" / "_common.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("bootstrap_llamacpp_dependencies()", common)
        self.assertIn("ensure_chimera_submodule", common)
        for path, mode in ((SCRIPTS[0], "full"), (SCRIPTS[1], "stats")):
            text = path.read_text(encoding="utf-8")
            bootstrap = text.index("bootstrap_llamacpp_dependencies")
            openmp = text.index("detect_chimera_openmp")
            self.assertLess(bootstrap, openmp, path.name)
            self.assertRegex(
                text,
                rf"bootstrap_llamacpp_dependencies\s+{mode}",
                path.name,
            )

    def test_bootstrap_policy_is_noninteractive_and_mode_specific(self):
        main = SCRIPTS[0].read_text(encoding="utf-8")
        stats = SCRIPTS[1].read_text(encoding="utf-8")
        common = (ROOT / "examples" / "scripts" / "build" / "_common.sh").read_text(
            encoding="utf-8"
        )
        for text in (main, stats):
            self.assertNotIn('read -r -p "现在执行 git submodule update', text)
        self.assertEqual(common.count("plugins=(stackobject vector-gate)"), 2)
        self.assertNotIn('bootstrap_llamacpp_dependencies full', stats)
        self.assertNotIn('toolchain build svf', stats)

    def test_clean_submodule_is_not_reported_as_dirty(self):
        common = (ROOT / "examples" / "scripts" / "build" / "_common.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'git -C "$path" diff --quiet 2>/dev/null || return 0', common
        )
        self.assertIn(
            'git -C "$path" diff --cached --quiet 2>/dev/null || return 0', common
        )
        self.assertNotIn('! git -C "$path" diff --quiet', common)
        self.assertNotIn('! git -C "$path" diff --cached --quiet', common)

    def test_run_scripts_use_single_migration_contract(self) -> None:
        run_dir = ROOT / "examples" / "scripts" / "run"
        one_way = (
            run_dir / "run_llamacpp_1024_to_256.sh",
            run_dir / "run_llamacpp_256_to_1024.sh",
        )
        migrate_command = (
            '$CHIMERA_USER migrate --workspace "$WORKSPACE" --parent-thread "$TID" '
            '--migration-count "$MIGRATION_COUNT" --direction "$DIRECTION"'
        )
        for path in one_way:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertEqual(text.count(migrate_command), 1)
                self.assertNotIn("MIGRATE_INTERVAL", text)
                self.assertNotIn("ONLY_ONCE", text)
                self.assertNotIn("while kill -0", text)
                self.assertNotIn("补迁", text)
                self.assertIn('if ! kill -0 "$RUN_PID"', text)
                self.assertIn('if wait "$RUN_PID"; then', text)

        bidirectional = (run_dir / "run_llamacpp_1024_256_bidirectional.sh").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            bidirectional.count('$CHIMERA_USER migrate --workspace "$WORKSPACE"'), 2
        )

        scheduler = (run_dir / "run_llamacpp_scheduler.sh").read_text(encoding="utf-8")
        self.assertNotIn(" migrate ", scheduler)

        for path in (
            ROOT / "doc/developer/architecture/targets/rvv/README.md",
            ROOT / "doc/user/cli.md",
        ):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertNotIn("MIGRATE_INTERVAL", text)
                self.assertNotIn("ONLY_ONCE", text)
                self.assertNotIn("周期补迁", text)
                self.assertNotIn("周期性 `migrate`", text)
                self.assertNotIn("MIGRATE_ROUNDS", text)

    def test_scalar_install_is_limited_to_full_bootstrap(self):
        common = (ROOT / "examples" / "scripts" / "build" / "_common.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("install_llamacpp_scalar", common)
        self.assertRegex(common, r'if \[\[ "\$mode" == "full" \]\]; then\s+install_llamacpp_scalar')

    def test_bootstrap_requires_current_cli_and_does_not_auto_install(self):
        common = (ROOT / "examples" / "scripts" / "build" / "_common.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("make develop", common)
        self.assertIn("command -v chimera-pkg", common)
        self.assertNotIn("pip install -e", common)

    def test_patch_trap_is_registered_before_apply_and_dirty_tree_is_rejected(self):
        for path in SCRIPTS:
            text = path.read_text(encoding="utf-8")
            self.assertIn("diff --quiet", text, path.name)
            trap = text.index("trap _on_exit EXIT") if "_on_exit" in text else text.index("trap llama_patch_restore EXIT")
            apply = text.index("llama_patch_apply\n", trap)
            self.assertLess(trap, apply, path.name)
            apply_body = text[text.index("llama_patch_apply()"):text.index("llama_patch_restore()")]
            self.assertNotIn("checkout -- .", apply_body, path.name)
            self.assertNotIn("checkout -- .", text, path.name)
            self.assertIn("LATEST_BACKUP", text, path.name)
            self.assertIn("cp \"$LATEST_BACKUP\" \"$LATEST_POINTER\"", text, path.name)

    def test_main_rejects_function_pointer_route_without_lto_capacity_probe(self):
        common = (ROOT / "examples" / "scripts" / "build" / "_common.sh").read_text(
            encoding="utf-8"
        )
        main = SCRIPTS[0].read_text(encoding="utf-8")
        self.assertIn("check_chimera_lto_capacity", common)
        self.assertIn("MemAvailable", common)
        self.assertIn("SwapTotal", common)
        self.assertIn("不支持 FP/LTO 路线", main)
        self.assertNotIn("check_chimera_lto_capacity", main)
        self.assertNotIn("ensure_temp_swap", main)
        self.assertNotIn("swapon", main)

    def test_stats_has_explicit_function_pointer_dependency_failure(self):
        text = SCRIPTS[1].read_text(encoding="utf-8")
        self.assertIn("function_pointer_plugin", text)
        self.assertIn("ensure_stats_decision_dependencies", text)



if __name__ == "__main__":
    unittest.main()
