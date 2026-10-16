"""chimera-pkg llvm wrapper: mode detection, injection matrix, state transition."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from chimera import llvm_wrapper as wrapper_module

from chimera.elf_state import (
    CHECKED,
    PROBLEMATIC,
    REMEDIATED,
    UNCHECKED,
    ElfStateRegistry,
)
from chimera.llvm_wrapper import (
    _detect_mode,
    _is_probe,
    _output_target,
    _write_gate_names,
    run_llvm_wrapper,
)

FAKE_CLANG = """#!/bin/sh
printf '%s\\n' \"$@\" > \"$CHIMERA_RECORD\"
exit 0
"""


class ModeDetectionTests(unittest.TestCase):
    def test_compile_mode(self):
        self.assertEqual(_detect_mode(["-c", "-o", "a.o", "a.c"]), "compile")

    def test_link_mode(self):
        self.assertEqual(
            _detect_mode(["a.o", "b.o", "-o", "app", "-flto"]), "link"
        )

    def test_passthrough_mode(self):
        self.assertEqual(_detect_mode(["--version"]), "passthrough")

    def test_output_target_plain_and_glued(self):
        self.assertEqual(_output_target(["-o", "app"]), Path("app"))
        self.assertEqual(_output_target(["-oapp"]), Path("app"))
        self.assertIsNone(_output_target(["-c", "x.c"]))


class ProbeDetectionTests(unittest.TestCase):
    """autoconf 探针必须被认出来：它们的判据是 stderr，不是退出码。"""

    def test_preprocess_probe(self):
        self.assertTrue(_is_probe(["-E", "conftest.c"]))

    def test_conftest_compile_probe(self):
        self.assertTrue(_is_probe(["-c", "conftest.c", "-o", "conftest.o"]))

    def test_conftest_link_probe(self):
        self.assertTrue(_is_probe(["-o", "conftest", "conftest.c"]))

    def test_real_translation_unit_is_not_a_probe(self):
        self.assertFalse(
            _is_probe(
                [
                    "-c",
                    "-DHAVE_CONFIG_H",
                    "-o",
                    "fibheap.o",
                    "/src/libiberty/fibheap.c",
                ]
            )
        )
        # 目录里带 conftest 字样不算：只看输入文件的 basename
        self.assertFalse(_is_probe(["-c", "conftest_dir/real.c", "-o", "real.o"]))
        self.assertFalse(_is_probe(["-flto", "-o", "app", "a.o", "b.o"]))


class GateNamesPublicationTests(unittest.TestCase):
    def test_gate_names_are_sorted_and_atomically_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            decision_path = Path(directory) / "app.check.json"
            target = _write_gate_names(
                str(decision_path),
                {"gate": {"names": ["_Z3zedv", "_Z3alphav"]}},
            )

            self.assertEqual(
                target.read_text(encoding="utf-8"),
                "_Z3alphav\n_Z3zedv\n",
            )
            self.assertEqual(list(target.parent.glob(f".{target.name}.*")), [])

    def test_unchanged_gate_names_keep_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            decision_path = Path(directory) / "app.check.json"
            target = _write_gate_names(
                str(decision_path), {"gate": {"names": ["_Z3foov"]}}
            )
            before = target.stat().st_mtime_ns
            rewritten = _write_gate_names(
                str(decision_path), {"gate": {"names": ["_Z3foov"]}}
            )

            self.assertEqual(rewritten, target)
            self.assertEqual(target.stat().st_mtime_ns, before)


class FixedBuildPlanWrapperTests(unittest.TestCase):
    """Run wrapper policy on every host; only the compiler process is mocked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin_dir = self.root / "bin"
        self.plugins = self.root / "plugins"
        self.bin_dir.mkdir()
        self.plugins.mkdir()
        for name in ("clang", "clang++"):
            (self.bin_dir / name).write_bytes(b"compiler")
        for name in ("ChimeraStackObject.so", "ChimeraVectorGate.so"):
            (self.plugins / name).write_bytes(b"plugin")
        self.decision_path = self.root / "decision.json"
        self.decision = {
            "strategy": "none", "stack_object_plugin": True,
            "function_pointer_plugin": False,
            "gate": {"enabled": False, "names": []},
        }
        self.decision_path.write_text(json.dumps({"decision": self.decision}), encoding="utf-8")
        self.loader = mock.Mock(return_value=(self.decision, self.decision_path))
        self.addCleanup(mock.patch.stopall)
        mock.patch.dict("sys.modules", {
            "chimera.compiler_plan": SimpleNamespace(load_rebuild_plan=self.loader),
        }).start()
        mock.patch.object(wrapper_module, "_toolchain_paths", return_value=(self.bin_dir, self.plugins)).start()
        self.latest = mock.patch.object(wrapper_module, "load_latest_pointer", side_effect=AssertionError("latest must not be read")).start()
        self.compiler = mock.patch.object(wrapper_module.subprocess, "run", return_value=SimpleNamespace(returncode=0)).start()

    def arguments(self, params, **extra):
        fields = dict(
            cxx=False, list_path=None, build_plan=self.root,
            no_gate=False, registry=self.root / "registry.json", llvm_params=params,
        )
        fields.update(extra)
        return SimpleNamespace(**fields)

    def test_fixed_plan_overrides_registry_and_latest(self):
        registry = mock.Mock()
        decisions, path = wrapper_module._resolve_decisions(
            self.arguments([]), registry, self.root / "new-app", "link",
        )
        self.assertEqual(decisions, self.decision)
        self.assertEqual(Path(path), self.decision_path)
        registry.effective_status.assert_not_called()
        self.latest.assert_not_called()
        self.loader.assert_called_once_with(self.root)

    def test_metadata_entry_injects_stack_object_only(self):
        self.assertEqual(run_llvm_wrapper(self.arguments(["-c", "file with spaces.c", "-o", "out.o"])), 0)
        argv = self.compiler.call_args.args[0]
        self.assertIn(f"-fpass-plugin={self.plugins / 'ChimeraStackObject.so'}", argv)
        self.assertFalse(any("ChimeraVectorGate" in item for item in argv))
        self.assertIn("file with spaces.c", argv)

    def test_gate_entry_injects_both_plugins_and_its_own_names(self):
        self.decision.update(strategy="gate", gate={"enabled": True, "names": ["exact", "shared"]})
        self.assertEqual(run_llvm_wrapper(self.arguments(["-c", "a.cc", "-o", "a.o"], cxx=True)), 0)
        argv = self.compiler.call_args.args[0]
        self.assertEqual(argv[0], str(self.bin_dir / "clang++"))
        self.assertIn(f"-fpass-plugin={self.plugins / 'ChimeraStackObject.so'}", argv)
        self.assertIn(f"-fpass-plugin={self.plugins / 'ChimeraVectorGate.so'}", argv)
        env = self.compiler.call_args.kwargs["env"]
        self.assertEqual(Path(env["CHIMERA_GATE_LIST"]).read_text(encoding="utf-8"), "exact\nshared\n")

    def test_configure_probe_validates_plan_without_injecting(self):
        arguments = self.arguments(["-E", "conftest.c"])
        self.assertEqual(run_llvm_wrapper(arguments), 0)
        self.loader.assert_called_once_with(self.root)
        self.assertEqual(self.compiler.call_args.args[0], [str(self.bin_dir / "clang"), "-E", "conftest.c"])

    def test_corrupt_plan_is_rejected_before_a_probe_runs(self):
        self.loader.side_effect = ValueError("decision hash mismatch")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            run_llvm_wrapper(self.arguments(["-E", "conftest.c"]))
        self.compiler.assert_not_called()

    def test_fixed_plan_cannot_be_overridden_by_no_gate_or_list(self):
        for extra in ({"no_gate": True}, {"list_path": self.decision_path}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                run_llvm_wrapper(self.arguments(["-c", "a.c"], **extra))
        self.compiler.assert_not_called()

    def test_compile_exit_code_is_preserved(self):
        self.compiler.return_value = SimpleNamespace(returncode=7)
        self.assertEqual(run_llvm_wrapper(self.arguments(["-c", "a.c"])), 7)


@unittest.skipIf(
    os.name == "nt",
    "fake clang 是 POSIX shell 脚本，Windows 原生 python 无法直接执行",
)
class WrapperIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = root = Path(self.tmp.name)
        self.toolchain = root / "toolchain_build"
        self.bin_dir = self.toolchain / "llvm" / "bin"
        self.plugins = self.toolchain / "plugins" / "lib" / "chimera" / "llvm"
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.plugins.mkdir(parents=True, exist_ok=True)

        self.record = root / "record.txt"
        self.env_record = root / "record_env.txt"
        fake_clang = self.bin_dir / "clang"
        fake_clang.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$@\" > '" + str(self.record) + "'\n"
            "printf 'CHIMERA_GATE_LIST=%s\\nCHIMERA_GATE_STATS=%s\\n' "
            "\"$CHIMERA_GATE_LIST\" \"$CHIMERA_GATE_STATS\" "
            "> '" + str(self.env_record) + "'\n"
            "prev=\"\"\n"
            "for a in \"$@\"; do"
            "  if [ \"$prev\" = \"-o\" ]; then"
            "    printf '\\x7fELF.chimera.stackobj_map' > \"$a\";"
            "  fi; prev=\"$a\"; done\n"
            "exit 0\n"
        )
        fake_clang.chmod(0o755)
        (self.plugins / "ChimeraFunctionPointer.so").write_bytes(b"")
        (self.plugins / "ChimeraVectorGate.so").write_bytes(b"")

        self.registry_path = root / "elf_registry.json"
        self.decision = root / "app.check.json"

        os.environ["CHIMERA_TOOLCHAIN_BUILD"] = str(self.toolchain)
        os.environ["CHIMERA_RECORD"] = str(self.record)
        self.addCleanup(os.environ.pop, "CHIMERA_TOOLCHAIN_BUILD", None)
        self.addCleanup(os.environ.pop, "CHIMERA_RECORD", None)

        # A registered PROBLEMATIC output path with a decision file.
        self.target = root / "out" / "llama-perplexity"
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.target.write_bytes(b"\x7fELF-old")
        self.decision_path = root / "app.check.json"
        self.decision = {
            "decisions": {
                "vector_gate": {"enabled": True},
                "function_pointer_plugin": False,
                "stack_object_plugin": False,
            },
            "gate": {"enabled": True, "names": ["_Zseed"]},
        }
        self.decision_document = {
            "schema": "chimera.check.v1",
            "elf": {"path": str(self.target)},
            "strategy": "gate",
            "decision": self.decision,
        }
        self.decision_path.write_text(
            json.dumps(self.decision_document), encoding="utf-8"
        )

        registry = ElfStateRegistry(self.registry_path)
        registry.set_status(
            self.target, PROBLEMATIC, decision_ref=str(self.decision_path)
        )

        self.output_elf = self.target  # link -o writes exactly here

    def _arguments(self, params):
        return SimpleNamespace(
            cxx=False,
            list_path=None,
            no_gate=False,
            registry=self.registry_path,
            llvm_params=params,
        )

    def _recorded_argv(self):
        return [
            line for line in self.record.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def _recorded_env(self):
        values = {}
        for line in self.env_record.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            values[key] = value
        return values

    def test_link_injects_gate_and_plugin_per_decision(self):
        code = run_llvm_wrapper(self._arguments(["-flto", "-o", str(self.target), "a.o"]))
        self.assertEqual(code, 0)
        argv = self._recorded_argv()
        self.assertIn("-flto", argv)
        # lld 在加载 pass 插件前解析 -mllvm，插件 cl::opt 不可见；
        # 门控参数必须走环境变量，argv 里不得再出现 -mllvm 注入。
        self.assertNotIn("-mllvm", argv)
        self.assertNotIn("-Wl,-mllvm", argv)
        self.assertIn("-Wl,--load-pass-plugin", argv)
        self.assertIn("ChimeraVectorGate.so", " ".join(argv))
        env = self._recorded_env()
        names_file = Path(env["CHIMERA_GATE_LIST"])
        self.assertIn("_Zseed", names_file.read_text(encoding="utf-8"))
        self.assertTrue(
            env["CHIMERA_GATE_STATS"].endswith(".implicit_vector_census.tsv")
        )

    def test_link_success_transitions_to_remediated(self):
        run_llvm_wrapper(self._arguments(["-flto", "-o", str(self.target), "a.o"]))
        status, _ = ElfStateRegistry(self.registry_path).effective_status(
            self.target
        )
        self.assertEqual(status, REMEDIATED)

    def test_checked_target_is_passthrough(self):
        other = self.root / "checked.elf"
        other.write_bytes(b"\x7fELF-checked")
        ElfStateRegistry(self.registry_path).set_status(other, CHECKED)
        code = run_llvm_wrapper(self._arguments(["-flto", "-o", str(other), "a.o"]))
        self.assertEqual(code, 0)
        argv = [line for line in self.record.read_text(encoding="utf-8").splitlines()]
        self.assertNotIn("--load-pass-plugin", argv)

    def test_missing_flto_is_rejected_when_fp_selected(self):
        # LTO 只是 SVF/function_pointer 路线的使用需求（链接期指针分析
        # 需要合并模块）；gate 决策不要求 -flto。
        self.decision["function_pointer_plugin"] = True
        self.decision_document["decision"] = self.decision
        self.decision_path.write_text(
            json.dumps(self.decision_document), encoding="utf-8"
        )
        with self.assertRaises(ValueError):
            run_llvm_wrapper(self._arguments(["-o", str(self.target), "a.o"]))

    def test_gate_only_without_flto_is_passthrough_link(self):
        # gate-only 决策 + 非 LTO 链接：编译期门控已完成一切，链接期
        # 原样透传——不加载 pass 插件、不设 gate 环境变量。
        # （fake clang 无条件记录 CHIMERA_GATE_LIST=...，未设时为空串，
        #   故断言值为空而非键不存在。）
        code = run_llvm_wrapper(self._arguments(["-o", str(self.target), "a.o"]))
        self.assertEqual(code, 0)
        argv = self._recorded_argv()
        self.assertNotIn("-Wl,--load-pass-plugin", argv)
        self.assertNotIn("-flto", argv)
        env = self._recorded_env()
        self.assertEqual(env.get("CHIMERA_GATE_LIST", ""), "")

    def test_compile_mode_injects_gate_via_fpass_plugin(self):
        # -flto 的向量化发生在 per-TU 编译期，门控必须在编译期注入；
        # 用 --list 提供决策（绕过 latest 指针的全局路径依赖）。
        args = self._arguments(["-flto", "-c", "a.c", "-o", "a.o"])
        args.list_path = self.decision_path
        code = run_llvm_wrapper(args)
        self.assertEqual(code, 0)
        argv = self._recorded_argv()
        # clang 只认 joined 形式 -fpass-plugin=<path>，分离两项会被拒收
        self.assertTrue(
            any(item.startswith("-fpass-plugin=") for item in argv), argv
        )
        self.assertIn("ChimeraVectorGate.so", " ".join(argv))
        env = self._recorded_env()
        names_file = Path(env["CHIMERA_GATE_LIST"])
        self.assertIn("_Zseed", names_file.read_text(encoding="utf-8"))

    def test_preprocess_probe_gets_no_decision_even_with_explicit_list(self):
        # AC_PREPROC_IFELSE 的判据是 conftest.err 非空即失败。即使 --list
        # 显式给了决策，-E 探针也必须零注入、零 stderr 输出。
        args = self._arguments(["-E", "conftest.c"])
        args.list_path = self.decision_path
        code = run_llvm_wrapper(args)

        self.assertEqual(code, 0)
        argv = self._recorded_argv()
        self.assertEqual(argv, ["-E", "conftest.c"])
        self.assertFalse(any(i.startswith("-fpass-plugin=") for i in argv), argv)
        env = self._recorded_env()
        self.assertEqual(env.get("CHIMERA_GATE_LIST", ""), "")
        # 没有决策就没有派生产物：不写 gate names / census 文件
        self.assertFalse(
            Path(self.decision_path).with_suffix(".gate_names.txt").exists()
        )

    def test_conftest_compile_probe_gets_no_decision(self):
        # 同一条规则覆盖 compile / link / run 三类 probe：autoconf 一律用
        # conftest.* 命名，探针产物会被丢弃。
        args = self._arguments(["-flto", "-c", "conftest.c", "-o", "conftest.o"])
        args.list_path = self.decision_path
        code = run_llvm_wrapper(args)

        self.assertEqual(code, 0)
        argv = self._recorded_argv()
        self.assertFalse(any(i.startswith("-fpass-plugin=") for i in argv), argv)

    def test_real_compile_still_injects_after_probe_rule(self):
        # 反向护栏：探针规则不能把真实编译也一起放过。
        args = self._arguments(["-flto", "-c", "fibheap.c", "-o", "fibheap.o"])
        args.list_path = self.decision_path
        self.assertEqual(run_llvm_wrapper(args), 0)
        argv = self._recorded_argv()
        self.assertTrue(any(i.startswith("-fpass-plugin=") for i in argv), argv)


if __name__ == "__main__":
    unittest.main()
