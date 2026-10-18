from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")


def _markdown_files() -> list[Path]:
    return sorted(
        path for path in ROOT.rglob("*.md")
        if not ({"third_party", ".git", "build", "build_patched"} & set(path.parts))
    )


def _heading_slugs(path: Path) -> set[str]:
    slugs: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^#{1,6}\s+(.+?)\s*#*$", line)
        if not match:
            continue
        heading = re.sub(r"[`*_]", "", match.group(1)).strip().lower()
        heading = re.sub(r"[^\w\-\u4e00-\u9fff ]+", "", heading)
        slugs.add(re.sub(r"\s+", "-", heading))
    return slugs


class DocumentationContractTests(unittest.TestCase):
    def test_extensibility_guide_is_indexed_and_describes_current_hooks(self):
        guide_path = ROOT / "docs" / "developer" / "extensibility.md"
        guide = guide_path.read_text(encoding="utf-8")
        docs_index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
        overview = (ROOT / "docs" / "developer" / "architecture" / "README.md").read_text(encoding="utf-8")

        self.assertIn("(developer/extensibility.md)", docs_index)
        self.assertIn("(targets/README.md)", overview)
        required = (
            "registered_step_catalog",
            "registered_target_catalog",
            "registered_scene_verifiers",
            "registered_launch_adapters",
            "registered_registrars",
            "workspace_contributions",
            "required_by",
            "Dynamic external plugin discovery",
        )
        for marker in required:
            self.assertIn(marker, guide, marker)

    def test_local_markdown_links_and_ascii_or_cjk_anchors_exist(self):
        errors: list[str] = []
        for source in _markdown_files():
            text = source.read_text(encoding="utf-8")
            for raw_target in LINK_RE.findall(text):
                target = unquote(raw_target.strip().split(" ", 1)[0])
                if not target or target.startswith(("http://", "https://", "mailto:")):
                    continue
                target_path, separator, anchor = target.partition("#")
                resolved = (source.parent / target_path).resolve() if target_path else source
                if not (resolved.is_file() or resolved.is_dir()):
                    errors.append(f"{source.relative_to(ROOT)} -> {raw_target}")
                    continue
                if separator and anchor and anchor not in _heading_slugs(resolved):
                    errors.append(f"{source.relative_to(ROOT)} -> missing anchor {raw_target}")
        self.assertEqual([], errors, "broken Markdown links or anchors:\n" + "\n".join(errors))

    def test_formal_documents_are_reachable_from_index(self):
        documents = {path.resolve() for path in (ROOT / "docs").rglob("*.md")}
        pending = [(ROOT / "docs/README.md").resolve()]
        reached: set[Path] = set()
        while pending:
            source = pending.pop()
            if source in reached:
                continue
            reached.add(source)
            for target in LINK_RE.findall(source.read_text(encoding="utf-8")):
                target = unquote(target.strip().split(" ", 1)[0]).partition("#")[0]
                if not target or target.startswith(("http://", "https://", "mailto:")):
                    continue
                resolved = (source.parent / target).resolve()
                if resolved in documents and resolved not in reached:
                    pending.append(resolved)
        self.assertEqual([], sorted(str(path.relative_to(ROOT)) for path in documents - reached))

    def test_current_cli_and_plugin_contracts_are_documented(self):
        cli = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                ROOT / "docs" / "developer" / "cli.md",
                ROOT / "docs" / "deployment" / "cli.md",
                ROOT / "docs" / "user" / "cli.md",
            )
        )
        required = (
            # The application no longer lives in the package, so every command
            # that touches a real file needs the machine's own path for it.
            "chimera-user register --input ELF [--workspace ID_OR_PATH]",
            "chimera-user run --input ELF [--workspace ID_OR_PATH]",
            "chimera-user verify --workspace ID_OR_PATH [--input ELF]",
            "chimera-pkg check-elf --profile PROFILE --input ELF",
            "--plugins stackobject function-pointer vector-gate",
            "llvm-objdump",
        )
        for fragment in required:
            self.assertIn(fragment, cli, fragment)

    def test_stale_public_documentation_terms_are_absent(self):
        stale = (
            "register,runtime",
            "libinject.so",
            "online/inject_lib.c",
            "fromyang",
            "openblas-translator",
            "774 项",
            "29 个测试文件",
            "32 个 case",
            "patches/llvm-21.1.0",
            "acceptance-report.md",
        )
        offenders: list[str] = []
        for path in _markdown_files():
            text = path.read_text(encoding="utf-8")
            for term in stale:
                if term in text:
                    offenders.append(f"{path.relative_to(ROOT)}: {term}")
        self.assertEqual([], offenders, "stale documentation terms:\n" + "\n".join(offenders))

    def test_generated_support_matrix_is_current(self):
        generator = ROOT / "preprocessing" / "translator" / "rvv_sbt_tool" / "tools" / "generate_support_docs.py"
        result = subprocess.run(
            [sys.executable, str(generator), "--check"],
            cwd=generator.parent.parent,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
