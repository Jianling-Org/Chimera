"""Package user-supplied ELF build files without executing or rewriting them."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import tomllib
from typing import Mapping
import zipfile


FORMAT = "chimera-build-bundle"
VERSION = 1
MANIFEST = "build-bundle.json"
ROLES = {"profile", "script", "instructions"}
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_WINDOWS_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])\Z", re.IGNORECASE)


def _member_name(value: object) -> str:
    # Payloads are three sibling files; do not accept directory entries,
    # Windows drive paths or names that alias one another on Windows.
    if (not isinstance(value, str) or not value or value in {".", ".."}
            or any(ord(char) < 32 or char in '/\\:<>"|?*' for char in value)
            or value.endswith((".", " "))):
        raise ValueError(f"invalid build bundle file name: {value!r}")
    if _WINDOWS_DEVICE.fullmatch(value.split(".", 1)[0].rstrip(" ")):
        raise ValueError(f"reserved build bundle file name: {value}")
    return value


def _output_path(value: str | Path) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    current = Path(candidate.anchor)
    for component in candidate.parts[1:]:
        current = current / component
        is_junction = getattr(current, "is_junction", lambda: False)
        if current.is_symlink() or is_junction():
            raise ValueError(f"build bundle output contains a link: {current}")
    return candidate.resolve()


def _read_input(value: str | Path) -> tuple[str, bytes]:
    path = Path(value).expanduser()
    name = _member_name(path.name)
    if not path.is_file():
        raise ValueError(f"build bundle input is not a regular file: {path}")
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if not data or len(data) > MAX_FILE_BYTES:
        raise ValueError(f"build bundle input is empty or exceeds {MAX_FILE_BYTES} bytes: {path}")
    return name, data


def _validate_texts(payload: Mapping[str, bytes], files: list[dict]) -> None:
    for item in files:
        try:
            text = payload[item["path"]].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"build bundle {item['role']} must be UTF-8 text") from error
        if not text.strip():
            raise ValueError(f"build bundle {item['role']} must not be empty")
        if item["role"] == "profile":
            tomllib.loads(text)


def _validate_env(records: object) -> list[dict[str, str]]:
    if not isinstance(records, list):
        raise ValueError("build bundle required_env must be an array")
    seen = set()
    for item in records:
        if (not isinstance(item, dict) or set(item) != {"name", "description"}
                or not isinstance(item["name"], str)
                or not _ENV_NAME.fullmatch(item["name"])
                or not isinstance(item["description"], str)
                or "\x00" in item["description"]
                or item["name"] in seen):
            raise ValueError("invalid or duplicate build bundle environment variable")
        seen.add(item["name"])
    return records


def _env_declarations(values) -> list[dict[str, str]]:
    records = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError("--require-env must be NAME or NAME=DESCRIPTION")
        name, _, description = value.partition("=")
        records.append({"name": name, "description": description})
    return _validate_env(records)


def _validate_payload(payload: Mapping[str, bytes]) -> dict:
    if len(payload.get(MANIFEST, b"")) > MAX_MANIFEST_BYTES:
        raise ValueError("build bundle manifest is too large")
    try:
        doc = json.loads(payload[MANIFEST])
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("build bundle has no valid build-bundle.json") from error
    if (not isinstance(doc, dict) or doc.get("format") != FORMAT
            or type(doc.get("version")) is not int or doc["version"] != VERSION):
        raise ValueError("unsupported build bundle format or version")
    files = doc.get("files")
    if not isinstance(files, list) or len(files) != len(ROLES):
        raise ValueError("build bundle must contain profile, script and instructions")
    roles, names = set(), set()
    for item in files:
        if (not isinstance(item, dict) or not isinstance(item.get("role"), str)
                or item["role"] not in ROLES):
            raise ValueError("invalid build bundle file role")
        name = _member_name(item.get("path"))
        if (item["role"] in roles or name.casefold() in names
                or name.casefold() == MANIFEST.casefold()
                or type(item.get("size")) is not int
                or not 0 < item["size"] <= MAX_FILE_BYTES
                or not isinstance(item.get("sha256"), str)
                or not _DIGEST.fullmatch(item["sha256"])):
            raise ValueError("invalid or duplicate build bundle file record")
        data = payload.get(name)
        if (data is None or len(data) != item["size"]
                or hashlib.sha256(data).hexdigest() != item["sha256"]):
            raise ValueError(f"build bundle file integrity check failed: {name}")
        names.add(name.casefold())
        roles.add(item["role"])
    if roles != ROLES or set(payload) != {MANIFEST, *(item["path"] for item in files)}:
        raise ValueError("build bundle file list disagrees with archive contents")
    _validate_env(doc.get("required_env"))
    _validate_texts(payload, files)
    return doc


def pack_build_bundle(profile: str | Path, script: str | Path,
                      instructions: str | Path, output: str | Path, *,
                      required_env=()) -> Path:
    """Create a ZIP bundle containing exactly the three supplied files."""
    payload, files = {}, []
    names = {MANIFEST.casefold()}
    for role, source in (("profile", profile), ("script", script), ("instructions", instructions)):
        name, data = _read_input(source)
        if name.casefold() in names:
            raise ValueError(f"build bundle input file names must be distinct: {name}")
        names.add(name.casefold())
        payload[name] = data
        files.append({"role": role, "path": name, "size": len(data),
                      "sha256": hashlib.sha256(data).hexdigest()})
    doc = {"format": FORMAT, "version": VERSION, "files": files,
           "required_env": _env_declarations(required_env)}
    payload[MANIFEST] = (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _validate_payload(payload)
    destination = _output_path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with destination.open("xb") as stream:
            created = True
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in sorted(payload.items()):
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(info, data)
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise
    return destination


def _read_archive(source: str | Path) -> dict[str, bytes]:
    source = Path(source).expanduser()
    if not source.is_file():
        raise ValueError(f"build bundle input is not a regular file: {source}")
    try:
        with zipfile.ZipFile(source) as archive:
            infos = archive.infolist()
            if len(infos) != 4:
                raise ValueError("build bundle must contain exactly four files")
            payload, names = {}, set()
            for info in infos:
                name = _member_name(info.orig_filename)
                file_type = stat.S_IFMT(info.external_attr >> 16)
                limit = MAX_MANIFEST_BYTES if name == MANIFEST else MAX_FILE_BYTES
                if (info.is_dir() or file_type not in {0, stat.S_IFREG}
                        or info.flag_bits & 1 or name.casefold() in names
                        or not 0 < info.file_size <= limit):
                    raise ValueError(f"invalid build bundle archive member: {name}")
                names.add(name.casefold())
                with archive.open(info) as stream:
                    data = stream.read(limit + 1)
                if len(data) != info.file_size or len(data) > limit:
                    raise ValueError(f"build bundle member size disagrees: {name}")
                payload[name] = data
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ValueError(f"invalid build bundle archive: {error}") from error
    _validate_payload(payload)
    return payload


def unpack_build_bundle(source: str | Path, output_dir: str | Path) -> Path:
    """Verify before writing, refuse existing destinations, never execute code."""
    payload = _read_archive(source)
    destination = _output_path(output_dir)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(exist_ok=False)
    created = []
    try:
        for name, data in payload.items():
            path = destination / name
            with path.open("xb") as stream:
                created.append(path)
                stream.write(data)
            path.chmod(0o644)
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        destination.rmdir()
        raise
    return destination


def _relative_profile_paths(data: bytes) -> list[tuple[str, str]]:
    """Identify known path fields for a portability notice, without changing them."""
    doc = tomllib.loads(data.decode("utf-8"))
    config = doc.get("config", {})
    if not isinstance(config, dict):
        return []
    candidates = []
    for key in ("data_root", "workspace_root", "scalar_root"):
        candidates.append((f"config.{key}", config.get(key)))
    translators = config.get("translators", [])
    if isinstance(translators, list):
        for index, item in enumerate(translators):
            if isinstance(item, dict):
                candidates.append((f"config.translators[{index}].translator_path", item.get("translator_path")))
    for table, keys in (("target_files", ("sysroot", "cmake_toolchain_file")),
                        ("runtime", ("bpf_map", "ai_thread_control"))):
        values = config.get(table, {})
        if isinstance(values, dict):
            candidates.extend((f"config.{table}.{key}", values.get(key)) for key in keys)
            roots = values.get("library_roots", [])
            if table == "target_files" and isinstance(roots, list):
                candidates.extend((f"config.{table}.library_roots[{i}]", value) for i, value in enumerate(roots))
    tools = config.get("tools", {})
    if isinstance(tools, dict):
        candidates.extend((f"config.tools.{key}", value) for key, value in tools.items()
                          if isinstance(value, str) and ("/" in value or "\\" in value))
    return [(field, value) for field, value in candidates
            if isinstance(value, str) and value and not value.startswith("~")
            and not PurePosixPath(value).is_absolute() and not PureWindowsPath(value).is_absolute()]


def render_build_bundle_usage(directory: str | Path, *,
                              environment: Mapping[str, str] | None = None) -> str:
    root = _output_path(directory)
    if (root / MANIFEST).is_symlink():
        raise ValueError("unpacked build bundle manifest is a link")
    with (root / MANIFEST).open("rb") as stream:
        manifest = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(manifest) > MAX_MANIFEST_BYTES:
        raise ValueError("build bundle manifest is too large")
    doc = json.loads(manifest)
    # Read only names that pass the same flat-name validation as extraction.
    files = doc.get("files", []) if isinstance(doc, dict) else []
    if not isinstance(files, list) or len(files) != 3:
        raise ValueError("invalid unpacked build bundle file list")
    payload = {MANIFEST: manifest}
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("invalid unpacked build bundle file record")
        name = _member_name(item.get("path"))
        if (root / name).is_symlink():
            raise ValueError(f"unpacked build bundle file is a link: {name}")
        with (root / name).open("rb") as stream:
            payload[name] = stream.read(MAX_FILE_BYTES + 1)
    doc = _validate_payload(payload)
    roles = {item["role"]: item["path"] for item in doc["files"]}
    environment = os.environ if environment is None else environment
    lines = ["使用说明：", payload[roles["instructions"]].decode("utf-8").rstrip(), "",
             f"Profile：{root / roles['profile']}", f"构建脚本：{root / roles['script']}",
             f"说明文件：{root / roles['instructions']}", "", "必要环境变量（由打包者声明）："]
    for item in doc["required_env"]:
        status = "已设置" if environment.get(item["name"]) else "未设置"
        description = f"：{item['description']}" if item["description"] else ""
        lines.append(f"- {item['name']}{description}（{status}；运行前请 export）")
    if not doc["required_env"]:
        lines.append("未单独声明必要变量，请按上面的使用说明设置。")
    lines += ["", "解包只保存文件和显示说明；构建脚本尚未执行。",
              "三个文件均保留原文；源码、工具链及其他依赖由接收机器准备。"]
    relative_paths = _relative_profile_paths(payload[roles["profile"]])
    if relative_paths:
        lines += ["", "Profile 的以下相对路径按解包后的 Profile 目录解析；引用资源未随包提供，请先核对："]
        lines.extend(f"- {field} = {value}" for field, value in relative_paths)
    return "\n".join(lines)
