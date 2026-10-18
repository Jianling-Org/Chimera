# llama.cpp 的 RVV1024 与 RVV256 兼容补丁

Chimera 的 llama.cpp 示例以官方提交 `4fc4ec5541b243957ae5099edb67372f8f3b550e` 加本目录补丁作为应用源码，提供 RVV1024 计算路径及 RVV256 兼容回退。源码子模块仍指向官方仓库，项目定制部分由补丁交付。

## 修改内容与顺序

按 [series](series) 中的顺序应用：

| 补丁 | 作用 |
|---|---|
| [llama-cpp-rvv-vlen1024-q5-fix-4fc4ec554.patch](llama-cpp-rvv-vlen1024-q5-fix-4fc4ec554.patch) | 增加 RVV1024 量化矩阵乘/矩阵向量乘、重排和数据块支持，并包含 Q5 修复。 |
| [0001-llama.cpp-rvv-vlen1024-compatible-with-vlen256.patch](0001-llama.cpp-rvv-vlen1024-compatible-with-vlen256.patch) | 在宽路径函数中按实际 VL 选择分支：`vl == 64` 走宽路径，VL 更小时分段计算且保持数据布局；对应重排资格放宽到 VLEN ≥ 256。依赖第一份补丁。 |

例如，补丁增加 `ggml_gemm_q3_K_64x1_q8_K` 等函数；兼容补丁在 `vl == 64` 时保留宽向量路径，在较窄 VL 下分段计算。这里 `vl` 表示运算的向量元素数，VLEN 表示寄存器位宽。256 位兼容回退仍使用 RVV，并与 Chimera 的跨 VLEN 翻译、线程迁移配合使用。

## 使用自动构建入口

从 Chimera 仓库根目录初始化官方子模块。先按[应用构建说明](../README.md#依赖与构建入口)准备 patched LLVM、插件，并在 `examples/applications/llama-cpp/scalar/` 中提供已核验的标量底座文件，再运行构建脚本：

```bash
git submodule update --init examples/applications/llama-cpp/llama.cpp
bash examples/scripts/build/build_llamacpp.sh
```

`build_llamacpp.sh` 与 `build_llamacpp_stats.sh` 按上述顺序临时应用两份补丁，退出时逆序恢复。源码必须是干净的官方版本，补丁由脚本自行应用。外部源码模式 `CHIMERA_EXAMPLE_SOURCE_DIR` 同样如此；下面手动应用过补丁的检出仅用于自有构建流程。

## 手动集成

自有构建流程可以手动应用补丁。下面使用新目录检出官方固定版本：

```bash
CHIMERA_SOURCE=/absolute/path/to/Chimera
LLAMA_SOURCE=/absolute/path/to/llama.cpp

git clone https://github.com/ggml-org/llama.cpp.git "$LLAMA_SOURCE"
git -C "$LLAMA_SOURCE" checkout --detach 4fc4ec5541b243957ae5099edb67372f8f3b550e
PATCH_DIR="$CHIMERA_SOURCE/examples/applications/llama-cpp/patch"

git -C "$LLAMA_SOURCE" apply --check "$PATCH_DIR/llama-cpp-rvv-vlen1024-q5-fix-4fc4ec554.patch"
git -C "$LLAMA_SOURCE" apply "$PATCH_DIR/llama-cpp-rvv-vlen1024-q5-fix-4fc4ec554.patch"
git -C "$LLAMA_SOURCE" apply --check "$PATCH_DIR/0001-llama.cpp-rvv-vlen1024-compatible-with-vlen256.patch"
git -C "$LLAMA_SOURCE" apply "$PATCH_DIR/0001-llama.cpp-rvv-vlen1024-compatible-with-vlen256.patch"
git -C "$LLAMA_SOURCE" diff --stat
```

每个 `apply --check` 检查当前源码状态：先检查并应用第一份，再检查并应用第二份。发生冲突时，核对源码版本和应用顺序。

使用该检出的源码完成自有构建流程。补丁应用后的源文件显示为本地修改是预期状态；这份目录用于手动集成，不再直接交给会自动打补丁的构建脚本。

需要移除补丁时，在保留其他改动的前提下逆序应用：

```bash
git -C "$LLAMA_SOURCE" apply -R "$PATCH_DIR/0001-llama.cpp-rvv-vlen1024-compatible-with-vlen256.patch"
git -C "$LLAMA_SOURCE" apply -R "$PATCH_DIR/llama-cpp-rvv-vlen1024-q5-fix-4fc4ec554.patch"
```

## 构建与验证

保留 RVV 及所用算子需要的扩展，使用匹配的 Chimera LLVM 和插件。应用补丁后，按 [Gate 构建](../../../../docs/deployment/gate-build.md)执行必要的元数据/gate 重编，并对最终 ELF 做严格检查。

多线程双向自动迁移的 OpenMP、依赖、Profile、运行参数与 PPL 检查见[双向自动迁移示例](../reference-v32/README.md)。补丁提供应用计算路径；最终检查和目标机迁移验证针对实际构建执行。上游许可证和现有版权声明继续保留。

固定版本的补丁应用、原文件对象与逆向恢复核对结果见[源码重放记录](source-replay.json)。
