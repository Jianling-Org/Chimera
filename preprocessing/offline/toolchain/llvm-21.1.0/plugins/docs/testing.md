# 测试指南

本文档是可复现的测试指南。命令使用环境变量表示路径，不依赖任何特定机器的绝对路径；测试结果应以本次命令输出为准：

| 变量 | 含义 |
|---|---|
| `$LLVM_SRC` | patched LLVM 源码树（`llvmorg-21.1.0` + `patches/*.patch`） |
| `$LLVM_BUILD` | LLVM 21.1.0 构建目录 |
| `$CHIMERA` | 本工程根目录（`chimera/preprocessing/offline/toolchain/llvm-21.1.0`） |
| `$STACK_BUILD` | StackObject-only 构建目录 |
| `$SVF_BUILD` | SVF-only 构建目录 |
| `$ALL_BUILD` | dual-plugin 构建目录 |
| `$SVF_DIR` | SVF 安装目录（`lib/cmake/SVF`），`chimera-dev toolchain build svf` 的产物 |

---

## 1. 环境准备

先构建带 Chimera patch 的 LLVM：

> 下面的命令序列（checkout → `git am` → 配置 → 构建 → 安装 → 恢复原码）已封装为
> `chimera-dev toolchain build patched-llvm`；SVF 库本身对应
> `chimera-dev toolchain build svf`，插件一起由 `chimera-dev toolchain build llvm-plugin`
> 构建。三者产物依次安装到 `~/.chimera/toolchain_build/{llvm,svf,plugins}`。

```bash
# 在 $LLVM_SRC 中应用 patch
git checkout llvmorg-21.1.0
git am "$CHIMERA"/patches/*.patch
git diff --check          # 必须干净

# 配置并构建
cmake -S "$LLVM_SRC"/llvm -B "$LLVM_BUILD" -G Ninja \
  -DLLVM_ENABLE_PROJECTS=clang \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_TARGETS_TO_BUILD=RISCV
ninja -C "$LLVM_BUILD"
```

---

## 2. LLVM targeted lit + unit test

直接运行 series 新增的 regression tests：

```bash
"$LLVM_BUILD"/bin/llvm-lit -v \
  llvm/test/CodeGen/Generic/pcsections-absolute.ll \
  llvm/test/CodeGen/Generic/chimera-pcsections-flags.ll \
  llvm/test/CodeGen/RISCV/chimera-pcsections-inline-asm.ll \
  llvm/test/CodeGen/RISCV/chimera-rvv-spill.ll \
  llvm/test/CodeGen/RISCV/chimera-rvv-spill-stock-rv64.ll \
  llvm/test/CodeGen/RISCV/chimera-rvv-spill-stock-rv32.ll \
  llvm/test/CodeGen/RISCV/chimera-rvv-spill-rv32.ll \
  llvm/test/CodeGen/RISCV/chimera-rvv-tuple-spill.mir \
  llvm/test/CodeGen/RISCV/chimera-rvv-tuple-spill-stock.mir \
  llvm/test/CodeGen/RISCV/chimera-pcsections-call-tail.ll \
  llvm/test/Transforms/LoopVectorize/RISCV/spill-cost.ll \
  llvm/test/Transforms/SLPVectorizer/spill-cost.ll

ninja -C "$LLVM_BUILD" VectorizeTests   # 构建后运行
"$LLVM_BUILD"/unittests/Transforms/Vectorize/VectorizeTests \
  --gtest_filter='VPRegisterUsageTest.*'
```

### 覆盖的核心场景

| 场景 | 对应 lit |
|---|---|
| Generic absolute PCSections | `pcsections-absolute.ll` |
| Chimera ELF flags | `chimera-pcsections-flags.ll` |
| inline asm locator | `chimera-pcsections-inline-asm.ll` |
| ordinary RVV spill | `chimera-rvv-spill.ll` |
| RV32 Chimera negative | `chimera-rvv-spill-rv32.ll` |
| tuple RVV spill | `chimera-rvv-tuple-spill.mir` |
| CALL/TAIL | `chimera-pcsections-call-tail.ll` |
| LoopVectorize spill-cost | `LoopVectorize/RISCV/spill-cost.ll` |
| SLP spill-cost | `SLPVectorizer/spill-cost.ll` |

此外还有 stock RV32/RV64 ordinary-spill、stock tuple 等 negative，以及 vector-class-only pressure 的 unit test。

---

## 3. StackObject-only（SVF 关闭）

```bash
cmake -S "$CHIMERA"/plugins -B "$STACK_BUILD" \
  -DLLVM_DIR="$LLVM_BUILD"/lib/cmake/llvm \
  -DCHIMERA_ENABLE_STACKOBJECT=ON \
  -DBUILD_TESTING=ON
cmake --build "$STACK_BUILD" --target ChimeraStackObject
ctest --test-dir "$STACK_BUILD" --output-on-failure
```

注册两个 CTest：

- `ChimeraStackObject`：跑 `tests/stackobject/run.sh`；inventory guard 保证目录内所有 `.ll` 都被执行，并进行最终 RV64 linked ELF 检查。
- `ChimeraStackObjectMapChecker`：`tests/tools/test_check_stackobj_map.py` 单元测试（不依赖 LLVM 工具链）。

### expected negative：RV32 / riscv64-pointer32

`rv32-unsupported.ll` 与 `riscv64-pointer32-unsupported.ll` 通过 LLVM fatal error 触发负向检查，因此日志会出现：

```text
已中止（核心已转储）
```

这是 **expected negative test**，不是测试失败。

---

## 4. SVF-only（StackObject 关闭）

```bash
cmake -S "$CHIMERA"/plugins -B "$SVF_BUILD" \
  -DLLVM_DIR="$LLVM_BUILD"/lib/cmake/llvm \
  -DSVF_DIR="$SVF_DIR" \
  -DCHIMERA_ENABLE_SVF=ON \
  -DBUILD_TESTING=ON
cmake --build "$SVF_BUILD" --target ChimeraFunctionPointer
ctest --test-dir "$SVF_BUILD" --output-on-failure
```

`ChimeraFunctionPointer` CTest 运行 `tests/svf/test_function_pointer.py`，覆盖 resolved target set、direct-call exclusion、external/dlsym unresolved、missing-extapi failure、final linked call VA 与 final section relocation 状态。

静态链接检查：确认 `ChimeraFunctionPointer.so` 动态依赖 `libLLVM.so.21.1`，但不动态依赖 `libSvfLLVM.so` / `libSvfCore.so`（如：

```bash
ldd "$SVF_BUILD"/plugins/svf/ChimeraFunctionPointer.so | grep -E 'LLVM|Svf'
```

）。

---

## 5. 多插件组合

```bash
cmake -S "$CHIMERA"/plugins -B "$ALL_BUILD" \
  -DLLVM_DIR="$LLVM_BUILD"/lib/cmake/llvm \
  -DSVF_DIR="$SVF_DIR" \
  -DCHIMERA_ENABLE_STACKOBJECT=ON \
  -DCHIMERA_ENABLE_SVF=ON \
  -DCHIMERA_ENABLE_VECTOR_GATE=ON \
  -DBUILD_TESTING=ON
cmake --build "$ALL_BUILD"
ctest --test-dir "$ALL_BUILD" --output-on-failure
```

启用相应选项后，CTest 会注册以下测试；实际集合以当前 CMake/runner inventory 为准：

- `ChimeraStackObject`
- `ChimeraStackObjectMapChecker`
- `ChimeraFunctionPointer`
- `ChimeraVectorGate`（`-DCHIMERA_ENABLE_VECTOR_GATE=ON` 时；见下节）

---

## 5b. VectorGate-only

```bash
cmake -S "$CHIMERA"/plugins -B "$GATE_BUILD" \
  -DLLVM_DIR="$LLVM_BUILD"/lib/cmake/llvm \
  -DCHIMERA_ENABLE_VECTOR_GATE=ON \
  -DBUILD_TESTING=ON
cmake --build "$GATE_BUILD" --target ChimeraVectorGate
ctest --test-dir "$GATE_BUILD" --output-on-failure
```

`ChimeraVectorGate` CTest 跑 `tests/vector_gate/run.sh`，核心回归是
2026-08-28 的 **C1/C2 构造函数重整名错配**事故：ELF 符号表暴露 `C1` 拼写、
IR 模块定义 `C2` 拼写，gate 名单只拿符号表拼写时永远匹配不上 IR 定义，
复检会持续报告 local-root。测试用 nm 取 `C1` 拼写驱动插件，断言：

- 构造函数（C1 名单条目）被打上 `chimera-no-vectorize`；
- 析构函数 `D1` 拼写同样生效（D1/D2 互为别名）；
- 无匹配名单不会产生逐模块 warning；最终有效性由 `chimera-pkg check-elf`
  的全局复检判定。

---

## 6. full check-llvm

```bash
ninja -C "$LLVM_BUILD" check-llvm
```

运行 `ninja -C "$LLVM_BUILD" check-llvm` 后以 runner 输出为准。测试集合由当前
runner inventory 决定，文档不固定某次机器上的通过数量；需要复现实验时，
请保存命令、提交版本和完整日志。
