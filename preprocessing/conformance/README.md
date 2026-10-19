# vlen-escape

RISC-V Vector（RVV）程序的 **vlen 逃逸检测器**。

## 功能

**输入**：项目路径 + 构建命令（make / cmake 均可）。

**输出**：该构建选项下，程序中是否存在"读取 RVV 向量长度寄存器（vlenb/vsetvl 族）且该值逃逸出函数"的情况。逃逸口径（保守）：

| 类别 | 含义 |
|---|---|
| `RETURN` | vlen（或派生值）作为返回值传出 |
| `HEAP` | vlen 被写入堆对象 |
| `GLOBAL` | vlen 被写入数据段（全局/静态变量） |

仅写栈局部变量不算逃逸。每个可能逃逸位置输出一条记录（`out/escapes.jsonl`）：

```json
{"function": "...", "file": "...", "line": N, "kind": "GLOBAL",
 "target": "GLOBAL::xxx", "derived": false, "confidence": "exact|may"}
```

并生成 `out/report.md` 汇总表。

## 用法

```bash
# 一键（拦截构建 → 逃逸分析 → 报告）
vlen-escape/run.sh <项目路径> -- <构建命令>

# 示例：自带 demo
vlen-escape/run.sh vlen-escape/examples/hello_make -- make -B

# 示例：llama.cpp（cmake 交叉 RVV）
vlen-escape/run.sh llamacpp -- bash -c '
  cmake -B build-vlenwrap -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=riscv64 \
        -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY -DBUILD_SHARED_LIBS=OFF \
        -DGGML_NATIVE=OFF -DGGML_RVV=ON -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
        -DLLAMA_BUILD_TOOLS=OFF -DLLAMA_BUILD_SERVER=OFF &&
  cmake --build build-vlenwrap --target ggml-cpu -- -k -j$(nproc)'

# 已有 bitcode 时跳过构建 / 只重生成报告
vlen-escape/run.sh <项目> --skip-build
vlen-escape/run.sh <项目> --report-only
```

分阶段：

```bash
vlen-escape/scripts/intercept_build.sh <项目> -- <构建命令>   # → <项目>/.vlen-bc/bc.list
vlen-escape/scripts/analyze.sh <bc.list> [-o out]             # → out/escapes.jsonl
```

## 原理

1. **构建拦截**：`wrap_cc.sh`/`wrap_cxx.sh` 作为 CC/CXX 注入（make 读 CC/CXX 变量；cmake 首次 configure 读 CC/CXX 环境变量）。每个 TU 双产出真实 `.o` + `-emit-llvm` 的 `.bc`（bc 复用项目自身编译选项）。自动 `CCACHE_DISABLE=1`（防 ccache 命中跳过 wrapper）。
2. **静态分析**：bc → vscale 清洗（`<vscale x N x T>`→`<N x T>`）→ `svf-vlenesc`（SVF Andersen 指针分析 + 污点追踪）。vlen 读取识别覆盖三种 IR 形态：`@__riscv_vsetvl*` intrinsic、`llvm.read_register("vlenb")`、含 `vsetvli`/`vlenb` 的内联汇编（asm 内部 vl 不可追踪者标 `uncertain`）。

## 构建（自包含，不依赖上级目录）

```bash
vlen-escape/build.sh    # 增量构建，产物 vlen-escape/build/bin/svf-vlenesc
```

### Docker（完全免环境）

```bash
docker build -t vlen-escape vlen-escape/   # 镜像内完成：构建分析器 + 克隆 llama.cpp + RVV 拦截编译 + 逃逸分析
docker run --rm vlen-escape                # 直接打印 llama.cpp 的检测报告与 escapes.jsonl
docker run --rm -it vlen-escape bash       # 交互式排查/换项目复跑
```

镜像内工具链：Ubuntu 22.04 + LLVM/Clang 21（apt.llvm.org，RVV 发射与 SVF 构建共用）+ Z3（libz3-dev）+ riscv64 gcc 交叉 sysroot。llama.cpp 在镜像构建期克隆并拦截编译。

项目自带全部分源码与构建配置：`src/`（分析器主程序与库）、`include/`、`svf_src/`（含 RVV scalable-vector 补丁的 SVF 源码副本）。

## 依赖

- 分析器 `svf-vlenesc`：由本项目 `build.sh` 自建（`vlen-escape/build/bin/`），可用 `SVF_VLENESC` 覆盖。
- 外部工具链（env 可覆盖）：`RVV_LLVM_DIR`（RVV clang19）、`LLVM21_DIR`、`Z3_DIR`（构建时经 `-DLLVM_DIR/-DZ3_DIR` 传入，见 build.sh）。

## 测试

```bash
bash vlen-escape/selftest.sh    # hello_make 端到端 + 断言逃逸记录
```

