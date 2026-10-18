# Hello World 迁移样例

本目录的 [hello_world.c](hello_world.c) 是仓库自带的最小应用。它循环执行 RVV 整数计算，输出应用就绪、开始计算、校验和与参考值；用于检查构建、交付和迁移链路，不承担性能基准。

## 来源与依赖

需要 Linux / RISC-V64 / RVV 目标、支持 `<riscv_vector.h>` 的编译器、目标 `objdump/nm`、CMake、Python 与 Chimera。准备环境须有 scalar 底座与翻译器；运行环境还需匹配的 BPF map、迁移控制接口及权限。源文件支持便携标量分支，但 `CHIMERA_HELLO_VECTOR=portable` 不能证明 RVV 路径可用。

默认 Profile 为 [hello-world.toml](../../platforms/k3/hello-world.toml)，声明 1024→256 的翻译与 safety workflow。使用前核对工具名、`scalar_root` 和翻译器路径。Workspace 默认写入 CLI 配置的根目录；需要独立输出目录时，在 `prepare` 中传入 `--workspace-root`。

## 构建与严格检查

在仓库根目录执行：

```bash
PROFILE="$PWD/examples/platforms/k3/hello-world.toml"
OUTPUT="$PWD/build/examples/hello-world"
mkdir -p "$OUTPUT"
ELF="$OUTPUT/hello-world"
cc -O2 -g -std=c11 -pthread -march=rv64gcv -mabi=lp64d \
  examples/applications/hello-world/hello_world.c -o "$ELF"
chimera-pkg check-elf --profile "$PROFILE" --input "$ELF" --strict
```

这里的 `cc` 必须是目标编译器。也可用 [build_hello_world.sh](../../scripts/build/build_hello_world.sh) 执行构建、严格检查和 debug prepare：

```bash
CHIMERA_HELLO_CC=clang bash examples/scripts/build/build_hello_world.sh
```

脚本支持 `CHIMERA_HELLO_PROFILE`、`CHIMERA_EXAMPLE_ARTIFACT_ROOT` 和 `CHIMERA_HELLO_CFLAGS`；默认输出 `~/.chimera/examples/hello_world/hello-world`，Workspace 为 `hello_world`。覆盖参数时保留 RVV 与 ABI 选项，并用脚本输出的实际 ELF 路径继续操作。

若检查未通过，保留报告，按 [固定重编计划](../../../docs/deployment/cli.md#固定重编计划) 做必要的 metadata/gate 重编。单文件例子可直接使用计划中的 `cc`：

```bash
chimera-pkg check-elf --profile "$PROFILE" --input "$ELF" \
  --rebuild-stage metadata --rebuild-dir "$OUTPUT/metadata-plan"
"$OUTPUT/metadata-plan/cc" -O2 -g -std=c11 -pthread \
  -march=rv64gcv -mabi=lp64d \
  examples/applications/hello-world/hello_world.c -o "$OUTPUT/hello-world-metadata"
chimera-pkg check-elf --profile "$PROFILE" --input "$OUTPUT/hello-world-metadata" \
  --rebuild-stage gate --rebuild-dir "$OUTPUT/gate-plan"
"$OUTPUT/gate-plan/cc" -O2 -g -std=c11 -pthread \
  -march=rv64gcv -mabi=lp64d \
  examples/applications/hello-world/hello_world.c -o "$OUTPUT/hello-world-gate"
ELF="$OUTPUT/hello-world-gate"
chimera-pkg check-elf --profile "$PROFILE" --input "$ELF" --strict
```

metadata 结果已通过时可直接使用该产物，不必继续 gate。计划目录必须尚不存在，发现 SVF 决策时不能强制消费为 gate。安全分析细节见 [安全点文档](../../../docs/developer/architecture/safepoints/README.md)。

## 准备与交付

```bash
chimera-pkg --debug prepare --profile "$PROFILE" --input "$ELF" --workspace hello_world
chimera-pkg workspace pack --workspace hello_world --output "$OUTPUT/hello-world.workspace"
```

debug prepare 使 Runtime 保留迁移诊断，便于核对地址重写事件。包不包含应用；把最终 `ELF` 按应用安装方式放到目标机，确保内容一致，再执行 `chimera-pkg workspace install --input hello-world.workspace --name hello_world`。本例没有外部模型或数据文件。

## 显式运行与迁移

先在目标机把 `ELF` 设为已安装的最终文件路径：

```bash
chimera-user verify --workspace hello_world
chimera-user register --workspace hello_world --input "$ELF"
chimera-user --debug run --workspace hello_world --input "$ELF" > hello-world.log 2>&1 &
PID=$!
```

观察日志中的 `CHIMERA_HELLO_VECTOR=rvv`、`CHIMERA_HELLO_READY=1` 和 `CHIMERA_HELLO_ACTIVE=1`。这些是应用标记；还必须等 Runtime 信号处理器就绪。应用约运行一万轮，每轮有短暂停顿，及时在其存活期间提交：

```bash
chimera-user migrate --workspace hello_world --threads "$PID" --direction 1024-to-256
wait "$PID"
```

若报 `migration not ready`，等待 Runtime 初始化后在进程存活期间重试。

也可从仓库根目录使用 [run_hello_world.sh](../../scripts/run/run_hello_world.sh) 执行上述流程：

```bash
CHIMERA_EXAMPLE_ELF="$ELF" CHIMERA_EXAMPLE_WORKSPACE=hello_world \
  bash examples/scripts/run/run_hello_world.sh
```

脚本依次验证 Workspace、注册实际 ELF、启动应用并提交迁移请求，检查应用退出状态和地址重写日志。默认 ELF 为 `~/.chimera/examples/hello_world/hello-world`，可用 `CHIMERA_EXAMPLE_ELF` 覆盖；整个示例运行由 30 秒 watchdog 限时。

## 验证与证据边界

保留检查 JSON、最终 ELF 摘要、Workspace、运行日志和退出码。`CHIMERA_HELLO_CHECKSUM` 必须等于 `CHIMERA_HELLO_REFERENCE`，正常退出为 0。debug Runtime 的 `action=rewrite` 事件可用于确认发生地址重写；结合迁移前后线程核位置与 Runtime 事件判断实际迁移。`migrate` 返回 0 仅表示提交，应用 ready 标记和静态检查也不单独证明迁移完成。

[应用集成者指南](../../../docs/deployment/README.md) · [应用使用者指南](../../../docs/user/README.md)
