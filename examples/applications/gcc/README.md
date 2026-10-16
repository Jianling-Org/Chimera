# GCC 应用适配样例

本例说明如何把 GCC 构建树中的驱动 `xgcc` 与 C 前端 `cc1` 分别接入 Chimera。源码由集成者提供，本目录不包含 GCC 源码、专用脚本或预制 Workspace。目标为 Linux / RISC-V64 / RVV，集成记录中应固定 GCC 版本与构建选项。

## 源码与构建条件

准备选定版本的 GCC 源码、该版本规定的构建依赖、RISC-V64 工具链和目标 sysroot。保留源码版本、配置、补丁、宿主编译器和构建日志。常见依赖包括 GMP、MPFR、MPC 等，以所选源码要求为准。

`APP_SOURCE` 为 GCC 源码根，`APP_BUILD` 为新构建目录；`CONFIGURE_ARGS` 为读者保存的 Bash 数组，包含目标、语言和 sysroot 等所需选项。

```bash
mkdir -p "$APP_BUILD"
cd "$APP_BUILD"
"$APP_SOURCE/configure" "${CONFIGURE_ARGS[@]}"
make -j2 all-gcc
XGCC="$APP_BUILD/gcc/xgcc"
CC1="$APP_BUILD/gcc/cc1"
```

构建 GCC 所用编译器、是否 bootstrap 及运行依赖由集成者确认；`all-gcc` 这里只构建相应编译器部分，不代表已安装完整 GCC 或目标运行库。

## 检查两个 ELF

从 [双向 Profile](../../platforms/k3/linux-riscv64-rvv-1024-256-bidirectional.toml) 等现有配置复制到自己的集成目录，调整翻译器路径、scalar_root、工具与依赖根。所有 safety 范围选择须记录，细节见 [安全点文档](../../../doc/developer/architecture/safepoints/README.md)。

```bash
chimera-pkg check-elf --profile "$PROFILE" \
  --input "$XGCC" --input "$CC1" --json "$CHECK_REPORTS" --strict
```

`CHECK_REPORTS` 是目录。驱动调用前端是子进程边界，xgcc 的 Workspace 不会自动覆盖 cc1；两者分别需要最终 ELF、当前范围检查凭据和 Workspace。

## 必要的 metadata 与 gate 重编

初始检查发现问题时，可对同项目两个 ELF 生成合并计划，先增加元数据，再按新报告决定 gate：

```bash
chimera-pkg check-elf --profile "$PROFILE" --input "$XGCC" --input "$CC1" \
  --rebuild-stage metadata --rebuild-dir "$METADATA_PLAN"
mkdir -p "$METADATA_BUILD"
cd "$METADATA_BUILD"
CC="$METADATA_PLAN/cc" CXX="$METADATA_PLAN/cxx" \
  "$APP_SOURCE/configure" "${CONFIGURE_ARGS[@]}"
make -j2 all-gcc
chimera-pkg check-elf --profile "$PROFILE" \
  --input "$METADATA_BUILD/gcc/xgcc" --input "$METADATA_BUILD/gcc/cc1" \
  --rebuild-stage gate --rebuild-dir "$GATE_PLAN"
mkdir -p "$GATE_BUILD"
cd "$GATE_BUILD"
CC="$GATE_PLAN/cc" CXX="$GATE_PLAN/cxx" \
  "$APP_SOURCE/configure" "${CONFIGURE_ARGS[@]}"
make -j2 all-gcc
XGCC="$GATE_BUILD/gcc/xgcc"
CC1="$GATE_BUILD/gcc/cc1"
chimera-pkg check-elf --profile "$PROFILE" --input "$XGCC" --input "$CC1" --strict
```

路径变量均应为绝对路径，计划目录和构建目录须为新的。此例要求所选 GCC 能由计划的 patched Clang 构建，且报告给出兼容 gate 决策。版本所需配置、兼容补丁和禁用 bootstrap 等由集成者显式决定。metadata 已通过时可直接交付；SVF/function-pointer 决策不能交给 gate 计划。完整语义见 [集成 CLI](../../../doc/integration/cli.md#固定重编计划)。

## 准备与打包

```bash
chimera-pkg prepare --profile "$PROFILE" --input "$XGCC" --workspace gcc-xgcc
chimera-pkg prepare --profile "$PROFILE" --input "$CC1" --workspace gcc-cc1
chimera-pkg workspace pack --workspace gcc-xgcc --output gcc-xgcc.workspace
chimera-pkg workspace pack --workspace gcc-cc1 --output gcc-cc1.workspace
```

两次 prepare 各自必须完成。GCC 源码、构建树、头文件、specs、目标库和其他工具不会自动随包交付。目标机独立安装同内容 xgcc/cc1，保持驱动搜索前端、include 和库的布局，可用 `-B` 或对应 GCC 配置显式指定。测试源码可通过 `--resource "$TEST_SOURCE=inputs/test.c"` 附带，运行时显式传安装后路径。

## 最小运行验证

安装两个 Workspace 后，分别验证与注册：

```bash
chimera-user verify --workspace gcc-xgcc
chimera-user verify --workspace gcc-cc1
chimera-user register --workspace gcc-xgcc --input "$XGCC"
chimera-user register --workspace gcc-cc1 --input "$CC1"
chimera-user run --workspace gcc-xgcc --input "$XGCC" -- \
  -B "$GCC_EXEC_DIR/" -S "$TEST_SOURCE" -o "$OUTPUT_ASSEMBLY"
```

`GCC_EXEC_DIR` 指向正确前端及辅助工具目录，`TEST_SOURCE` 为确定性 C 输入。此调用验证驱动编译链；不能据此认定 cc1 子进程已在其自身 Workspace 下运行。

验证 cc1 时，先用原生驱动 `xgcc -###` 获得该输入实际使用的前端命令与参数，再把同一组参数显式传给：

```text
chimera-user run --workspace gcc-cc1 --input CC1 -- CC1_ARGUMENTS...
```

迁移验收使用足够长且结果可核对的输入，定位实际目标进程 PID/TID，等其 Runtime ready 后执行 `chimera-user migrate --workspace gcc-cc1 --threads TID --direction 1024-to-256`。驱动与前端不能混用 TID/Workspace。

## 验证与证据边界

保存两份 ELF 摘要、独立检查报告、两个包、输入源码、原生/Chimera 输出和退出码。同参数确定性输入可比较汇编；含路径等差异时记录规范化规则。静态检查、prepare、驱动完成编译和前端迁移应分别验证。

[应用集成者指南](../../../doc/integration/README.md) · [应用使用者指南](../../../doc/user/README.md)
