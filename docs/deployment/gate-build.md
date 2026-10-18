# Gate 构建

Gate 按函数决策清单禁用编译器隐式向量化，帮助应用满足跨 VLEN 迁移所需的栈状态和安全条件。清单之外的计算路径可以继续使用 RVV。Gate 构建完成后，仍需对最终 ELF 执行严格检查。

## 工具链要求

使用项目维护的 LLVM 21.1.0 补丁、VectorGate 插件和编译包装器，构建方法见[构建与测试](../developer/build-and-test.md#llvm-与插件)。三个部分共同实现按函数约束：

1. 包装器将 JSON 决策导出为逐行 mangled symbol 名单，并配置 `CHIMERA_GATE_LIST` 和 census 输出路径。
2. VectorGate 为匹配函数添加 `chimera-no-vectorize` 属性。
3. LLVM 补丁在 LoopVectorize、SLP、RISC-V memcpy/memset lowering 和 DAG store merging 中阻止对应的隐式向量生成。

`tools/write_gate_wrapper.py` 生成 CC/CXX 包装器，调用 `chimera-pkg llvm [--cxx] --list DECISION -- COMPILER_ARGS`。JSON 决策由驱动转换后供插件使用。

完整约束依赖上述工具链。仅设置 `-fno-vectorize` 或仅在链接时加载插件，覆盖范围与该流程不同。显式 intrinsic、内联汇编和既有向量指令仍由最终 ELF 检查判定。

## 重编流程

在应用构建环境中执行以下步骤，命令见[固定重编计划](cli.md#固定重编计划)和[端到端应用集成](end-to-end-rvv.md)。

1. 检查原始 ELF。报告要求编译器元数据时，生成 metadata 重编计划，启用 stack-object 插桩后重新构建并检查。
2. 根据检查结果生成 gate 重编计划，保留 stack-object 插桩并固定决策清单。
3. 将应用的 CC/CXX 配置为计划生成的包装器，清洁构建相应对象；保存编译、链接命令、决策和 census（编译统计），与同次构建的最终 ELF 一并留存。
4. 对最终 ELF 执行 `chimera-pkg check-elf --strict --strategy gate --profile "$PROFILE" --input "$ELF"`。检查通过后，使用同一 ELF 和 Profile 执行 `prepare`，再完成目标机运行验证。

原始 ELF 已通过检查时，可直接进入准备流程。应用、依赖、编译选项或工具链变化后，应检查新的最终 ELF。

## LTO

普通编译通过 `PipelineStartEP` 标记函数；full LTO 还通过 `FullLinkTimeOptimizationEarlyEP` 标记。两种方式都要求编译包装器覆盖各个翻译单元。

当前 ThinLTO 回调覆盖有限。需要 LTO 的 gate 构建应采用已验证的 full `-flto` 配置，并核对编译与链接命令；`-flto=thin` 不属于已验证的配置。

lld 在装载插件前解析部分参数，正式驱动通过环境变量回退传递符号清单。使用该驱动管理插件与参数的注入顺序。

## llama.cpp 示例

[双向自动迁移示例](../../examples/applications/llama-cpp/reference-v32/README.md)使用启用 OpenMP 的 llama-perplexity，提供包含 1,245 个名字的 [gate 决策](../../examples/applications/llama-cpp/reference-v32/gate.decision.json)。清单包含 `common_params_parser_init`；`ggml_vec_dot_q3_K_q8_K` 等计算路径保留 RVV 算术和 VLEN 分派。

示例安全 Profile 使用 `assume-scalar-independent` 与绑定 libc 内容的 memset scalar-leaf 契约，因此静态检查结论为 `conditional`。更换 libc 时需重新核验契约条件；配置与依赖准备见示例页面。
