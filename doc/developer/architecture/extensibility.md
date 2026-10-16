# 扩展 step、target、scene 与 capability

扩展通过已有的组合入口注册，配置只能选择已注册的实现；当前没有通用的第三方 entry-point 自动发现机制。

## 扩展层次与真实入口

| 扩展对象 | 注册入口 | 必须同时考虑的契约 |
| --- | --- | --- |
| 离线 step | `analysis_profile/registry.py` 的 `StepCatalog`、`common_step_definitions()` 与 bundle 的 `step_definitions` | 参数、`requires/provides`、重复性、执行后条件、replay、检查与发布校验 |
| 离线 target | `analysis_profile/target.py` 的 `TargetCatalog`、`registered_target_catalog()` | `PrepareTargetBundle`、服务、生产规范、property schema、runtime 构建规格与完成要求 |
| Runtime 工件场景契约 | `runtime/artifacts/scene_contracts/chimera/scene_contracts/composition.py` | ELF machine、scene marker、ABI 与必要导出符号 |
| Python 在线验证 scene | `runtime/artifacts/validate/chimera/validate/scenes.py` 的 `registered_scene_verifiers()` | 拓扑、capability handlers 与 host verifier |
| 启动与迁移适配 | `runtime/launcher/run/chimera/launcher/{adapters,migration}.py` | 启动环境、方向编码、线程就绪政策 |
| C scene 装载 | `runtime/artifacts/manifest/linux_riscv64_rvv_v1/reader.c` 的 `scene_handlers` | 四元 key、装载函数与 C registry |
| Python capability | `runtime/artifacts/validate/chimera/validate/capabilities.py` 的 `registered_capability_handlers()` | `(capability, representation)` 到验证器的映射 |
| C capability | `runtime/artifacts/manifest/linux_riscv64_rvv_v1/capability_loaders.c` 的注册表 | owner、表示、ABI、数量与 loader 回调 |
| C 构建场景 | `runtime/CMakeLists.txt`、`runtime/interfaces/profiles/<scene>/runtime.cmake` | 场景源文件、导出、头文件和构建支持 |

表中的 `analysis_profile/` 均位于 `preprocessing/offline/` 下。target 与 scene 的职责划分见[目标与场景](targets/README.md)。新增目标需要实际实现和贯通这些层，不能只追加一个 `TargetKey`。

## 编写 step 的约束

step 实现 `name` 与 `run(context) -> AnalysisContext`，从服务和显式输入获取数据。公共输入列入 `requires`，公共输出列入 `provides`；不可依赖某个全局结果碰巧仍留在内存。参数由 `ParameterSpec` 限定，未知字段会被拒绝。

生产文件先写入 staging，再以 `ArtifactRecord` 登记到 session registry。工件 ID、所有者、用途、表示、ABI、消费者、相对路径和整文件 SHA-256 必须明确。需要阻止发布的条件应注册 publication validator，由 finalizer 统一执行。生产者不自行提交目录，也不修改输入 ELF。

需要二进制准入的 step 提供 `binary_check_factory(parameters) -> BinaryCheckRequest`，由检查计划直接运行；检查工厂不应通过生产 step 的构造或 `run()` 间接执行生产。检查语义变化时更新版本，以使旧凭据失效。

支持增量重建时，为可跳过的 step 实现 `replay(parameters, context)`；若成本很低且每次都应重新生产，可设置 `rebuild_execute=True`。`rebuild_inputs` 描述影响结果的数据输入，不能把 session 记账误当作数据传播。缺少这些安排的 step 可能能 prepare，却不能在跳过时被 rebuild 恢复。

## 最小示例：可选模块报告

以下是供开发者加入源码的示例，不是当前默认 catalog 已提供的 step。它只汇总已选模块，不改变安全分析或 Runtime 必需能力。可将实现放入 `preprocessing/offline/analysis/module_report.py`：

```python
import json

from chimera.preprocess.offline.analysis.core.contracts import AnalysisContext
from chimera.preprocess.offline.analysis.core.workspace import sha256_file
from chimera.preprocess.offline.analysis_profile.registry import StepDefinition
from chimera.runtime.manifest import ArtifactRecord


class ModuleReportStep:
    name = "module-report"

    def run(self, context: AnalysisContext) -> AnalysisContext:
        if context.stage is None:
            raise RuntimeError("module-report 需要暂存目录")
        session = context.require_global("workspace_session")
        document = {
            "format": "chimera-module-report-v1",
            "modules": [
                {
                    "module_id": module.module_id,
                    "runtime_name": module.selected_path.name,
                    "delivery": module.delivery,
                }
                for module in context.require_global("modules")
            ],
        }
        path = context.stage / "artifacts" / "module-report.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        session.registry.register_artifact(ArtifactRecord(
            artifact_id="module-report",
            owner_kind="workspace",
            owner_id="root",
            capability="module-report",
            representation="json",
            abi=1,
            required_by=frozenset(),
            path=path.relative_to(context.stage).as_posix(),
            sha256=sha256_file(path),
        ))
        return context.put_global("module_report", path)


REPORT_STEP = StepDefinition(
    name="module-report",
    parameters={},
    requires=frozenset({"workspace_session", "modules"}),
    provides=frozenset({"module_report", "workspace_contributions"}),
    repeatable=False,
    factory=lambda _p, _configuration, _repository: ModuleReportStep(),
    rebuild_execute=True,
)
```

在 `analysis_profile/target.py` 的 `current_target_bundle()` 内局部导入 `REPORT_STEP`，将该 bundle 的 `step_definitions` 字段改为下列组合。局部导入避免本例从 registry 导入 `StepDefinition` 时形成模块初始化循环。

```python
from chimera.preprocess.offline.analysis.module_report import REPORT_STEP

# 放在 current_target_bundle() 内，并用于 PrepareTargetBundle 的对应字段。
step_definitions = (
    *rvv_step_definitions(translation_semantics=translation_semantics),
    REPORT_STEP,
)
```

上面的局部变量应作为 `PrepareTargetBundle(..., step_definitions=step_definitions, ...)` 的实际实参，不能只定义后仍保留旧字段值。若实现与某个目标无关，也可由维护者在通用 catalog 的组合处登记；不要同时向同一 catalog 登记两次相同名称。

在完整 Profile 的 workflow 中，把以下声明放到 `prepare-workspace` 之后、`finalize-workspace` 之前：

```toml
[[profile.workflow.steps]]
step = "module-report"
```

报告没有参数、不可重复，每次 rebuild 执行，因而无需 replay。`workspace_contributions` 由流水线追加，本例不手动更新它；finalizer 因该屏障等待报告完成。自定义 `module_report` 结果仍显式返回，以满足 `provides`。

`required_by` 为空使它成为 Runtime 可忽略的可选工件，但 Manifest 仍校验文件路径和 SHA-256。默认打包会携带 `artifacts/` 中这份报告。若未来让 Runtime 依赖它，应增加 Python 语义验证器和 C capability 契约，再把 `runtime` 加入消费者；只改 `required_by` 会使当前验证器拒绝未知必需 capability。

## 扩展 target 与协议能力

`PrepareTargetBundle` 注入 architecture、extension、platform、toolchain 工厂，以及 `translation_semantics`、`trap_patch_services`、Runtime 构建规格和发布校验。通用 step 依赖 `core/contracts/services.py` 中的协议，不应在流水线里硬编码新目标的路径和指令。

最小 `ArchitectureExtensionServices` 提供名称和标量栈语义；向量分析通过可选 `VectorExtensionServices` 暴露。ELF 专属步骤检查 `ElfModuleServices`，补丁步骤检查 `TrapPatchServices`，工件生产检查 `ArtifactEmitter`。所需能力缺失时，step 应在开始生产前报错并停止。

`TranslationSemantics` 负责端点合法性、`TranslationProductionSpec`、Manifest 属性及属性到端点的恢复。输出路径必须留在 staging，不能覆盖受保护模块；补丁机制还要求独立的未打补丁翻译副本与摘要。通用 registry 只检查记录结构，某种新 property 的目标语义需要 bundle 和在线 scene 一起验证。

## 扩展检查范围

应验证普通 prepare、缺输入/错参数、重复声明、集合消费者过早、工件摘要或 owner 错误、失败时 staging 清理，以及 rebuild 的执行传播和 replay。新增在线必需能力还应验证未知必需能力拒绝、ABI/scene 不匹配、初始化失败不启用迁移、映射失败政策。代码检查可以证明相应分支行为，真实目标机的内核通知、信号上下文和迁移执行仍需单独验收。

相关设计见[离线流水线](offline.md)、[在线运行时](runtime.md)和 [ABI](../abi/README.md)。
