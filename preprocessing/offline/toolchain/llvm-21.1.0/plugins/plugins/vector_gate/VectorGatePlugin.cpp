//
// ChimeraVectorGate — keep listed functions out of implicit vectorization.
//
// The plugin stamps the "chimera-no-vectorize" function attribute on every
// listed function and, at the end of IR optimization, stamps a stable census
// function id for code generation.  Everything else reads those attributes:
//
//   * the patched LoopVectorize/SLPVectorizer decision points reject a gated
//     positive decision immediately before committing vector IR;
//   * the RISC-V memcpy/memset lowering and the DAG store-merging path
//     check it directly and suppress their vector forms (memop / store
//     merging classes, toolchain patches 0010/0011);
//   * counting lives with each mechanism as well — the per-mechanism
//     unified implicit-vector-census records are written by those patches
//     into CHIMERA_GATE_STATS.
//
// Historical components retired when the attribute-driven backend
// switches landed: MemopScalarPass (IR-level memop expansion), the
// "-v" target-feature stripping with its functionHasRvvCode guard, and
// the VectorScanPass residual monitor — the attribute now reaches every
// generation site directly, so there is no "skip-if-intrinsics" escape
// and no residual class left unaccounted.
//
// Registered callbacks:
//
//   PipelineStartEP / FullLinkTimeOptimizationEarlyEP   GateMarkPass
//       Count defined functions, match them against the gate list
//       (one mangled name per line) and stamp matching functions with
//       "chimera-no-vectorize".  PipelineStartEP covers plain compile
//       pipelines (-fpass-plugin); the full-LTO post-link pipeline
//       (buildLTODefaultPipeline, i.e. `-flto` links through lld) does
//       NOT fire PipelineStartEP/OptimizerLastEP — it only fires the
//       FullLinkTimeOptimization EPs, so both EPs must be registered.
//
//   OptimizerLastEP / FullLinkTimeOptimizationLastEP   CensusIdPass
//       Attach "chimera-census-function-id" after inlining and other IR
//       optimization so the RISC-V memop lowering can attribute its decision
//       without changing the optimization-time function identity.
//
//   Caveat: under `-flto=thin` (buildThinLTODefaultPipeline) neither
//   pair fires PipelineStartEP for GateMarkPass; the gate silently does
//   not apply there.  Use full `-flto`.
//
// Parameters (cl::opt, forwarded by the driver as -mllvm arguments —
// unusable with lld, which parses -mllvm before loading pass plugins;
// the environment fallback below is the supported channel at link time):
//
//   -chimera-gate-list=<path>   one mangled name per line (required for
//                               gating; an empty path disables the pass)
// Environment fallback: CHIMERA_GATE_LIST is used when the cl::opt is
// empty, so the wrapper can drive the pass without flag-ordering concerns.
//

#include "llvm/IR/Attributes.h"
#include "llvm/IR/ChimeraImplicitVectorCensus.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

#include <cstdlib>
#include <fstream>
#include <set>
#include <string>
#include <utility>

using namespace llvm;

namespace {

// Consumed by the patched LoopVectorize/SLPVectorizer (auto-vectorization
// class), the patched RISCVISelLowering memcpy/memset lowering (memop
// class) and the patched DAGCombiner store merging (store-merging class).
constexpr const char *kGateAttr = "chimera-no-vectorize";

cl::opt<std::string> GateListPath(
    "chimera-gate-list",
    cl::desc("chimera vector gate: file of mangled function names to keep "
             "unvectorized (one per line)"),
    cl::init(""));

cl::opt<std::string> GateListEnv(
    "chimera-gate-list-env",
    cl::desc("chimera vector gate: environment variable holding the list "
             "path (fallback when -chimera-gate-list is empty)"),
    cl::init("CHIMERA_GATE_LIST"));

std::string resolveGateListPath() {
  if (!GateListPath.empty()) {
    return GateListPath.getValue();
  }
  const char *from_env = std::getenv(GateListEnv.getValue().c_str());
  return from_env ? std::string(from_env) : std::string();
}

std::set<std::string> loadNames(const std::string &path) {
  std::set<std::string> names;
  if (path.empty()) {
    return names;
  }
  std::ifstream stream(path);
  std::string line;
  while (std::getline(stream, line)) {
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
      line.pop_back();
    }
    if (!line.empty()) {
      names.insert(line);
    }
  }
  return names;
}

// Constructors and destructors exist as C1/C2 (and D1/D2) alias pairs
// pointing at one body: the IR module defines the C2/D2 name while the
// ELF symbol table — where check-elf collects gate names from — exposes
// whichever alias objdump prints, typically C1/D1.  A gate list holding
// only the C1 spelling therefore never matches the IR definition and the
// function silently stays un-gated, resurfacing as a local-root finding
// every remediation round.  Global ELF validation, rather than per-module
// diagnostics, is responsible for detecting an ineffective list.
//
// Matching must try the alias spelling.  Parameter TYPES never contain
// constructor/destructor tags, so every C1/C2 or D1/D2 sequence in a mangled
// name belongs to the function's own (or its enclosing, for lambdas) special
// member — swapping all occurrences is safe, and a swapped spelling that
// matches nothing is simply an inert extra name.
std::set<std::string> expandSpecialMemberVariants(
    const std::set<std::string> &names) {
  static const std::pair<std::string, std::string> Swaps[] = {
      {"C1", "C2"}, {"C2", "C1"}, {"D1", "D2"}, {"D2", "D1"},
  };
  std::set<std::string> expanded = names;
  for (const std::string &name : names) {
    for (const auto &[from, to] : Swaps) {
      std::string variant = name;
      std::string::size_type pos = variant.find(from);
      if (pos == std::string::npos) {
        continue;
      }
      while (pos != std::string::npos) {
        variant.replace(pos, from.size(), to);
        pos = variant.find(from, pos + to.size());
      }
      expanded.insert(variant);
    }
  }
  return expanded;
}

class GateMarkPass : public PassInfoMixin<GateMarkPass> {
public:
  PreservedAnalyses run(Module &module, ModuleAnalysisManager &) {
    const std::string path = resolveGateListPath();
    const std::set<std::string> names = loadNames(path);
    // Match against C1/C2 (D1/D2) alias spellings: see
    // expandSpecialMemberVariants.
    const std::set<std::string> matchNames =
        names.empty() ? names : expandSpecialMemberVariants(names);

    bool changed = false;

    for (Function &function : module) {
      if (function.isDeclaration()) {
        continue;
      }
      if (matchNames.count(function.getName().str())) {
        function.addFnAttr(kGateAttr);
        changed = true;
      }
    }

    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};

class CensusIdPass : public PassInfoMixin<CensusIdPass> {
public:
  PreservedAnalyses run(Module &module, ModuleAnalysisManager &) {
    if (!chimeraImplicitVectorCensusEnabled())
      return PreservedAnalyses::all();
    bool changed = false;
    for (Function &function : module) {
      if (function.isDeclaration())
        continue;
      const std::string id = chimeraCanonicalFunctionName(function.getName());
      Attribute current = function.getFnAttribute(kChimeraCensusFunctionIdAttr);
      if (current.isValid() && current.getValueAsString() == id)
        continue;
      function.addFnAttr(kChimeraCensusFunctionIdAttr, id);
      changed = true;
    }
    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "ChimeraVectorGate",
      LLVM_VERSION_STRING,
      [](PassBuilder &PB) {
        PB.registerPipelineStartEPCallback(
            [](ModulePassManager &MPM, OptimizationLevel) {
              MPM.addPass(GateMarkPass());
            });
        // 全量 LTO 链接管线（buildLTODefaultPipeline）不触发
        // PipelineStartEP，只触发 FullLinkTimeOptimizationEarlyEP；
        // 两者签名都是两参。
        PB.registerFullLinkTimeOptimizationEarlyEPCallback(
            [](ModulePassManager &MPM, OptimizationLevel) {
              MPM.addPass(GateMarkPass());
            });
        PB.registerOptimizerLastEPCallback(
            [](ModulePassManager &MPM, OptimizationLevel,
               ThinOrFullLTOPhase Phase) {
              // A pre-link ID would survive in bitcode and be visible to the
              // LTO inliner.  The full-LTO post-link callback below supplies
              // the ID after that inlining is complete.
              if (Phase != ThinOrFullLTOPhase::ThinLTOPreLink &&
                  Phase != ThinOrFullLTOPhase::FullLTOPreLink)
                MPM.addPass(CensusIdPass());
            });
        PB.registerFullLinkTimeOptimizationLastEPCallback(
            [](ModulePassManager &MPM, OptimizationLevel) {
              MPM.addPass(CensusIdPass());
            });
      }};
}
