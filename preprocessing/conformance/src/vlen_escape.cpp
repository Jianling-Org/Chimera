//===----------------------------------------------------------------------===//
// vlen_escape.cpp — vlen (vsetvl/vlenb) escape analysis
//
// Module-level scan: every defined function containing a call whose callee
// name contains "vsetvl" or "vlenb" (covers __riscv_vsetvl*, __riscv_vsetvli*,
// __riscv_vsetvlmax*, __riscv_vlenb, llvm.riscv.*) is a root function. Per
// root, a small taint analysis (Andersen pts for store/load targets) decides
// whether the vlen value escapes the root's scope.
//
// Taint rules (worklist to fixpoint, monotone):
//   1. seeds: vsetvl/vlenb call results of the root (derived=false).
//   2. SSA: binop / value-changing cast / insertvalue / extractvalue / gep
//      with a tainted operand => tainted, derived=true; phi/select/bitcast
//      => tainted, inherit derived.
//   3. `ret tainted`: in the root => RETURN escape; in another function H on
//      the taint chain => mark H returns-tainted and taint the results of
//      all callsites (within the chain) that call H (fixpoint iteration).
//   4. `store tainted, P`: objs = pts(P) (empty when P has no PAG node).
//      isHeap => HEAP; isGlobalObj/isStaticObj => GLOBAL; isStack => holder
//      (no escape); other => UNKNOWN. objs empty => def-use backtrack P
//      (bitcast/gep/phi/select/addrspacecast, plus loads from spill allocas
//      for -O0 form) to an llvm::Argument => PARAM, else UNKNOWN. Every
//      written object (STACK included) joins holders. confidence: single
//      clearly-classified object => exact; multiple => may; UNKNOWN kind =>
//      unknown; escapes downstream of holder-loads floor at may.
//   5. `load P` with pts(P) intersecting holders => result tainted (derived
//      = OR of the hit holders); such escapes are at least may.
//   6. `call` with tainted actuals: callee name containing "riscv" or
//      starting with "llvm." => ignored; libc whitelist => ignored; direct
//      call with a body => taint the formal at the position (depth-capped at
//      -max-depth, excess marks truncated_depth), vararg position =>
//      UNKNOWN_CALL+uncertain; declaration-only => UNKNOWN_CALL+uncertain;
//      indirect => resolved via the Andersen call graph's indCallMap,
//      unresolved => UNKNOWN_CALL+uncertain.
//   7. Escape locations come from the instruction's DILocation.
//===----------------------------------------------------------------------===//

#include "vlen_escape.h"

#include "SVF-LLVM/LLVMModule.h"
#include "Util/SVFUtil.h"

#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include <algorithm>
#include <queue>

namespace rvirvv {

namespace {

/// libc / runtime functions whose pointer args are not treated as escaping.
bool isWhitelistedCall(const std::string &name) {
    static const char *const kWhitelist[] = {
        "memcpy", "memmove", "memset", "strlen", "strcmp", "strncmp",
        "malloc", "calloc", "realloc", "free", "qsort", "abort", "assert",
        "fprintf", "printf", "snprintf", "fwrite", "__assert_fail",
    };
    for (const char *w : kWhitelist)
        if (name == w) return true;
    return false;
}

/// Normalize an object node to its base object.
const SVF::BaseObjVar *baseObjOf(const SVF::SVFVar *var) {
    if (const auto *b = SVF::SVFUtil::dyn_cast<SVF::BaseObjVar>(var))
        return b;
    if (const auto *g = SVF::SVFUtil::dyn_cast<SVF::GepObjVar>(var))
        return g->getBaseObj();
    return nullptr;
}

} // anonymous namespace

VlenEscapeAnalyzer::VlenEscapeAnalyzer(SVF::SVFIR *pag, SVF::Andersen *ander)
    : pag_(pag), ander_(ander) {}

bool VlenEscapeAnalyzer::isVlenSourceName(const std::string &name) const {
    return name.find("vsetvl") != std::string::npos ||
           name.find("vlenb") != std::string::npos;
}

VlenEscapeAnalyzer::VlenCallInfo VlenEscapeAnalyzer::classifyVlenCall(
    const llvm::CallBase *cb) const {
    VlenCallInfo info;
    if (!cb) return info;

    // Inline asm: vlen may appear only inside the asm string.
    if (cb->isInlineAsm()) {
        const auto *ia = llvm::dyn_cast<llvm::InlineAsm>(cb->getCalledOperand());
        if (!ia) return info;
        std::string asmStr = ia->getAsmString().str();
        const bool hasVsetvl = asmStr.find("vsetvl") != std::string::npos;
        const bool hasVlenb = asmStr.find("vlenb") != std::string::npos;
        if (!hasVsetvl && !hasVlenb) return info;
        if (asmStr.size() > 40) asmStr = asmStr.substr(0, 40);
        info.display = "asm(\"" + asmStr + "\")";
        if (hasVlenb && cb->getType()->isIntegerTy()) {
            info.kind = VlenSrcKind::AsmVlenb; // result carries the vlen value
        } else {
            info.kind = VlenSrcKind::AsmUntrackable;
        }
        return info;
    }

    const llvm::Function *callee = cb->getCalledFunction();
    if (!callee) return info;
    const std::string name = callee->getName().str();

    if (isVlenSourceName(name)) {
        info.kind = VlenSrcKind::VsetvlLike;
        info.display = name;
        return info;
    }

    // llvm.read_register.i64(metadata !{!"vlenb"}) — clang's lowering of
    // __riscv_vlenb(): the call result IS the vlen value.
    if (name.rfind("llvm.read_register", 0) == 0 && cb->arg_size() > 0) {
        if (const auto *mav = llvm::dyn_cast<llvm::MetadataAsValue>(
                cb->getArgOperand(0))) {
            const llvm::MDNode *md =
                llvm::dyn_cast<llvm::MDNode>(mav->getMetadata());
            if (md && md->getNumOperands() > 0)
                if (const auto *mds = llvm::dyn_cast<llvm::MDString>(
                        md->getOperand(0).get()))
                    if (mds->getString().find("vlen") != std::string::npos) {
                        info.kind = VlenSrcKind::ReadRegister;
                        info.display = "llvm.read_register(\"" +
                                       mds->getString().str() + "\")";
                        return info;
                    }
        }
    }
    return info;
}

namespace {

/// Per-root taint state.
struct TaintState {
    const llvm::Function *root = nullptr;
    std::map<const llvm::Value *, bool> tainted;   // value -> derived
    std::map<const llvm::Value *, bool> processed; // derived watermark
    std::set<const llvm::Value *> mayMarked;       // holder-load-derived values
    std::map<SVF::NodeID, bool> holders;           // written objects -> derived
    std::set<const llvm::Function *> returnsTainted;
    std::map<const llvm::Function *, std::vector<const llvm::CallBase *>> callersOf;
    std::map<const llvm::Function *, unsigned> depthOf;
    std::vector<const llvm::LoadInst *> loadCandidates;
    std::vector<const llvm::Value *> worklist;
    std::set<const llvm::Function *> loadsCollected;
    std::map<const llvm::Instruction *, std::vector<const llvm::Function *>> indTargets;
    bool truncated = false;
};

} // anonymous namespace

long VlenEscapeAnalyzer::countModuleUnresolvedIndirect() {
    SVF::LLVMModuleSet *ms = SVF::LLVMModuleSet::getLLVMModuleSet();
    SVF::CallGraph *cg = ander_->getCallGraph();
    // Resolved indirect callsites (llvm instructions).
    std::set<const llvm::Instruction *> resolved;
    if (cg) {
        for (const auto &kv : cg->getIndCallMap()) {
            if (kv.second.empty()) continue;
            if (ms->hasLLVMValue(kv.first))
                if (const auto *i = llvm::dyn_cast<llvm::Instruction>(
                        ms->getLLVMValue(kv.first)))
                    resolved.insert(i);
        }
    }
    long total = 0;
    for (llvm::Module &mod : ms->getLLVMModules())
        for (const llvm::Function &f : mod) {
            if (f.isDeclaration()) continue;
            for (const llvm::BasicBlock &bb : f)
                for (const llvm::Instruction &i : bb)
                    if (const auto *cb = llvm::dyn_cast<llvm::CallBase>(&i))
                        if (!cb->isInlineAsm() && !cb->getCalledFunction() &&
                            !resolved.count(&i))
                            ++total;
        }
    return total;
}

VlenEscapeResult VlenEscapeAnalyzer::analyze(const std::string &moduleName) {
    VlenEscapeResult result;
    result.module = moduleName;
    SVF::LLVMModuleSet *ms = SVF::LLVMModuleSet::getLLVMModuleSet();

    std::vector<const llvm::Function *> defined;
    for (llvm::Module &mod : ms->getLLVMModules())
        for (const llvm::Function &f : mod)
            if (!f.isDeclaration())
                defined.push_back(&f);
    result.function_count = defined.size();
    result.unresolved_indirect_calls = countModuleUnresolvedIndirect();

    for (const llvm::Function *f : defined) {
        bool isReader = false;
        for (const llvm::BasicBlock &bb : *f) {
            if (isReader) break;
            for (const llvm::Instruction &i : bb) {
                const auto *cb = llvm::dyn_cast<llvm::CallBase>(&i);
                if (!cb) continue;
                if (classifyVlenCall(cb).kind != VlenSrcKind::None) {
                    isReader = true;
                    break;
                }
            }
        }
        if (!isReader) continue;
        VlenRootResult rr;
        rr.name = f->getName().str();
        if (const llvm::DISubprogram *sp = f->getSubprogram()) {
            rr.file = sp->getFilename().str();
            rr.line = sp->getLine();
        }
        analyzeRoot(f, rr, result.truncated_depth);
        result.functions.push_back(rr);
    }
    return result;
}

void VlenEscapeAnalyzer::analyzeRoot(const llvm::Function *root,
                                     VlenRootResult &out, bool &truncatedOut) {
    SVF::LLVMModuleSet *ms = SVF::LLVMModuleSet::getLLVMModuleSet();
    SVF::CallGraph *cg = ander_->getCallGraph();
    TaintState st;
    st.root = root;
    st.depthOf[root] = 0;

    // Resolved indirect call targets: llvm instruction -> callee functions.
    if (cg) {
        for (const auto &kv : cg->getIndCallMap()) {
            if (kv.second.empty()) continue;
            if (!ms->hasLLVMValue(kv.first)) continue;
            const auto *inst = llvm::dyn_cast<llvm::Instruction>(
                ms->getLLVMValue(kv.first));
            if (!inst) continue;
            for (const SVF::FunObjVar *calleeFun : kv.second)
                if (const llvm::Function *cf =
                        ms->getFunction(calleeFun->getName()))
                    st.indTargets[inst].push_back(cf);
        }
    }

    auto ptsOf = [&](const llvm::Value *v) -> std::set<SVF::NodeID> {
        std::set<SVF::NodeID> out_;
        if (!ms->hasValueNode(v)) return out_; // no PAG node: treat as empty
        for (SVF::NodeID o : ander_->getPts(ms->getValueNode(v)))
            out_.insert(o);
        return out_;
    };

    auto baseOfId = [&](SVF::NodeID id) -> const SVF::BaseObjVar * {
        return baseObjOf(pag_->getGNode(id));
    };

    auto recordEscape = [&](const std::string &kind, const llvm::Instruction *inst,
                            const std::string &target, bool derived,
                            const std::string &confidence) {
        std::string func = inst->getFunction()->getName().str();
        std::string file;
        unsigned line = 0, col = 0;
        const llvm::DebugLoc dl = inst->getDebugLoc();
        if (dl) {
            file = dl->getFilename().str();
            line = dl->getLine();
            col = dl->getColumn();
        }
        std::string key = kind + "|" + func + "|" + file + "|" +
                          std::to_string(line) + ":" + std::to_string(col) +
                          "|" + target;
        for (const VlenEscape &e : out.escapes)
            if (e.kind == kind && e.function == func && e.file == file &&
                e.line == line && e.column == col && e.target == target)
                return; // dedup
        (void)key;
        VlenEscape e;
        e.kind = kind;
        e.function = func;
        e.file = file;
        e.line = line;
        e.column = col;
        e.target = target;
        e.derived = derived;
        e.confidence = confidence;
        out.escapes.push_back(e);
        if (kind == "UNKNOWN_CALL" || kind == "UNKNOWN")
            out.uncertain = true;
    };

    // Forward declarations of the mutually recursive helpers via std::function
    // is overkill; the worklist loop below drives everything.

    auto taint = [&](const llvm::Value *v, bool derived, bool mayFromHolder) {
        auto it = st.tainted.find(v);
        const bool merged = it != st.tainted.end() ? (it->second || derived) : derived;
        if (it != st.tainted.end() && it->second == merged && !mayFromHolder)
            return; // no new information
        if (it != st.tainted.end() && it->second == merged &&
            mayFromHolder && st.mayMarked.count(v))
            return;
        st.tainted[v] = merged;
        if (mayFromHolder) st.mayMarked.insert(v);
        st.worklist.push_back(v);
    };

    auto collectLoads = [&](const llvm::Function *f) {
        if (!st.loadsCollected.insert(f).second) return;
        for (const llvm::BasicBlock &bb : *f)
            for (const llvm::Instruction &i : bb)
                if (const auto *li = llvm::dyn_cast<llvm::LoadInst>(&i))
                    st.loadCandidates.push_back(li);
    };

    // Backtrack a store destination to an Argument (bitcast/gep/phi/select/
    // addrspacecast, plus loads from spill allocas for -O0 form).
    auto backtrackToArg = [&](const llvm::Value *v) -> const llvm::Argument * {
        std::vector<const llvm::Value *> wl(1, v);
        std::set<const llvm::Value *> seen;
        while (!wl.empty()) {
            const llvm::Value *cur = wl.back();
            wl.pop_back();
            if (!cur || !seen.insert(cur).second) continue;
            cur = cur->stripPointerCasts();
            if (const auto *arg = llvm::dyn_cast<llvm::Argument>(cur))
                return arg;
            if (const auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(cur)) {
                wl.push_back(gep->getPointerOperand());
            } else if (const auto *pn = llvm::dyn_cast<llvm::PHINode>(cur)) {
                for (const llvm::Value *iv : pn->incoming_values())
                    wl.push_back(iv);
            } else if (const auto *sv = llvm::dyn_cast<llvm::SelectInst>(cur)) {
                wl.push_back(sv->getTrueValue());
                wl.push_back(sv->getFalseValue());
            } else if (const auto *li = llvm::dyn_cast<llvm::LoadInst>(cur)) {
                // -O0 spill: continue through the alloca's stored values.
                if (const auto *A = llvm::dyn_cast<llvm::AllocaInst>(
                        li->getPointerOperand()->stripPointerCasts()))
                    for (const llvm::User *au : A->users())
                        if (const auto *si = llvm::dyn_cast<llvm::StoreInst>(au))
                            if (si->getPointerOperand() == A)
                                wl.push_back(si->getValueOperand());
            }
        }
        return nullptr;
    };

    collectLoads(root);
    // Seeds: vlen read points inside the root (vsetvl/vlenb calls,
    // llvm.read_register("vlen*"), inline-asm vlenb with integer result).
    // Inline-asm vsetvl forms without an SSA-visible value only mark the
    // function as an uncertain reader (no seed, verdict stays LOCAL_ONLY).
    for (const llvm::BasicBlock &bb : *root) {
        for (const llvm::Instruction &i : bb) {
            const auto *cb = llvm::dyn_cast<llvm::CallBase>(&i);
            if (!cb) continue;
            const VlenCallInfo vc = classifyVlenCall(cb);
            if (vc.kind == VlenSrcKind::None) continue;
            VlenRead vr;
            vr.callee = vc.display;
            const llvm::DebugLoc dl = i.getDebugLoc();
            if (dl) {
                vr.line = dl->getLine();
                vr.column = dl->getColumn();
            }
            if (vc.kind == VlenSrcKind::AsmUntrackable) {
                vr.note = "vlen inside inline asm, value flow not trackable";
                out.uncertain = true;
                out.vlen_reads.push_back(vr);
                continue; // no SSA-visible vlen value to seed
            }
            out.vlen_reads.push_back(vr);
            if (!cb->getType()->isVoidTy())
                taint(cb, false, false);
        }
    }

    bool changed = true;
    while (changed) {
        changed = false;
        while (!st.worklist.empty()) {
            const llvm::Value *v = st.worklist.back();
            st.worklist.pop_back();
            const bool derived = st.tainted[v];
            // Process at most once per derived watermark.
            auto pit = st.processed.find(v);
            if (pit != st.processed.end() && pit->second >= derived) continue;
            st.processed[v] = derived;
            changed = true;

            const llvm::Function *vFun = nullptr;
            if (const auto *inst = llvm::dyn_cast<llvm::Instruction>(v))
                vFun = inst->getFunction();
            else if (const auto *arg = llvm::dyn_cast<llvm::Argument>(v))
                vFun = arg->getParent();

            for (const llvm::User *u : v->users()) {
                if (const auto *si = llvm::dyn_cast<llvm::StoreInst>(u)) {
                    if (si->getValueOperand() != v) continue; // address side: no flow
                    const llvm::Value *P = si->getPointerOperand();
                    const std::set<SVF::NodeID> objs = ptsOf(P);
                    const bool mayFloor = st.mayMarked.count(v) > 0;
                    if (objs.empty()) {
                        if (const llvm::Argument *a = backtrackToArg(P)) {
                            std::string tname = a->hasName()
                                ? a->getName().str()
                                : "arg" + std::to_string(a->getArgNo());
                            recordEscape("PARAM", si, "ARG::" + tname, derived,
                                         mayFloor ? "may" : "may");
                        } else {
                            recordEscape("UNKNOWN", si, "UNKNOWN::ptr", derived,
                                         "unknown");
                        }
                        continue;
                    }
                    const bool multi = objs.size() > 1;
                    for (SVF::NodeID oid : objs) {
                        st.holders[oid] = st.holders.count(oid)
                            ? (st.holders[oid] || derived) : derived;
                        const SVF::BaseObjVar *b = baseOfId(oid);
                        std::string conf = multi || mayFloor ? "may" : "exact";
                        if (!b) {
                            recordEscape("UNKNOWN", si,
                                         "UNKNOWN::obj@" + std::to_string(oid),
                                         derived, "unknown");
                            continue;
                        }
                        if (b->isHeap()) {
                            std::string site = "HEAP::";
                            if (b->getFunction())
                                site += b->getFunction()->getName() + "::";
                            site += b->getICFGNode()
                                ? b->getICFGNode()->getSourceLoc()
                                : "obj@" + std::to_string(oid);
                            recordEscape("HEAP", si, site, derived, conf);
                        } else if (b->isGlobalObj() || b->isStaticObj()) {
                            std::string gname = b->getName();
                            if (gname.empty())
                                gname = "obj@" + std::to_string(oid);
                            recordEscape("GLOBAL", si, "GLOBAL::" + gname,
                                         derived, conf);
                        } else if (b->isStack()) {
                            // holder only: no escape
                        } else {
                            recordEscape("UNKNOWN", si,
                                         "UNKNOWN::obj@" + std::to_string(oid),
                                         derived, "unknown");
                        }
                    }
                } else if (const auto *ri = llvm::dyn_cast<llvm::ReturnInst>(u)) {
                    if (ri->getReturnValue() != v) continue;
                    const llvm::Function *H = ri->getFunction();
                    if (H == root) {
                        recordEscape("RETURN", ri, "<ret>", derived, "exact");
                    } else if (st.returnsTainted.insert(H).second) {
                        for (const llvm::CallBase *cs : st.callersOf[H])
                            taint(cs, derived, st.mayMarked.count(v) > 0);
                    }
                } else if (const auto *cb = llvm::dyn_cast<llvm::CallBase>(u)) {
                    if (cb->isInlineAsm()) continue;
                    // Arg positions of v at this call.
                    std::vector<unsigned> positions;
                    for (unsigned pi = 0; pi < cb->arg_size(); ++pi)
                        if (cb->getArgOperand(pi) == v)
                            positions.push_back(pi);
                    if (positions.empty()) continue; // v is the callee operand

                    std::vector<const llvm::Function *> targets;
                    if (const llvm::Function *direct = cb->getCalledFunction())
                        targets.push_back(direct);
                    else if (auto it = st.indTargets.find(cb);
                             it != st.indTargets.end())
                        targets = it->second;
                    if (targets.empty()) {
                        recordEscape("UNKNOWN_CALL", cb, "CALL::<indirect>",
                                     derived, "unknown");
                        continue;
                    }
                    for (const llvm::Function *callee : targets) {
                        const std::string cname = callee->getName().str();
                        if (cname.find("riscv") != std::string::npos ||
                            cname.rfind("llvm.", 0) == 0)
                            continue; // intrinsic/config: not an escape
                        if (isWhitelistedCall(cname)) continue;
                        if (callee->isDeclaration()) {
                            recordEscape("UNKNOWN_CALL", cb,
                                         "CALL::" + cname, derived, "unknown");
                            continue;
                        }
                        // Direct (or resolved) call with a body: descend.
                        const llvm::Function *callerFn = vFun;
                        unsigned nd =
                            (callerFn && st.depthOf.count(callerFn)
                                 ? st.depthOf[callerFn]
                                 : 0) + 1;
                        if (nd > max_depth_) {
                            st.truncated = true;
                            continue;
                        }
                        st.callersOf[callee].push_back(cb);
                        for (unsigned pi : positions) {
                            if (pi >= callee->arg_size()) {
                                // vararg position
                                recordEscape("UNKNOWN_CALL", cb,
                                             "CALL::" + cname, derived,
                                             "unknown");
                                continue;
                            }
                            taint(callee->getArg(pi), derived,
                                  st.mayMarked.count(v) > 0);
                            st.depthOf[callee] =
                                st.depthOf.count(callee)
                                    ? std::min(st.depthOf[callee], nd)
                                    : nd;
                            collectLoads(callee);
                            if (st.returnsTainted.count(callee))
                                taint(cb, derived, st.mayMarked.count(v) > 0);
                        }
                    }
                } else if (llvm::isa<llvm::PHINode>(u) ||
                           llvm::isa<llvm::SelectInst>(u) ||
                           llvm::isa<llvm::BitCastInst>(u) ||
                           llvm::isa<llvm::AddrSpaceCastInst>(u)) {
                    taint(llvm::cast<llvm::Value>(u), derived,
                          st.mayMarked.count(v) > 0);
                } else if (llvm::isa<llvm::BinaryOperator>(u) ||
                           llvm::isa<llvm::CastInst>(u) ||
                           llvm::isa<llvm::GetElementPtrInst>(u) ||
                           llvm::isa<llvm::InsertValueInst>(u) ||
                           llvm::isa<llvm::ExtractValueInst>(u)) {
                    taint(llvm::cast<llvm::Value>(u), true,
                          st.mayMarked.count(v) > 0);
                }
            }
        }
        // Rule 5 recheck: loads whose pts intersects the (growing) holders.
        for (const llvm::LoadInst *li : st.loadCandidates) {
            if (st.tainted.count(li)) continue;
            bool hit = false, hder = false;
            for (SVF::NodeID oid : ptsOf(li->getPointerOperand())) {
                auto hit2 = st.holders.find(oid);
                if (hit2 != st.holders.end()) {
                    hit = true;
                    hder = hder || hit2->second;
                }
            }
            if (hit) {
                taint(li, hder, true);
                changed = true;
            }
        }
    }

    out.verdict = "LOCAL_ONLY";
    for (const VlenEscape &e : out.escapes)
        if (e.kind == "RETURN" || e.kind == "PARAM" || e.kind == "GLOBAL" ||
            e.kind == "HEAP")
            out.verdict = "ESCAPES";
    truncatedOut = truncatedOut || st.truncated;
}

} // namespace rvirvv
