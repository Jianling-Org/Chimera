//===----------------------------------------------------------------------===//
// global_read_tracker.cpp — Track reads of a named global variable
//
// Pipeline (module level, single bitcode input):
//   1. Locate the target: match llvm::GlobalVariable by name (exact match
//      first, substring fallback; matched names are reported) and map to the
//      SVF BaseObjVar plus its field (GepObjVar) sub-objects. Target object
//      set = base obj + all its GepObjVars.
//   2. Read points: every LoadInst in a defined function, and the source
//      operand of memcpy/memmove (llvm.memcpy*/llvm.memmove* or libc names),
//      whose Andersen pts intersects the target set. The field offset comes
//      from constant GEP decomposition (nested GEP offsets summed; loads
//      through -O0 spill allocas are backtracked); a non-constant index
//      yields offset -1 and confidence may. confidence = exact when pts
//      contains ONLY target objects, otherwise may.
//   3. Forward dataflow per read (worklist to fixpoint):
//      - phi/select/bitcast/addrspacecast propagate; binop / other casts /
//        gep / insertvalue / extractvalue propagate.
//      - icmp/fcmp feeding a conditional br/switch => CMP_BRANCH
//        (detail like "icmp sgt 0").
//      - call actuals: callee with a body => taint the formal at the
//        position and descend (depth-capped at -max-depth, excess marks
//        truncated_depth); external / declaration-only / unresolved
//        indirect => CALL_EXTERNAL (detail = callee name or "<indirect>").
//        riscv / llvm.* intrinsics are skipped silently.
//      - ret => RETURNED (detail = containing function); every callsite of
//        that function (direct or Andersen-resolved indirect) gets its
//        result tainted — the getter-chain propagation across functions.
//      - store => STORE, target classified via Andersen: STACK
//        (detail=STACK::fn::name, recorded as a holder so later loads
//        continue), GLOBAL (detail=GLOBAL::name), HEAP (detail=HEAP::<site>),
//        PARAM (def-use backtrack to an Argument, detail=ARG::name),
//        otherwise UNKNOWN::<desc>.
//      - load whose pts intersects holders => result tainted (recheck loop).
//   4. Missing target: matched_globals and reads stay empty, statistics 0,
//      stdout reports it, exit code 0 (handled by the caller).
//===----------------------------------------------------------------------===//

#include "global_read_tracker.h"

#include "SVF-LLVM/LLVMModule.h"
#include "Util/SVFUtil.h"

#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include <algorithm>
#include <functional>
#include <queue>

namespace rvirvv {

namespace {

const SVF::BaseObjVar *baseObjOf(const SVF::SVFVar *var) {
    if (const auto *b = SVF::SVFUtil::dyn_cast<SVF::BaseObjVar>(var))
        return b;
    if (const auto *g = SVF::SVFUtil::dyn_cast<SVF::GepObjVar>(var))
        return g->getBaseObj();
    return nullptr;
}

bool isMemcpyLike(const std::string &name) {
    return name == "memcpy" || name == "memmove" ||
           name.rfind("llvm.memcpy", 0) == 0 ||
           name.rfind("llvm.memmove", 0) == 0;
}

/// Per-read forward taint state.
struct FlowState {
    std::map<const llvm::Value *, bool> tainted;  // value -> visited-with-flag
    std::map<SVF::NodeID, bool> holders;          // written STACK objects
    std::map<const llvm::Function *, unsigned> depthOf;
    std::vector<const llvm::Value *> worklist;
    std::vector<FlowEvent> flows;
    std::map<const llvm::Instruction *, std::vector<const llvm::Function *>> indTargets;
    bool truncated = false;
};

} // anonymous namespace

GlobalReadTracker::GlobalReadTracker(SVF::SVFIR *pag, SVF::Andersen *ander)
    : pag_(pag), ander_(ander) {}

GlobalReadTrackResult GlobalReadTracker::analyze(
    const std::string &targetName) {
    GlobalReadTrackResult result;
    result.requested = targetName;
    SVF::LLVMModuleSet *ms = SVF::LLVMModuleSet::getLLVMModuleSet();
    SVF::CallGraph *cg = ander_->getCallGraph();

    // Statistics: module-level unresolved indirect calls (same口径 as the
    // vlen analysis).
    {
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
        for (llvm::Module &mod : ms->getLLVMModules())
            for (const llvm::Function &f : mod) {
                if (f.isDeclaration()) continue;
                for (const llvm::BasicBlock &bb : f)
                    for (const llvm::Instruction &i : bb)
                        if (const auto *cb = llvm::dyn_cast<llvm::CallBase>(&i))
                            if (!cb->isInlineAsm() && !cb->getCalledFunction() &&
                                !resolved.count(&i))
                                ++result.unresolved_indirect_calls;
            }
    }

    // ---- step 1: locate the target global(s) ----
    std::vector<const llvm::GlobalVariable *> gvs;
    {
        const llvm::GlobalVariable *exact = nullptr;
        for (llvm::Module &mod : ms->getLLVMModules())
            for (const llvm::GlobalVariable &g : mod.globals())
                if (g.getName() == targetName) {
                    exact = &g;
                    break;
                }
        if (exact) {
            gvs.push_back(exact);
        } else {
            for (llvm::Module &mod : ms->getLLVMModules())
                for (const llvm::GlobalVariable &g : mod.globals())
                    if (g.getName().find(targetName) != std::string::npos)
                        gvs.push_back(&g);
        }
    }

    // Map matched LLVM globals to SVF base objects; field sub-objects join.
    std::set<SVF::NodeID> targetObjs;
    for (const llvm::GlobalVariable *gv : gvs) {
        for (auto it = pag_->begin(); it != pag_->end(); ++it) {
            const SVF::BaseObjVar *b = baseObjOf(it->second);
            if (!b || !b->isGlobalObj()) continue;
            if (!ms->hasLLVMValue(b) || ms->getLLVMValue(b) != gv) continue;
            targetObjs.insert(b->getId());
            result.matched_globals.push_back(gv->getName().str());
            break;
        }
    }
    for (auto it = pag_->begin(); it != pag_->end(); ++it)
        if (const auto *g = SVF::SVFUtil::dyn_cast<SVF::GepObjVar>(it->second))
            if (targetObjs.count(g->getBaseNode()))
                targetObjs.insert(g->getId());

    if (result.matched_globals.empty())
        return result; // caller prints the "not found" message

    const llvm::DataLayout &dl = ms->getMainLLVMModule()->getDataLayout();

    auto ptsOf = [&](const llvm::Value *v) -> std::set<SVF::NodeID> {
        std::set<SVF::NodeID> out;
        if (!ms->hasValueNode(v)) return out;
        for (SVF::NodeID o : ander_->getPts(ms->getValueNode(v)))
            out.insert(o);
        return out;
    };

    // Constant byte offset from a value to the tracked global: strip casts,
    // accumulate GEP indices (nested sums), and backtrack through -O0 spill
    // loads (allocas). -1 = non-constant / unresolved.
    std::function<int64_t(const llvm::Value *, unsigned)> offsetOf =
        [&](const llvm::Value *v, unsigned depth) -> int64_t {
        if (!v || depth > 8) return -1;
        v = v->stripPointerCasts();
        if (llvm::isa<llvm::GlobalVariable>(v)) return 0;
        if (const auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(v)) {
            int64_t local = 0;
            llvm::Type *ptrTy = gep->getSourceElementType();
            for (unsigned i = 1; i < gep->getNumOperands(); ++i) {
                const auto *ci =
                    llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(i));
                if (!ci) return -1; // non-constant index
                const int64_t idx = ci->getSExtValue();
                if (i == 1) {
                    local += idx * (int64_t)dl.getTypeAllocSize(ptrTy);
                } else if (auto *st = llvm::dyn_cast<llvm::StructType>(ptrTy)) {
                    local += dl.getStructLayout(st)
                                 ->getElementOffset((unsigned)idx);
                    ptrTy = st->getElementType((unsigned)idx);
                } else if (auto *at = llvm::dyn_cast<llvm::ArrayType>(ptrTy)) {
                    local += idx * (int64_t)dl.getTypeAllocSize(
                                       at->getElementType());
                    ptrTy = at->getElementType();
                } else if (ptrTy->isSized()) {
                    local += idx * (int64_t)dl.getTypeAllocSize(ptrTy);
                }
            }
            const int64_t base = offsetOf(gep->getPointerOperand(), depth + 1);
            return base < 0 ? -1 : base + local;
        }
        if (const auto *li = llvm::dyn_cast<llvm::LoadInst>(v)) {
            // -O0 spill: backtrack through the alloca's stored values.
            const llvm::Value *slot = li->getPointerOperand()->stripPointerCasts();
            if (const auto *A = llvm::dyn_cast<llvm::AllocaInst>(slot)) {
                for (const llvm::User *u : A->users())
                    if (const auto *si = llvm::dyn_cast<llvm::StoreInst>(u))
                        if (si->getPointerOperand() == A) {
                            const int64_t r =
                                offsetOf(si->getValueOperand(), depth + 1);
                            if (r >= 0) return r;
                        }
            }
        }
        return -1;
    };

    // Indirect call targets (for getter-chain callsite lookup and descent).
    std::map<const llvm::Instruction *, std::vector<const llvm::Function *>>
        indTargets;
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
                    indTargets[inst].push_back(cf);
        }
    }

    auto fnLoc = [](const llvm::Instruction *inst, std::string &file,
                    unsigned &line) {
        file.clear();
        line = 0;
        if (const llvm::DebugLoc dl = inst->getDebugLoc()) {
            file = dl->getFilename().str();
            line = dl->getLine();
        }
    };

    // ---- step 2: read points ----
    struct ReadSite {
        const llvm::Function *fun;
        const llvm::Instruction *inst;
        const llvm::Value *seed;      // value to forward-track (null for memcpy)
        int64_t offset;
        std::string confidence;
    };
    std::vector<ReadSite> sites;
    std::map<int64_t, unsigned> fieldReads;

    for (llvm::Module &mod : ms->getLLVMModules()) {
        for (const llvm::Function &f : mod) {
            if (f.isDeclaration()) continue;
            for (const llvm::BasicBlock &bb : f) {
                for (const llvm::Instruction &i : bb) {
                    const llvm::Value *ptr = nullptr;
                    const llvm::Value *seed = nullptr;
                    if (const auto *li = llvm::dyn_cast<llvm::LoadInst>(&i)) {
                        ptr = li->getPointerOperand();
                        seed = li;
                    } else if (const auto *cb =
                                   llvm::dyn_cast<llvm::CallBase>(&i)) {
                        const llvm::Function *callee = cb->getCalledFunction();
                        if (callee && isMemcpyLike(callee->getName().str()) &&
                            cb->arg_size() > 1)
                            ptr = cb->getArgOperand(1); // memcpy source
                    }
                    if (!ptr) continue;
                    const std::set<SVF::NodeID> objs = ptsOf(ptr);
                    bool hit = false, other = false;
                    for (SVF::NodeID o : objs) {
                        if (targetObjs.count(o)) hit = true;
                        else other = true;
                    }
                    if (!hit) continue;
                    ReadSite rs;
                    rs.fun = &f;
                    rs.inst = &i;
                    rs.seed = seed;
                    rs.offset = offsetOf(ptr, 0);
                    rs.confidence =
                        (other || rs.offset < 0) ? "may" : "exact";
                    sites.push_back(rs);
                    if (rs.offset >= 0) fieldReads[rs.offset]++;
                }
            }
        }
    }

    // ---- step 3: forward dataflow per read ----
    for (const ReadSite &rs : sites) {
        GlobalRead gr;
        gr.function = rs.fun->getName().str();
        fnLoc(rs.inst, gr.file, gr.line);
        if (const llvm::DebugLoc dl = rs.inst->getDebugLoc())
            gr.column = dl->getColumn();
        gr.field_offset = rs.offset;
        gr.confidence = rs.confidence;

        if (rs.seed) {
            FlowState st;
            st.indTargets = indTargets;
            st.depthOf[rs.fun] = 0;
            st.tainted[rs.seed] = true;
            st.worklist.push_back(rs.seed);

            auto taint = [&](const llvm::Value *v) {
                if (st.tainted.insert({v, true}).second)
                    st.worklist.push_back(v);
            };
            auto addFlow = [&](const std::string &kind,
                               const std::string &detail,
                               const llvm::Instruction *inst) {
                FlowEvent fe;
                fe.kind = kind;
                fe.detail = detail;
                fe.function = inst->getFunction()->getName().str();
                fnLoc(inst, fe.file, fe.line);
                for (const FlowEvent &e : gr.flows)
                    if (e.kind == fe.kind && e.detail == fe.detail &&
                        e.function == fe.function && e.line == fe.line)
                        return; // dedup
                gr.flows.push_back(fe);
            };

            std::set<const llvm::Value *> processed;
            bool changed = true;
            unsigned rounds = 0;
            while (changed && rounds++ < 64) {
                changed = false;
                while (!st.worklist.empty()) {
                    const llvm::Value *v = st.worklist.back();
                    st.worklist.pop_back();
                    if (!processed.insert(v).second) continue;
                    changed = true;
                    const llvm::Function *vFun = nullptr;
                    if (const auto *inst = llvm::dyn_cast<llvm::Instruction>(v))
                        vFun = inst->getFunction();
                    else if (const auto *arg = llvm::dyn_cast<llvm::Argument>(v))
                        vFun = arg->getParent();

                    for (const llvm::User *u : v->users()) {
                        if (const auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(u)) {
                            // comparison feeding a conditional br/switch
                            bool feeds = false;
                            for (const llvm::User *cu : cmp->users())
                                if (llvm::isa<llvm::BranchInst>(cu) ||
                                    llvm::isa<llvm::SwitchInst>(cu))
                                    feeds = true;
                            if (feeds) {
                                std::string d = "icmp " +
                                    cmp->getPredicateName(cmp->getPredicate())
                                        .str();
                                const llvm::Value *other =
                                    cmp->getOperand(0) == v
                                        ? cmp->getOperand(1)
                                        : cmp->getOperand(0);
                                if (const auto *ci =
                                        llvm::dyn_cast<llvm::ConstantInt>(other))
                                    d += " " + std::to_string(ci->getSExtValue());
                                else
                                    d += " ?";
                                addFlow("CMP_BRANCH", d, cmp);
                            }
                            continue; // cmp is not a dataflow op here
                        }
                        if (llvm::isa<llvm::FCmpInst>(u)) {
                            bool feeds = false;
                            for (const llvm::User *cu : u->users())
                                if (llvm::isa<llvm::BranchInst>(cu) ||
                                    llvm::isa<llvm::SwitchInst>(cu))
                                    feeds = true;
                            if (feeds)
                                addFlow("CMP_BRANCH", "fcmp",
                                        llvm::cast<llvm::Instruction>(u));
                            continue;
                        }
                        if (const auto *ri = llvm::dyn_cast<llvm::ReturnInst>(u)) {
                            if (ri->getReturnValue() != v) continue;
                            const llvm::Function *H = ri->getFunction();
                            addFlow("RETURNED", H->getName().str(), ri);
                            // taint results of every callsite calling H
                            for (llvm::Module &mod : ms->getLLVMModules())
                                for (const llvm::Function &cf : mod) {
                                    if (cf.isDeclaration()) continue;
                                    for (const llvm::BasicBlock &cbb : cf)
                                        for (const llvm::Instruction &ci : cbb)
                                            if (const auto *cb =
                                                    llvm::dyn_cast<llvm::CallBase>(
                                                        &ci)) {
                                                bool targets = false;
                                                if (cb->getCalledFunction() == H)
                                                    targets = true;
                                                else {
                                                    auto it = st.indTargets.find(cb);
                                                    if (it != st.indTargets.end())
                                                        for (const llvm::Function *t :
                                                             it->second)
                                                            if (t == H)
                                                                targets = true;
                                                }
                                                if (targets) taint(cb);
                                            }
                                }
                        } else if (const auto *si =
                                       llvm::dyn_cast<llvm::StoreInst>(u)) {
                            if (si->getValueOperand() != v) continue;
                            const llvm::Value *P = si->getPointerOperand();
                            const std::set<SVF::NodeID> objs = ptsOf(P);
                            if (objs.empty()) {
                                // def-use backtrack to an Argument => PARAM
                                std::vector<const llvm::Value *> wl(1, P);
                                std::set<const llvm::Value *> seen;
                                const llvm::Argument *hit = nullptr;
                                while (!wl.empty() && !hit) {
                                    const llvm::Value *cur = wl.back();
                                    wl.pop_back();
                                    if (!cur || !seen.insert(cur).second)
                                        continue;
                                    cur = cur->stripPointerCasts();
                                    if (const auto *arg =
                                            llvm::dyn_cast<llvm::Argument>(cur)) {
                                        hit = arg;
                                        break;
                                    }
                                    if (const auto *gep =
                                            llvm::dyn_cast<llvm::GetElementPtrInst>(
                                                cur)) {
                                        wl.push_back(gep->getPointerOperand());
                                    } else if (const auto *pn =
                                                   llvm::dyn_cast<llvm::PHINode>(
                                                       cur)) {
                                        for (const llvm::Value *iv :
                                             pn->incoming_values())
                                            wl.push_back(iv);
                                    } else if (const auto *sv =
                                                   llvm::dyn_cast<llvm::SelectInst>(
                                                       cur)) {
                                        wl.push_back(sv->getTrueValue());
                                        wl.push_back(sv->getFalseValue());
                                    } else if (const auto *li2 =
                                                   llvm::dyn_cast<llvm::LoadInst>(
                                                       cur)) {
                                        const llvm::Value *slot =
                                            li2->getPointerOperand()
                                                ->stripPointerCasts();
                                        if (const auto *A =
                                                llvm::dyn_cast<llvm::AllocaInst>(
                                                    slot))
                                            for (const llvm::User *au : A->users())
                                                if (const auto *si2 =
                                                        llvm::dyn_cast<llvm::StoreInst>(
                                                            au))
                                                    if (si2->getPointerOperand() == A)
                                                        wl.push_back(
                                                            si2->getValueOperand());
                                    }
                                }
                                if (hit) {
                                    std::string tname =
                                        hit->hasName()
                                            ? hit->getName().str()
                                            : "arg" +
                                                  std::to_string(hit->getArgNo());
                                    addFlow("STORE", "ARG::" + tname, si);
                                } else {
                                    addFlow("STORE", "UNKNOWN::ptr", si);
                                }
                                continue;
                            }
                            for (SVF::NodeID oid : objs) {
                                const SVF::BaseObjVar *b = baseObjOf(
                                    pag_->getGNode(oid));
                                if (!b) {
                                    addFlow("STORE",
                                            "UNKNOWN::obj@" + std::to_string(oid),
                                            si);
                                    continue;
                                }
                                if (b->isStack()) {
                                    st.holders[oid] = true;
                                    std::string nm = b->getName();
                                    if (nm.empty())
                                        nm = "obj@" + std::to_string(oid);
                                    addFlow("STORE",
                                            "STACK::" +
                                                (b->getFunction()
                                                     ? b->getFunction()
                                                           ->getName()
                                                     : std::string("?")) +
                                                "::" + nm,
                                            si);
                                } else if (b->isGlobalObj() ||
                                           b->isStaticObj()) {
                                    std::string nm = b->getName();
                                    if (nm.empty())
                                        nm = "obj@" + std::to_string(oid);
                                    addFlow("STORE", "GLOBAL::" + nm, si);
                                } else if (b->isHeap()) {
                                    std::string site = "HEAP::";
                                    if (b->getFunction())
                                        site += b->getFunction()->getName();
                                    else
                                        site += "?";
                                    site += "::" +
                                            (b->getICFGNode()
                                                 ? b->getICFGNode()
                                                       ->getSourceLoc()
                                                 : std::string("obj@") +
                                                       std::to_string(oid));
                                    addFlow("STORE", site, si);
                                } else {
                                    addFlow("STORE",
                                            "UNKNOWN::obj@" + std::to_string(oid),
                                            si);
                                }
                            }
                        } else if (const auto *cb =
                                       llvm::dyn_cast<llvm::CallBase>(u)) {
                            if (cb->isInlineAsm()) continue;
                            std::vector<unsigned> positions;
                            for (unsigned pi = 0; pi < cb->arg_size(); ++pi)
                                if (cb->getArgOperand(pi) == v)
                                    positions.push_back(pi);
                            if (positions.empty()) continue;
                            std::vector<const llvm::Function *> targets;
                            if (const llvm::Function *direct =
                                    cb->getCalledFunction())
                                targets.push_back(direct);
                            else if (auto it = st.indTargets.find(cb);
                                     it != st.indTargets.end())
                                targets = it->second;
                            if (targets.empty()) {
                                addFlow("CALL_EXTERNAL", "<indirect>", cb);
                                continue;
                            }
                            for (const llvm::Function *callee : targets) {
                                const std::string cname =
                                    callee->getName().str();
                                if (cname.find("riscv") != std::string::npos ||
                                    cname.rfind("llvm.", 0) == 0)
                                    continue; // intrinsic: skip silently
                                if (callee->isDeclaration()) {
                                    addFlow("CALL_EXTERNAL", cname, cb);
                                    continue;
                                }
                                addFlow("CALL", cname, cb);
                                unsigned nd =
                                    (vFun && st.depthOf.count(vFun)
                                         ? st.depthOf[vFun]
                                         : 0) + 1;
                                if (nd > max_depth_) {
                                    st.truncated = true;
                                    continue;
                                }
                                for (unsigned pi : positions) {
                                    if (pi >= callee->arg_size()) continue;
                                    taint(callee->getArg(pi));
                                }
                                st.depthOf[callee] =
                                    st.depthOf.count(callee)
                                        ? std::min(st.depthOf[callee], nd)
                                        : nd;
                            }
                        } else if (llvm::isa<llvm::PHINode>(u) ||
                                   llvm::isa<llvm::SelectInst>(u) ||
                                   llvm::isa<llvm::BitCastInst>(u) ||
                                   llvm::isa<llvm::AddrSpaceCastInst>(u) ||
                                   llvm::isa<llvm::BinaryOperator>(u) ||
                                   llvm::isa<llvm::CastInst>(u) ||
                                   llvm::isa<llvm::GetElementPtrInst>(u) ||
                                   llvm::isa<llvm::InsertValueInst>(u) ||
                                   llvm::isa<llvm::ExtractValueInst>(u)) {
                            taint(llvm::cast<llvm::Value>(u));
                        }
                    }
                }
                // holder reload recheck: loads hitting STACK holders taint.
                for (llvm::Module &mod : ms->getLLVMModules())
                    for (const llvm::Function &f : mod) {
                        if (f.isDeclaration()) continue;
                        for (const llvm::BasicBlock &bb : f)
                            for (const llvm::Instruction &i : bb)
                                if (const auto *li =
                                        llvm::dyn_cast<llvm::LoadInst>(&i)) {
                                    if (st.tainted.count(li)) continue;
                                    for (SVF::NodeID o :
                                         ptsOf(li->getPointerOperand()))
                                        if (st.holders.count(o)) {
                                            taint(li);
                                            changed = true;
                                        }
                                }
                    }
            }
            if (st.truncated) result.truncated_depth = true;
        }
        result.reads.push_back(gr);
        result.flow_count += gr.flows.size();
    }

    for (const auto &kv : fieldReads)
        result.fields.push_back({kv.first, kv.second});
    std::sort(result.fields.begin(), result.fields.end(),
              [](const GlobalFieldStat &a, const GlobalFieldStat &b) {
                  return a.offset < b.offset;
              });
    return result;
}

} // namespace rvirvv
