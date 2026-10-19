//===- callgraph_extractor.cpp -- Extract call graph + RVV detection --------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013->  <Yulei Sui>
//

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//===-----------------------------------------------------------------------===//

/*
 // Usage:
 //   svf-cgext <input.bc> -entry-func=main [-detect-rvv] [-max-depth=30] [-output-dot=<file>]
 //
 // Options use single dash: -option-name=value or -option-name value
 */

#include "Graphs/CallGraph.h"
#include "Graphs/ICFG.h"
#include "Graphs/ICFGNode.h"
#include "SVF-LLVM/LLVMUtil.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "SVFIR/SVFIR.h"
#include "Util/CommandLine.h"
#include "Util/Options.h"
#include "Util/SVFUtil.h"
#include "WPA/Andersen.h"

#include <map>
#include <queue>
#include <set>

using namespace llvm;
using namespace std;
using namespace SVF;

static Option<std::string> EntryFuncOpt(
    "entry-func",
    "Entry function name for call graph extraction",
    "");

static Option<u32_t> MaxDepthOpt(
    "max-depth",
    "Maximum call depth (0 = unlimited, default 30)",
    30);

static Option<std::string> OutputDotOpt(
    "output-dot",
    "Output DOT file for call graph subgraph",
    "");

static Option<bool> ListFuncsOpt(
    "list-funcs",
    "List all functions in the call graph and exit",
    false);

static Option<bool> ShowCallsiteOpt(
    "show-callsite",
    "Show source location of each callsite",
    false);

static Option<std::string> OutputJsonOpt(
    "output-json",
    "Output JSON file for call graph subgraph",
    "");

static Option<bool> DetectRVVOpt(
    "detect-rvv",
    "Detect and mark functions that use RISC-V Vector (RVV) intrinsics",
    false);

static Option<std::string> DumpRVVJsonOpt(
    "dump-rvv-json",
    "Dump full Andersen + RVV analysis report as JSON (all functions)",
    "");

static bool isRVVIntrinsicName(const std::string& name)
{
    return name.find("llvm.riscv.") != std::string::npos;
}

static bool hasRVVIntrinsic(const CallGraphNode* node)
{
    for (auto it = node->OutEdgeBegin(), eit = node->OutEdgeEnd(); it != eit; ++it)
    {
        if (isRVVIntrinsicName((*it)->getDstNode()->getName()))
            return true;
    }
    return false;
}

static int countRVVIntrinsics(const CallGraphNode* node)
{
    int count = 0;
    for (auto it = node->OutEdgeBegin(), eit = node->OutEdgeEnd(); it != eit; ++it)
    {
        if (isRVVIntrinsicName((*it)->getDstNode()->getName()))
            count++;
    }
    return count;
}

static bool hasRVVRecursive(const CallGraphNode* node,
                            std::map<NodeID, bool>& cache,
                            std::set<NodeID>& visited)
{
    NodeID id = node->getId();

    auto cached = cache.find(id);
    if (cached != cache.end())
        return cached->second;

    if (visited.find(id) != visited.end())
        return false;

    visited.insert(id);

    if (hasRVVIntrinsic(node))
    {
        cache[id] = true;
        visited.erase(id);
        return true;
    }

    for (auto it = node->OutEdgeBegin(), eit = node->OutEdgeEnd(); it != eit; ++it)
    {
        if (hasRVVRecursive((*it)->getDstNode(), cache, visited))
        {
            cache[id] = true;
            visited.erase(id);
            return true;
        }
    }

    cache[id] = false;
    visited.erase(id);
    return false;
}

static std::string rvvTag(const CallGraphNode* node,
                          std::map<NodeID, bool>& rvvCache,
                          std::set<NodeID>& visited)
{
    if (!DetectRVVOpt())
        return "";

    if (isRVVIntrinsicName(node->getName()))
        return " [RVV-intrinsic]";

    if (hasRVVIntrinsic(node))
    {
        int cnt = countRVVIntrinsics(node);
        return " [RVV] (" + std::to_string(cnt) + " intrinsics)";
    }

    if (hasRVVRecursive(node, rvvCache, visited))
    {
        return " [RVV-prop]";
    }

    return "";
}

static int countOutEdges(const CallGraphNode* node)
{
    int count = 0;
    for (auto it = node->OutEdgeBegin(), eit = node->OutEdgeEnd(); it != eit; ++it)
        count++;
    return count;
}

static void printCallTree(CallGraph* cg, const CallGraphNode* node,
                          std::set<NodeID>& visitedOnPath, int depth,
                          const string& indent, bool isLast,
                          unsigned maxDepth,
                          std::map<NodeID, bool>& rvvCache,
                          std::set<NodeID>& rvvVisited)
{
    if (maxDepth > 0 && depth > (int)maxDepth)
        return;

    if (visitedOnPath.find(node->getId()) != visitedOnPath.end())
    {
        SVFUtil::outs() << indent;
        if (depth > 0) SVFUtil::outs() << (isLast ? "`-- " : "|-- ");
        SVFUtil::outs() << node->getName() << " [recursive]\n";
        return;
    }

    visitedOnPath.insert(node->getId());

    std::string tag = rvvTag(node, rvvCache, rvvVisited);
    SVFUtil::outs() << indent;
    if (depth > 0) SVFUtil::outs() << (isLast ? "`-- " : "|-- ");
    SVFUtil::outs() << node->getName() << tag << "\n";

    string childIndent = indent;
    if (depth == 0)
        childIndent = "  ";
    else
        childIndent += isLast ? "    " : "|   ";

    int totalChildren = countOutEdges(node);
    int childIdx = 0;
    for (auto it = node->OutEdgeBegin(), eit = node->OutEdgeEnd(); it != eit; ++it, childIdx++)
    {
        CallGraphEdge* edge = *it;
        const CallGraphNode* callee = edge->getDstNode();
        bool childLast = (childIdx == totalChildren - 1);

        string callTag = edge->isDirectCallEdge() ? "[D]" : "[I]";
        if (ShowCallsiteOpt())
        {
            const CallGraphEdge::CallInstSet& callsites =
                edge->isDirectCallEdge() ? edge->getDirectCalls() : edge->getIndirectCalls();
            for (const CallICFGNode* cs : callsites)
            {
                callTag += " " + cs->getSourceLoc();
            }
        }

        string edgeInfo = childIndent + "| " + callTag;
        SVFUtil::outs() << edgeInfo << "\n";

        printCallTree(cg, callee, visitedOnPath, depth + 1, childIndent, childLast,
                      maxDepth, rvvCache, rvvVisited);
    }

    visitedOnPath.erase(node->getId());
}

static void printRVVSummary(CallGraph* cg)
{
    if (!DetectRVVOpt())
        return;

    std::map<NodeID, bool> rvvCache;
    std::set<NodeID> visited;

    std::vector<const CallGraphNode*> directRVV;
    std::vector<const CallGraphNode*> propRVV;
    int intrinsicCount = 0;

    for (const auto& it : *cg)
    {
        const CallGraphNode* node = it.second;
        if (isRVVIntrinsicName(node->getName()))
        {
            if (!SVFUtil::isExtCall(node->getFunction()))
                intrinsicCount++;
            continue;
        }

        if (hasRVVIntrinsic(node))
        {
            directRVV.push_back(node);
        }
        else if (hasRVVRecursive(node, rvvCache, visited))
        {
            propRVV.push_back(node);
        }
    }

    SVFUtil::outs() << "\n";
    SVFUtil::outs() << "=== Andersen + RVV Analysis Summary ===\n";
    SVFUtil::outs() << "Total functions in call graph:  " << cg->getTotalNodeNum() << "\n";
    SVFUtil::outs() << "Functions directly using RVV:   " << directRVV.size() << "\n";
    if (!directRVV.empty())
    {
        SVFUtil::outs() << "\n  [Direct RVV callers]:\n";
        for (const CallGraphNode* n : directRVV)
        {
            int cnt = countRVVIntrinsics(n);
            SVFUtil::outs() << "    " << n->getName()
                            << "  (" << cnt << " RVV intrinsics)\n";
        }
    }

    SVFUtil::outs() << "Functions propagated RVV:        " << propRVV.size() << "\n";
    if (!propRVV.empty())
    {
        SVFUtil::outs() << "\n  [RVV-propagated callers (call RVV functions indirectly)]:\n";
        for (const CallGraphNode* n : propRVV)
        {
            SVFUtil::outs() << "    " << n->getName() << "\n";
        }
    }

    SVFUtil::outs() << "RVV intrinsic definitions:       " << intrinsicCount << "\n";
}

static std::string jsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s)
    {
        switch (c)
        {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\t': out += "\\t";  break;
        default:   out += c;      break;
        }
    }
    return out;
}

static void writeFullRVVJson(const std::string& filename, CallGraph* cg)
{
    std::map<NodeID, bool> rvvCache;
    std::set<NodeID> visited;

    std::vector<const CallGraphNode*> directRVV;
    std::vector<const CallGraphNode*> propRVV;
    std::vector<const CallGraphNode*> intrinsicDefs;
    std::vector<const CallGraphNode*> allFuncs;

    for (const auto& it : *cg)
    {
        const CallGraphNode* node = it.second;
        allFuncs.push_back(node);

        if (isRVVIntrinsicName(node->getName()))
        {
            if (!SVFUtil::isExtCall(node->getFunction()))
                intrinsicDefs.push_back(node);
            continue;
        }

        if (hasRVVIntrinsic(node))
            directRVV.push_back(node);
        else if (hasRVVRecursive(node, rvvCache, visited))
            propRVV.push_back(node);
    }

    std::string jsonPath = filename;
    if (jsonPath.rfind(".json") != jsonPath.size() - 5)
        jsonPath += ".json";

    std::error_code ec;
    llvm::raw_fd_ostream os(jsonPath, ec);
    if (ec)
    {
        SVFUtil::errs() << "Error opening JSON file: " << ec.message() << "\n";
        return;
    }

    os << "{\n";
    os << "  \"analysis\": \"Andersen Pointer Analysis + RVV Detection\",\n";
    os << "  \"total_functions\": " << cg->getTotalNodeNum() << ",\n";
    os << "  \"rvv_intrinsic_definitions\": " << intrinsicDefs.size() << ",\n";
    os << "  \"functions_directly_using_rvv\": " << directRVV.size() << ",\n";
    os << "  \"functions_rvv_propagated\": " << propRVV.size() << ",\n";

    os << "  \"rvv_intrinsic_list\": [\n";
    for (size_t i = 0; i < intrinsicDefs.size(); i++)
    {
        if (i > 0) os << ",\n";
        os << "    {\"name\": \"" << jsonEscape(intrinsicDefs[i]->getName()) << "\"}";
    }
    os << "\n  ],\n";

    os << "  \"direct_rvv_functions\": [\n";
    for (size_t i = 0; i < directRVV.size(); i++)
    {
        if (i > 0) os << ",\n";
        const CallGraphNode* n = directRVV[i];
        int cnt = countRVVIntrinsics(n);
        os << "    {\n";
        os << "      \"name\": \"" << jsonEscape(n->getName()) << "\",\n";
        os << "      \"id\": " << n->getId() << ",\n";
        os << "      \"rvv_intrinsic_calls\": " << cnt << ",\n";
        os << "      \"rvv_intrinsics\": [";
        bool firstIntrin = true;
        for (auto it = n->OutEdgeBegin(), eit = n->OutEdgeEnd(); it != eit; ++it)
        {
            if (isRVVIntrinsicName((*it)->getDstNode()->getName()))
            {
                if (!firstIntrin) os << ", ";
                firstIntrin = false;
                os << "\"" << jsonEscape((*it)->getDstNode()->getName()) << "\"";
            }
        }
        os << "]\n    }";
    }
    os << "\n  ],\n";

    os << "  \"rvv_propagated_functions\": [\n";
    for (size_t i = 0; i < propRVV.size(); i++)
    {
        if (i > 0) os << ",\n";
        os << "    {\"name\": \"" << jsonEscape(propRVV[i]->getName())
           << "\", \"id\": " << propRVV[i]->getId() << "}";
    }
    os << "\n  ],\n";

    os << "  \"all_functions\": [\n";
    for (size_t i = 0; i < allFuncs.size(); i++)
    {
        if (i > 0) os << ",\n";
        const CallGraphNode* n = allFuncs[i];
        bool isIntrin = isRVVIntrinsicName(n->getName());
        bool isDirect = hasRVVIntrinsic(n);
        bool isProp = (!isIntrin && !isDirect) && hasRVVRecursive(n, rvvCache, visited);
        bool isExt = SVFUtil::isExtCall(n->getFunction());
        bool isEntry = SVFUtil::isProgEntryFunction(n->getFunction());
        os << "    {\n";
        os << "      \"id\": " << n->getId() << ",\n";
        os << "      \"name\": \"" << jsonEscape(n->getName()) << "\",\n";
        os << "      \"is_external\": " << (isExt ? "true" : "false") << ",\n";
        os << "      \"is_entry\": " << (isEntry ? "true" : "false") << ",\n";
        os << "      \"is_rvv_intrinsic\": " << (isIntrin ? "true" : "false") << ",\n";
        os << "      \"has_direct_rvv\": " << (isDirect ? "true" : "false") << ",\n";
        os << "      \"has_rvv_propagated\": " << (isProp ? "true" : "false") << ",\n";
        os << "      \"rvv_intrinsic_count\": " << (isDirect ? countRVVIntrinsics(n) : 0) << ",\n";
        os << "      \"in_degree\": " << n->getInEdges().size() << ",\n";
        os << "      \"out_degree\": " << n->getOutEdges().size();
        os << "\n    }";
    }
    os << "\n  ]\n";

    os << "}\n";
    os.close();
    SVFUtil::outs() << "Full RVV analysis JSON written to " << jsonPath
                    << " (" << allFuncs.size() << " functions)\n";
}

static void collectSubGraphNodes(CallGraph* cg, const CallGraphNode* root,
                                 std::set<const CallGraphNode*>& nodes,
                                 std::set<const CallGraphEdge*>& edges,
                                 unsigned maxDepth)
{
    std::queue<std::pair<const CallGraphNode*, int> > worklist;
    worklist.push(std::make_pair(root, 0));
    nodes.insert(root);

    while (!worklist.empty())
    {
        const CallGraphNode* node = worklist.front().first;
        int depth = worklist.front().second;
        worklist.pop();

        if (maxDepth > 0 && depth >= (int)maxDepth)
            continue;

        for (auto it = node->OutEdgeBegin(), eit = node->OutEdgeEnd(); it != eit; ++it)
        {
            CallGraphEdge* edge = *it;
            edges.insert(edge);
            const CallGraphNode* callee = edge->getDstNode();
            if (nodes.insert(callee).second)
            {
                worklist.push(std::make_pair(callee, depth + 1));
            }
        }
    }
}

static void writeSubGraphDot(const string& filename, CallGraph* cg,
                             const CallGraphNode* root, unsigned maxDepth)
{
    std::set<const CallGraphNode*> nodes;
    std::set<const CallGraphEdge*> edges;
    collectSubGraphNodes(cg, root, nodes, edges, maxDepth);

    string dotPath = filename;
    if (dotPath.rfind(".dot") != dotPath.size() - 4)
        dotPath += ".dot";

    std::error_code ec;
    llvm::raw_fd_ostream os(dotPath, ec);
    if (ec)
    {
        SVFUtil::errs() << "Error opening DOT file: " << ec.message() << "\n";
        return;
    }

    os << "digraph CallGraphSub {\n";
    os << "  rankdir=LR;\n";
    os << "  node [shape=record];\n";

    for (const CallGraphNode* node : nodes)
    {
        string label = node->getName();
        string color = "black";
        for (size_t i = 0; i < label.size(); i++)
        {
            if (label[i] == '<' || label[i] == '>' || label[i] == '"')
                label[i] = ' ';
        }
        if (isRVVIntrinsicName(node->getName()))
            color = "blue";
        else if (hasRVVIntrinsic(node))
            color = "red";
        else if (SVFUtil::isExtCall(node->getFunction()))
            color = "gray";
        os << "  n" << node->getId() << " [label=\"" << label
           << "\", color=" << color << "];\n";
    }

    for (const CallGraphEdge* edge : edges)
    {
        string color = "black";
        if (edge->isIndirectCallEdge())
            color = "red";
        else if (isRVVIntrinsicName(edge->getDstNode()->getName()))
            color = "blue";
        os << "  n" << edge->getSrcID() << " -> n" << edge->getDstID()
           << " [color=" << color << "];\n";
    }

    os << "}\n";
    os.close();
    SVFUtil::outs() << "Subgraph DOT written to " << dotPath << " ("
                    << nodes.size() << " nodes, " << edges.size()
                    << " edges)\n";
}

static void writeSubGraphJson(const string& filename, CallGraph* cg,
                               const CallGraphNode* root, unsigned maxDepth)
{
    std::set<const CallGraphNode*> nodes;
    std::set<const CallGraphEdge*> edges;
    collectSubGraphNodes(cg, root, nodes, edges, maxDepth);

    string jsonPath = filename;
    if (jsonPath.rfind(".json") != jsonPath.size() - 5)
        jsonPath += ".json";

    std::error_code ec;
    llvm::raw_fd_ostream os(jsonPath, ec);
    if (ec)
    {
        SVFUtil::errs() << "Error opening JSON file: " << ec.message() << "\n";
        return;
    }

    std::map<NodeID, bool> rvvCache;
    std::set<NodeID> rvvVisited;

    os << "{\n";
    os << "  \"tool\": \"svf-cgext\",\n";
    os << "  \"entry_function\": \"" << jsonEscape(root->getName()) << "\",\n";
    os << "  \"max_depth\": " << maxDepth << ",\n";

    os << "  \"nodes\": [\n";
    bool firstNode = true;
    for (const CallGraphNode* node : nodes)
    {
        if (!firstNode) os << ",\n";
        firstNode = false;
        os << "    {\n";
        os << "      \"id\": " << node->getId() << ",\n";
        os << "      \"name\": \"" << jsonEscape(node->getName()) << "\",\n";
        os << "      \"is_external\": " << (SVFUtil::isExtCall(node->getFunction()) ? "true" : "false") << ",\n";
        os << "      \"is_entry\": " << (SVFUtil::isProgEntryFunction(node->getFunction()) ? "true" : "false") << ",\n";
        os << "      \"is_rvv_intrinsic\": " << (isRVVIntrinsicName(node->getName()) ? "true" : "false") << ",\n";
        os << "      \"has_direct_rvv\": " << (hasRVVIntrinsic(node) ? "true" : "false") << ",\n";
        os << "      \"has_rvv_propagated\": " << (hasRVVRecursive(node, rvvCache, rvvVisited) ? "true" : "false") << ",\n";
        os << "      \"out_degree\": " << node->getOutEdges().size();
        os << "\n    }";
    }
    os << "\n  ],\n";

    os << "  \"edges\": [\n";
    bool firstEdge = true;
    for (const CallGraphEdge* edge : edges)
    {
        if (!firstEdge) os << ",\n";
        firstEdge = false;
        os << "    {\n";
        os << "      \"src\": " << edge->getSrcID() << ",\n";
        os << "      \"dst\": " << edge->getDstID() << ",\n";
        os << "      \"call_type\": \"" << (edge->isDirectCallEdge() ? "direct" : "indirect") << "\",\n";
        os << "      \"dst_is_rvv_intrinsic\": " << (isRVVIntrinsicName(edge->getDstNode()->getName()) ? "true" : "false") << ",\n";

        const CallGraphEdge::CallInstSet& callsites =
            edge->isDirectCallEdge() ? edge->getDirectCalls() : edge->getIndirectCalls();
        os << "      \"callsites\": [";
        bool firstCs = true;
        for (const CallICFGNode* cs : callsites)
        {
            if (!firstCs) os << ", ";
            firstCs = false;
            os << "{";
            os << "\"loc\": \"" << jsonEscape(cs->getSourceLoc()) << "\"";
            os << "}";
        }
        os << "]\n";
        os << "    }";
    }
    os << "\n  ],\n";

    os << "  \"statistics\": {\n";
    os << "    \"node_count\": " << nodes.size() << ",\n";
    os << "    \"edge_count\": " << edges.size() << "\n";
    os << "  }\n";

    os << "}\n";
    os.close();
    SVFUtil::outs() << "Subgraph JSON written to " << jsonPath << " ("
                    << nodes.size() << " nodes, " << edges.size()
                    << " edges)\n";
}

int main(int argc, char** argv)
{
    std::vector<std::string> moduleNameVec;
    moduleNameVec = OptionBase::parseOptions(
        argc, argv, "Call Graph Extractor with RVV Detection",
        "[options] <input-bitcode...>");

    if (moduleNameVec.empty())
    {
        SVFUtil::errs() << "Error: no input bitcode file specified.\n";
        SVFUtil::errs() << "Usage: svf-cgext <input.bc> -entry-func=<name> "
                        << "[-detect-rvv] [-max-depth=N] [-output-dot=<file>]\n";
        return 1;
    }

    LLVMModuleSet::preProcessBCs(moduleNameVec);
    LLVMModuleSet::buildSVFModule(moduleNameVec);

    SVFIRBuilder builder;
    SVFIR* pag = builder.build();

    Andersen* ander = AndersenWaveDiff::createAndersenWaveDiff(pag);
    CallGraph* callgraph = ander->getCallGraph();

    if (ListFuncsOpt())
    {
        SVFUtil::outs() << "Functions in call graph ("
                        << callgraph->getTotalNodeNum() << " total):\n";
        for (const auto& it : *callgraph)
        {
            const CallGraphNode* node = it.second;
            string tag = "";
            if (SVFUtil::isExtCall(node->getFunction()))
                tag = " [ext]";
            if (SVFUtil::isProgEntryFunction(node->getFunction()))
                tag += " [entry]";
            if (DetectRVVOpt())
            {
                if (isRVVIntrinsicName(node->getName()))
                    tag += " [RVV-intrinsic]";
                else if (hasRVVIntrinsic(node))
                {
                    int cnt = countRVVIntrinsics(node);
                    tag += " [RVV](" + std::to_string(cnt) + ")";
                }
            }
            SVFUtil::outs() << "  " << node->getName() << tag << "\n";
        }
        SVFUtil::outs() << "\nUse -entry-func=<name> to extract subgraph.\n";

        if (DetectRVVOpt())
            printRVVSummary(callgraph);

        {
            std::string rvvJson = DumpRVVJsonOpt();
            if (!rvvJson.empty())
                writeFullRVVJson(rvvJson, callgraph);
        }

        goto cleanup;
    }

    {
        std::string entryFn = EntryFuncOpt();
        std::string rvvJsonFile = DumpRVVJsonOpt();

        if (entryFn.empty())
        {
            if (!rvvJsonFile.empty())
            {
                writeFullRVVJson(rvvJsonFile, callgraph);
                goto cleanup;
            }
            SVFUtil::errs()
                << "Error: -entry-func is required (or use -list-funcs first).\n";
            goto cleanup;
        }

        const CallGraphNode* root = callgraph->getCallGraphNode(entryFn);
        if (!root)
        {
            SVFUtil::errs() << "Function '" << entryFn
                            << "' not found in call graph.\n";
            SVFUtil::errs()
                << "Use -list-funcs to see available functions.\n";
            goto cleanup;
        }

        SVFUtil::outs() << "=== Call tree starting from: " << root->getName();
        if (DetectRVVOpt())
            SVFUtil::outs() << " (RVV detection ON)";
        SVFUtil::outs() << " ===\n\n";

        std::map<NodeID, bool> rvvCache;
        std::set<NodeID> rvvVisited;

        unsigned maxD = MaxDepthOpt();
        std::set<NodeID> visitedOnPath;
        printCallTree(callgraph, root, visitedOnPath, 0, "", false, maxD,
                      rvvCache, rvvVisited);

        SVFUtil::outs() << "\n";

        if (DetectRVVOpt())
            printRVVSummary(callgraph);

        std::string dotFile = OutputDotOpt();
        if (!dotFile.empty())
        {
            writeSubGraphDot(dotFile, callgraph, root, maxD);
        }

        std::string jsonFile = OutputJsonOpt();
        if (!jsonFile.empty())
        {
            writeSubGraphJson(jsonFile, callgraph, root, maxD);
        }

        {
            std::string rvvJson = DumpRVVJsonOpt();
            if (!rvvJson.empty())
                writeFullRVVJson(rvvJson, callgraph);
        }
    }

cleanup:
    AndersenWaveDiff::releaseAndersenWaveDiff();
    SVFIR::releaseSVFIR();
    LLVMModuleSet::getLLVMModuleSet()->dumpModulesToFile(".svf.bc");
    SVF::LLVMModuleSet::releaseLLVMModuleSet();
#if LLVM_VERSION_MAJOR < 18
    llvm::llvm_shutdown();
#endif
    return 0;
}
