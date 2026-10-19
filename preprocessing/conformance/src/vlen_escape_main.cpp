//===- vlen_escape_main.cpp -- vlen escape analysis (module scan) ------------===//
//
// svf-vlenesc: scan a bitcode module for functions that read the RVV vector
// length (vsetvl/vlenb calls) and decide, via an Andersen-assisted taint
// analysis, whether the vlen value escapes each reader's scope.
//
// Usage:
//   svf-vlenesc <input.bc> [-output-json=<file.json>] [-max-depth=30]
//
// Options use single dash: -option-name=value or -option-name value
//
//===----------------------------------------------------------------------===//

#include "vlen_escape.h"
#include "global_read_tracker.h"

#include "Graphs/CallGraph.h"
#include "SVF-LLVM/LLVMUtil.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "SVFIR/SVFIR.h"
#include "Util/CommandLine.h"
#include "Util/Options.h"
#include "Util/SVFUtil.h"
#include "WPA/Andersen.h"

using namespace llvm;
using namespace std;
using namespace SVF;

static Option<u32_t> MaxDepthOpt(
    "max-depth",
    "Maximum call-chain depth for taint descent (default 30)",
    30);

static Option<std::string> OutputJsonOpt(
    "output-json",
    "Output JSON file for the vlen escape report",
    "vlen_escape.json");

static Option<std::string> TrackGlobalOpt(
    "track-global",
    "Track reads of the named global variable (dataflow mode)",
    "");

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

static std::string jsonStrOrNull(const std::string& s)
{
    return s.empty() ? std::string("null")
                     : std::string("\"") + jsonEscape(s) + "\"";
}

static void writeVlenJson(const string& filename,
                          const rvirvv::VlenEscapeResult& res)
{
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

    size_t escapeCount = 0;
    os << "{\n";
    os << "  \"tool\": \"svf-vlenesc\",\n";
    os << "  \"module\": \"" << jsonEscape(res.module) << "\",\n";

    os << "  \"functions\": [\n";
    bool firstFn = true;
    for (const rvirvv::VlenRootResult& fn : res.functions)
    {
        if (!firstFn) os << ",\n";
        firstFn = false;
        os << "    {\n";
        os << "      \"name\": \"" << jsonEscape(fn.name) << "\",\n";
        os << "      \"file\": " << jsonStrOrNull(fn.file) << ",\n";
        os << "      \"line\": " << fn.line << ",\n";

        os << "      \"vlen_reads\": [";
        bool firstRead = true;
        for (const rvirvv::VlenRead& vr : fn.vlen_reads)
        {
            if (!firstRead) os << ", ";
            firstRead = false;
            os << "{\"callee\": \"" << jsonEscape(vr.callee)
               << "\", \"line\": " << vr.line
               << ", \"column\": " << vr.column;
            if (!vr.note.empty())
                os << ", \"note\": \"" << jsonEscape(vr.note) << "\"";
            os << "}";
        }
        os << "],\n";

        os << "      \"escapes\": [";
        bool firstEsc = true;
        for (const rvirvv::VlenEscape& e : fn.escapes)
        {
            if (!firstEsc) os << ", ";
            firstEsc = false;
            ++escapeCount;
            os << "{\"kind\": \"" << e.kind
               << "\", \"function\": \"" << jsonEscape(e.function)
               << "\", \"file\": " << jsonStrOrNull(e.file)
               << ", \"line\": " << e.line
               << ", \"column\": " << e.column
               << ", \"target\": \"" << jsonEscape(e.target)
               << "\", \"derived\": " << (e.derived ? "true" : "false")
               << ", \"confidence\": \"" << e.confidence << "\"}";
        }
        os << "],\n";

        os << "      \"verdict\": \"" << fn.verdict << "\",\n";
        os << "      \"uncertain\": " << (fn.uncertain ? "true" : "false") << "\n";
        os << "    }";
    }
    os << "\n  ],\n";

    os << "  \"statistics\": {\n";
    os << "    \"function_count\": " << res.function_count << ",\n";
    os << "    \"vlen_reader_count\": " << res.functions.size() << ",\n";
    os << "    \"escape_count\": " << escapeCount << ",\n";
    os << "    \"truncated_depth\": "
       << (res.truncated_depth ? "true" : "false") << ",\n";
    os << "    \"unresolved_indirect_calls\": " << res.unresolved_indirect_calls << "\n";
    os << "  }\n";
    os << "}\n";
    os.close();
    SVFUtil::outs() << "vlen escape JSON written to " << jsonPath << " ("
                    << res.functions.size() << " vlen readers, "
                    << escapeCount << " escapes)\n";
}

static void writeTrackGlobalJson(const string& filename,
                                 const rvirvv::GlobalReadTrackResult& res)
{
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

    os << "{\n";
    os << "  \"tool\": \"svf-vlenesc\",\n";
    os << "  \"mode\": \"track-global\",\n";
    os << "  \"module\": \"" << jsonEscape(res.module) << "\",\n";

    os << "  \"target\": {\n";
    os << "    \"requested\": \"" << jsonEscape(res.requested) << "\",\n";
    os << "    \"matched_globals\": [";
    bool firstG = true;
    for (const std::string& g : res.matched_globals)
    {
        if (!firstG) os << ", ";
        firstG = false;
        os << "\"" << jsonEscape(g) << "\"";
    }
    os << "],\n";
    os << "    \"fields\": [";
    bool firstF = true;
    for (const rvirvv::GlobalFieldStat& fs : res.fields)
    {
        if (!firstF) os << ", ";
        firstF = false;
        os << "{\"offset\": " << fs.offset << ", \"reads\": " << fs.reads << "}";
    }
    os << "]\n";
    os << "  },\n";

    os << "  \"reads\": [\n";
    bool firstR = true;
    for (const rvirvv::GlobalRead& r : res.reads)
    {
        if (!firstR) os << ",\n";
        firstR = false;
        os << "    {\n";
        os << "      \"function\": \"" << jsonEscape(r.function) << "\",\n";
        os << "      \"file\": " << jsonStrOrNull(r.file) << ",\n";
        os << "      \"line\": " << r.line << ",\n";
        os << "      \"column\": " << r.column << ",\n";
        os << "      \"field_offset\": " << r.field_offset << ",\n";
        os << "      \"confidence\": \"" << r.confidence << "\",\n";
        os << "      \"flows\": [";
        bool firstFlow = true;
        for (const rvirvv::FlowEvent& fe : r.flows)
        {
            if (!firstFlow) os << ", ";
            firstFlow = false;
            os << "{\"kind\": \"" << fe.kind
               << "\", \"detail\": \"" << jsonEscape(fe.detail)
               << "\", \"function\": \"" << jsonEscape(fe.function)
               << "\", \"file\": " << jsonStrOrNull(fe.file)
               << ", \"line\": " << fe.line << "}";
        }
        os << "]\n";
        os << "    }";
    }
    os << "\n  ],\n";

    os << "  \"statistics\": {\n";
    os << "    \"read_count\": " << res.reads.size() << ",\n";
    os << "    \"flow_count\": " << res.flow_count << ",\n";
    os << "    \"truncated_depth\": "
       << (res.truncated_depth ? "true" : "false") << ",\n";
    os << "    \"unresolved_indirect_calls\": " << res.unresolved_indirect_calls << "\n";
    os << "  }\n";
    os << "}\n";
    os.close();
    SVFUtil::outs() << "track-global JSON written to " << jsonPath << " ("
                    << res.reads.size() << " reads, " << res.flow_count
                    << " flows)\n";
}

int main(int argc, char** argv)
{
    std::vector<std::string> moduleNameVec;
    moduleNameVec = OptionBase::parseOptions(
        argc, argv, "vlen Escape Analyzer (RVV)",
        "[options] <input-bitcode...>");

    if (moduleNameVec.empty())
    {
        SVFUtil::errs() << "Error: no input bitcode file specified.\n";
        return 1;
    }

    LLVMModuleSet::preProcessBCs(moduleNameVec);
    LLVMModuleSet::buildSVFModule(moduleNameVec);

    SVFIRBuilder builder;
    SVFIR* pag = builder.build();

    Andersen* ander = AndersenWaveDiff::createAndersenWaveDiff(pag);

    if (!TrackGlobalOpt().empty())
    {
        rvirvv::GlobalReadTracker tracker(pag, ander);
        tracker.setMaxDepth(MaxDepthOpt());
        rvirvv::GlobalReadTrackResult res =
            tracker.analyze(TrackGlobalOpt());
        res.module = moduleNameVec.front();

        if (res.matched_globals.empty())
        {
            SVFUtil::outs() << "track-global: no global matching '"
                            << TrackGlobalOpt() << "' found in module.\n";
        }
        else
        {
            SVFUtil::outs() << "track-global '" << TrackGlobalOpt() << "': "
                            << res.reads.size() << " reads, "
                            << res.flow_count << " flows\n";
        }

        string outFile = OutputJsonOpt() == "vlen_escape.json"
                             ? "track_global.json"
                             : OutputJsonOpt();
        writeTrackGlobalJson(outFile, res);
        goto cleanup;
    }

    {
        rvirvv::VlenEscapeAnalyzer analyzer(pag, ander);
        analyzer.setMaxDepth(MaxDepthOpt());
        rvirvv::VlenEscapeResult res = analyzer.analyze(moduleNameVec.front());

        SVFUtil::outs() << "vlen readers: " << res.functions.size()
                        << " (module functions: " << res.function_count << ")\n";
        for (const rvirvv::VlenRootResult& fn : res.functions)
            SVFUtil::outs() << "  " << fn.name << ": " << fn.verdict
                            << " (escapes: " << fn.escapes.size() << ")\n";

        writeVlenJson(OutputJsonOpt(), res);
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
