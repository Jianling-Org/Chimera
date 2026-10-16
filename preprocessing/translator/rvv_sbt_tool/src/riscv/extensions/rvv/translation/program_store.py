"""Private, per-invocation storage for an already analyzed program.

Only records written from the current prepared program are read. This is not
an import format: the caller owns an unlinked TemporaryFile for its lifetime.
Independent function records bound pickle's memo and the resident read cache.
"""

from collections.abc import Mapping, Sequence
from array import array
from dataclasses import replace
import pickle

from riscv.frontend.model import RVProgram


class _Functions(Sequence):
    def __init__(self, store):
        self.store = store

    def __len__(self):
        return len(self.store.offsets)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[item] for item in range(*index.indices(len(self)))]
        return self.store.record(index)[0]


class _Analysis(Mapping):
    def __init__(self, store, indices, attribute=None):
        self.store = store
        self.indices = indices
        self.attribute = attribute

    def __len__(self):
        return len(self.indices)

    def __iter__(self):
        return iter(self.indices)

    def __getitem__(self, address):
        analysis = self.store.record(self.indices[address])[1]
        return analysis if self.attribute is None else getattr(analysis, self.attribute)


class PreparedProgramStore:
    """Retain global facts and load one source function with its CFG/vtype facts."""

    def __init__(self, stream, program, analysis, program_context):
        self.stream = stream
        self.offsets = array("Q")
        self.current_offset = None
        self.current_record = None
        header = (
            program.symbols,
            program.global_labels,
            replace(analysis, functions={}, function_summaries={},
                    structure=replace(analysis.structure, functions={})),
            program_context,
        )
        pickle.dump(header, stream, protocol=pickle.HIGHEST_PROTOCOL)
        indices = {}
        for index, function in enumerate(program.functions):
            self.offsets.append(stream.tell())
            indices[function.start_addr] = index
            # A fresh memo per function avoids a program-sized serialization
            # peak; the source function and its analysis share the same record.
            pickle.dump(
                (function, analysis.for_function(function.start_addr)),
                stream,
                protocol=pickle.HIGHEST_PROTOCOL,
            )
        index_offset = stream.tell()
        pickle.dump((
            {address: indices[address] for address in analysis.functions},
            {address: indices[address] for address in analysis.function_summaries},
        ), stream, protocol=pickle.HIGHEST_PROTOCOL)
        stream.flush()
        # Reload global facts too: keeping scattered strings/integers from the
        # original IR can otherwise pin its Python allocator arenas after GC.
        stream.seek(0)
        self.symbols, self.global_labels, self.analysis_header, self.program_context = pickle.load(stream)
        stream.seek(index_offset)
        self.analysis_indices, self.summary_indices = pickle.load(stream)

    def record(self, index):
        offset = self.offsets[index]
        if offset != self.current_offset:
            self.stream.seek(offset)
            self.current_record = pickle.load(self.stream)
            self.current_offset = offset
        return self.current_record

    def views(self):
        stored_program = RVProgram(
            functions=_Functions(self),
            symbols=self.symbols,
            global_labels=self.global_labels,
        )
        stored_analysis = replace(
            self.analysis_header,
            functions=_Analysis(self, self.analysis_indices),
            function_summaries=_Analysis(self, self.summary_indices, "vtype_summary"),
            structure=replace(
                self.analysis_header.structure,
                functions=_Analysis(self, self.analysis_indices, "structure"),
            ),
        )
        return stored_program, stored_analysis
