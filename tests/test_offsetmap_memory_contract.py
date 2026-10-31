import json
import gzip
import tempfile
import unittest
from pathlib import Path
from chimera.preprocess.offline.analysis.offsetmap.model import PackedOffsetMapping
from chimera.preprocess.offline.analysis.offsetmap.codegen import export_json
from chimera.preprocess.offline.analysis.offsetmap.codegen import _read_lines


class OffsetMapMemoryContractTests(unittest.TestCase):
    def test_compressed_input_preserves_line_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'code.dump.gz'
            with gzip.open(path, 'wt', encoding='utf-8') as output:
                output.write('a\nb\nlast')
            self.assertEqual(list(_read_lines(path)), ['a\n', 'b\n', 'last'])
            self.assertEqual(list(_read_lines(path.with_suffix(''))), ['a\n', 'b\n', 'last'])

    def test_packed_lookup_and_serialization_match_dictionary(self):
        for mapping in ({}, {0: 0}, {4096: 8192, 8: 16, 2**63: 2**64-1}):
            with self.subTest(mapping=mapping), tempfile.TemporaryDirectory() as tmp:
                packed = PackedOffsetMapping(mapping)
                self.assertEqual(dict(packed.items()), mapping)
                self.assertEqual(list(packed), sorted(mapping))
                self.assertIsNone(packed.get(7))
                with self.assertRaises(KeyError):
                    packed[7]
                path = Path(tmp) / 'map.json'
                export_json(packed, path)
                rows = [{'original': a, 'original_hex': hex(a),
                         'translated': b, 'translated_hex': hex(b)}
                        for a, b in sorted(mapping.items())]
                expected = json.dumps({'format': 'chimera-offset-map-v1',
                    'entries': rows}, ensure_ascii=False, indent=2) + '\n'
                self.assertEqual(path.read_text(), expected)
