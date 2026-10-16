#!/usr/bin/env python3
"""Adapt the exact historical eight-thread harness, preserving its workload."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil

HISTORICAL_SHA = "08646f427938736686d7f50ce908e285c294d56598ab70d3cfce0309c6a3a015"

DECLARATIONS = r"""
typedef struct { int8_t scales[512]; uint8_t hmask[1024], qs[2048]; uint16_t d[32]; } I3;
typedef struct { float d[4]; int16_t sums[64]; int8_t qs[1024]; } I8;
_Static_assert(sizeof(I3)==3648 && sizeof(I8)==1168, "IME packing");
extern void gemm_ime_native(size_t,const uint8_t *,const uint8_t *,float *,size_t,size_t,size_t,size_t);
extern void gemm_ime_translated(size_t,const uint8_t *,const uint8_t *,float *,size_t,size_t,size_t,size_t);
static I3 *ime_weights;
static I8 *ime_inputs;
static int implementation;
"""

PACK = r"""
static void prepare_ime(void) {
    memset(ime_weights, 0, (size_t)(n/32)*blocks*sizeof(I3));
    memset(ime_inputs, 0, (size_t)(m/4)*blocks*sizeof(I8));
    for (int c=0;c<n;c++) for (int b=0;b<blocks;b++) {
        I3 *q=&ime_weights[(c/32)*blocks+b]; int col=c%32;
        q->d[col]=0x2400;
        for (int g=0;g<16;g++) q->scales[g*32+col]=-32;
        for (int x=0;x<256;x++) {
            int value=raw_w[(size_t)c*k+b*256+x];
            q->qs[(x/64)*512+col*16+x%16] |= (value&3) << (2*((x/16)%4));
            q->hmask[(x/16)*64+col*2+(x%16)/8] |= (value>=0) << (x%8);
        }
    }
    for (int r=0;r<m;r++) for (int b=0;b<blocks;b++) {
        I8 *q=&ime_inputs[(r/4)*blocks+b]; int row=r%4;
        q->d[row]=0.03125f;
        for (int x=0;x<256;x++) {
            int value=raw_x[(size_t)r*k+b*256+x];
            q->qs[row*256+x]=value;
            q->sums[row*16+x/16]-=value;
        }
    }
}
"""

CALL = r"""        for (int i = 0; i < iterations; ++i) {
            if (implementation == 2) {
                bench_kernel(k, output+(size_t)first_row*stride+first_col, stride,
                             weights+(first_col/64)*blocks, inputs+(first_row/4)*blocks, rows, cols);
            } else {
                /* The IME m4 function handles exactly four rows; the worker's
                   original rectangular assignment and output stride stay intact. */
                for (int r=first_row;r<first_row+rows;r+=4) {
                    const uint8_t *a=(const uint8_t *)(ime_inputs+(r/4)*blocks);
                    const uint8_t *b=(const uint8_t *)(ime_weights+(first_col/32)*blocks);
                    float *c=output+(size_t)r*stride+first_col;
                    if (implementation==0) gemm_ime_native(256,a,b,c,4,cols,blocks,stride);
                    else gemm_ime_translated(256,a,b,c,4,cols,blocks,stride);
                }
            }
        }"""


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--historical", type=Path, required=True, help="operator-8c8t-v256 directory")
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    native = args.historical / "native.c"
    source = native.read_text()
    if hashlib.sha256(native.read_bytes()).hexdigest() != HISTORICAL_SHA:
        raise ValueError("historical driver changed; review before adapting")
    args.out.mkdir(parents=True, exist_ok=True)
    source = source.replace('typedef struct { uint8_t * base, * data; size_t size; } Buffer;', DECLARATIONS + '\ntypedef struct { uint8_t * base, * data; size_t size; } Buffer;')
    source = source.replace('static void compute(int iterations, int check_environment) {', PACK + '\nstatic void compute(int iterations, int check_environment) {')
    source = source.replace('CPU_SET(t, &set)', 'CPU_SET(8+t, &set)')
    source = source.replace('if (cpu >= 8)', 'if (cpu < 8 || cpu >= 16)')
    source = source.replace('observed_vlenb[t] != 32 || affinity[t] != (1ul << t)', 'observed_vlenb[t] != 128 || affinity[t] != (1ul << (8+t))')
    before = '''        for (int i = 0; i < iterations; ++i)
            bench_kernel(k, output+(size_t)first_row*stride+first_col, stride,
                         weights+(first_col/64)*blocks, inputs+(first_row/4)*blocks, rows, cols);'''
    assert source.count(before) == 1
    source = source.replace(before, CALL)
    source = source.replace('if (argc != 6', 'if (argc != 7')
    source = source.replace('    stride = n+PAD; blocks = k/256;', '''    if (argv[6][0] < '0' || argv[6][0] > '2' || argv[6][1]) return 2;
    implementation=argv[6][0]-'0';
    if (n/64 < THREADS && THREADS % (n/64)) return 2;
    stride = n+PAD; blocks = k/256;''')
    source = source.replace('    prepare();', '''    Buffer iwb = buffer((size_t)(n/32)*blocks*sizeof(I3));
    Buffer ixb = buffer((size_t)(m/4)*blocks*sizeof(I8));
    ime_weights=(I3 *)iwb.data; ime_inputs=(I8 *)ixb.data;
    prepare();
    prepare_ime();
    uint64_t iwh=hash(iwb.data,iwb.size), ixh=hash(ixb.data,ixb.size);''')
    source = source.replace('failure || !guards(wb) || !guards(xb) || !guards(yb)', 'failure || !guards(wb) || !guards(xb) || !guards(yb) || !guards(iwb) || !guards(ixb)')
    source = source.replace('    int intact = guards(wb)', '    int intact = guards(iwb) && guards(ixb) && iwh==hash(iwb.data,iwb.size) && ixh==hash(ixb.data,ixb.size) && guards(wb)')
    source = source.replace(r'\"vlenb\":32', r'\"vlenb\":128')
    source = source.replace('    return failure || !intact;', '''    char output_path[4096];
    snprintf(output_path,sizeof(output_path),"%s.%d.out",argv[5],implementation);
    FILE *saved=fopen(output_path,"wb");
    if(!saved || fwrite(output,sizeof(float),(size_t)m*stride,saved)!=(size_t)m*stride || fclose(saved)) abort();
    return failure || !intact;''')
    (args.out / "full-bench.c").write_text(source)
    files = ["kernel.S", "kernel.bin", "ffn_up_m32.ref", "ffn_down_m32.ref", "attn_q_m32.ref", "attn_kv_m32.ref"]
    for name in files:
        shutil.copyfile(args.historical / name, args.out / name)
    manifest = {
        "historical_driver": str(native), "historical_driver_sha256": HISTORICAL_SHA,
        "adapted_driver_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "preserved": ["M/N/K", "seed and logical quantized values", "Q3/Q8 RVV packing",
                      "column/row worker partition", "PAD=16", "8-thread LLVM OpenMP region",
                      "3 warmups and calibration", "50 samples", "0.1-second target batches",
                      "CLOCK_MONOTONIC_RAW", "independent historical references"],
        "changed": ["A100 CPUs 8-15, VLEN=1024", "IME packing and row-by-4 adapter", "three implementation selector"],
        "input_files_sha256": {name:hashlib.sha256((args.out/name).read_bytes()).hexdigest() for name in files},
    }
    (args.out / "full-manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps(manifest,indent=2))


if __name__ == "__main__":
    main()
