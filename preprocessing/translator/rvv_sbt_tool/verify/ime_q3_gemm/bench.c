#define _GNU_SOURCE
#include <inttypes.h>
#include <math.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { MAX_N = 128, MAX_K = 1024, MAX_B = MAX_K / 256, STRIDE = MAX_N + 8 };
typedef struct { uint16_t d[64]; uint8_t hmask[32*64], qs[64*64], scales[12*64]; } Q3;
typedef struct { float d[4]; int8_t qs[256*4]; int16_t sums[16*4]; } Q8;
typedef struct { int8_t scales[32*16]; uint8_t hmask[32*32], qs[32*64]; uint16_t d[32]; } I3;
typedef struct { float d[4]; int16_t sums[4*16]; int8_t qs[4*256]; } I8;
_Static_assert(sizeof(Q3) == 7040 && sizeof(Q8) == 1168, "RVV repacked ABI");
_Static_assert(sizeof(I3) == 3648 && sizeof(I8) == 1168, "IME2 repacked ABI");

extern void gemm_ime_native(size_t, const uint8_t *, const uint8_t *, float *, size_t, size_t, size_t, size_t);
extern void gemm_ime_translated(size_t, const uint8_t *, const uint8_t *, float *, size_t, size_t, size_t, size_t);
extern void gemm_rvv_baseline(int, float *, size_t, const void *, const void *, int, int);

/* Both physical layouts are built from these same logical quantized values. */
static int8_t qa[4][MAX_K], qb[MAX_N][MAX_K], scales[MAX_N][MAX_B][16];
static float da[4][MAX_B];
static uint16_t db[MAX_N][MAX_B];
static double reference[4][STRIDE];
static int ncols, depth, nblocks, leading;
static const char *names[] = {"ime_native", "ime_translated_rvv", "rvv_baseline"};

struct Buffer { _Alignas(64) unsigned char bytes[MAX_N/32*MAX_B*sizeof(I3) + 128]; size_t used; };
static struct Buffer inputs[4], outputs[3];
static uint32_t rng;
static uint32_t random32(void) { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng; }
static void *payload(struct Buffer *b) { return b->bytes + 64; }
static void init_buffer(struct Buffer *b, size_t size) {
    if (size + 128 > sizeof(b->bytes)) abort();
    b->used = size;
    memset(b->bytes, 0xa5, size + 128);
    memset(payload(b), 0, size);
}
static int guards(const struct Buffer *b) {
    for (unsigned i = 0; i < 64; i++)
        if (b->bytes[i] != 0xa5 || b->bytes[64 + b->used + i] != 0xa5) return 0;
    return 1;
}
static uint64_t input_hash(void) {
    uint64_t h = UINT64_C(1469598103934665603);
    for (unsigned b = 0; b < 4; b++)
        for (size_t i = 0; i < inputs[b].used + 128; i++) h = (h ^ inputs[b].bytes[i]) * UINT64_C(1099511628211);
    return h;
}
static double half_value(uint16_t h) {
    return ldexp(1024.0 + (h & 1023), ((h >> 10) & 31) - 25) * (h & 32768 ? -1 : 1);
}

static void pack_rvv(void) {
    Q3 *b = payload(&inputs[0]); Q8 *a = payload(&inputs[1]);
    memset(b, 0, inputs[0].used); memset(a, 0, inputs[1].used);
    for (int block = 0; block < nblocks; block++) {
        for (int row = 0; row < 4; row++) {
            a[block].d[row] = da[row][block];
            for (int j = 0; j < 256; j++) {
                int v = qa[row][block*256 + j];
                a[block].qs[j*4 + row] = v;
                a[block].sums[(j/16)*4 + row] += v;
            }
        }
        for (int col = 0; col < ncols; col++) {
            Q3 *q = &b[(col/64)*nblocks + block]; int c = col % 64;
            q->d[c] = db[col][block];
            for (int g = 0; g < 16; g++) {
                unsigned v = scales[col][block][g] + 32;
                q->scales[(g%8)*64+c] |= (v & 15) << (4*(g/8));
                q->scales[(8+g%4)*64+c] |= (v >> 4) << (2*(g/4));
            }
            for (int j = 0; j < 256; j++) {
                int v = qb[col][block*256+j];
                q->qs[((j/128)*32+j%32)*64+c] |= (v & 3) << (2*((j%128)/32));
                q->hmask[(j%32)*64+c] |= (v >= 0) << (j/32);
            }
        }
    }
}

static void pack_ime(void) {
    I3 *b = payload(&inputs[2]); I8 *a = payload(&inputs[3]);
    memset(b, 0, inputs[2].used); memset(a, 0, inputs[3].used);
    for (int block = 0; block < nblocks; block++) {
        for (int row = 0; row < 4; row++) {
            a[block].d[row] = da[row][block];
            for (int j = 0; j < 256; j++) {
                int v = qa[row][block*256+j];
                a[block].qs[row*256+j] = v;
                a[block].sums[row*16+j/16] -= v;
            }
        }
        for (int col = 0; col < ncols; col++) {
            I3 *q = &b[(col/32)*nblocks + block]; int c = col % 32;
            q->d[c] = db[col][block];
            for (int g = 0; g < 16; g++) q->scales[g*32+c] = scales[col][block][g];
            for (int j = 0; j < 256; j++) {
                int v = qb[col][block*256+j];
                q->qs[(j/64)*512+c*16+j%16] |= (v & 3) << (2*((j/16)%4));
                q->hmask[(j/16)*64+c*2+(j%16)/8] |= (v >= 0) << (j%8);
            }
        }
    }
}

static void initialize(int k, int n, unsigned seed) {
    depth = k; ncols = n; nblocks = k/256; leading = n + 8; rng = seed;
    init_buffer(&inputs[0], (size_t)(n/64)*nblocks*sizeof(Q3));
    init_buffer(&inputs[1], (size_t)nblocks*sizeof(Q8));
    init_buffer(&inputs[2], (size_t)(n/32)*nblocks*sizeof(I3));
    init_buffer(&inputs[3], (size_t)nblocks*sizeof(I8));
    for (int b = 0; b < nblocks; b++) {
        for (int r = 0; r < 4; r++) {
            da[r][b] = ldexpf(1.0f, -8 + r);
            for (int j = 0; j < 256; j++) qa[r][b*256+j] = (int)(random32() % 256) - 128;
        }
        for (int c = 0; c < n; c++) {
            db[c][b] = 0x2000 + (c%3)*0x400 + ((c & 1) ? 0x8000 : 0);
            for (int g = 0; g < 16; g++) scales[c][b][g] = (int)(random32()%64) - 32;
            for (int j = 0; j < 256; j++) qb[c][b*256+j] = (int)(random32()%8) - 4;
        }
    }
    pack_rvv(); pack_ime();
    for (int r = 0; r < 4; r++) for (int c = 0; c < n; c++) {
        double sum = 0;
        for (int b = 0; b < nblocks; b++) {
            int64_t integer_sum = 0;
            for (int j = 0; j < 256; j++)
                integer_sum += (int)qa[r][b*256+j] * (int)qb[c][b*256+j] * (int)scales[c][b][j/16];
            sum += integer_sum * (double)da[r][b] * half_value(db[c][b]);
        }
        reference[r][c] = sum;
    }
}

static void invoke(int implementation) {
    float *out = payload(&outputs[implementation]);
    if (implementation == 0) gemm_ime_native(256, payload(&inputs[3]), payload(&inputs[2]), out, 4, ncols, nblocks, leading);
    else if (implementation == 1) gemm_ime_translated(256, payload(&inputs[3]), payload(&inputs[2]), out, 4, ncols, nblocks, leading);
    else gemm_rvv_baseline(depth, out, leading, payload(&inputs[0]), payload(&inputs[1]), 4, ncols);
}

static int verify(unsigned seed) {
    uint64_t hash = input_hash(); int failed = 0;
    for (int impl = 0; impl < 3; impl++) {
        init_buffer(&outputs[impl], (size_t)4*leading*sizeof(float));
        memset(payload(&outputs[impl]), 0xa5, outputs[impl].used);
        invoke(impl);
        float *out = payload(&outputs[impl]); double worst = 0; int bad = 0;
        for (int r = 0; r < 4; r++) for (int c = 0; c < ncols; c++) {
            double error = fabs((double)out[r*leading+c] - reference[r][c]);
            if (error > worst) worst = error;
            if (!isfinite(out[r*leading+c]) || error > 2e-5*(1+fabs(reference[r][c]))) {
                if (!bad) fprintf(stderr, "mismatch impl=%s row=%d col=%d actual=%.9g reference=%.17g\n", names[impl],r,c,out[r*leading+c],reference[r][c]);
                bad++;
            }
        }
        for (int r = 0; r < 4; r++) for (int c = ncols; c < leading; c++) {
            uint32_t bits; memcpy(&bits, &out[r*leading+c], 4);
            if (bits != 0xa5a5a5a5) bad++;
        }
        for (int b = 0; b < 4; b++) if (!guards(&inputs[b])) bad++;
        if (!guards(&outputs[impl]) || input_hash() != hash) bad++;
        printf("{\"event\":\"validation\",\"impl\":\"%s\",\"M\":4,\"N\":%d,\"K\":%d,\"seed\":%u,\"bad\":%d,\"max_abs_error\":%.17g}\n",names[impl],ncols,depth,seed,bad,worst);
        fflush(stdout); failed |= bad != 0;
    }
    int same = memcmp(payload(&outputs[0]),payload(&outputs[1]),outputs[0].used) == 0;
    printf("{\"event\":\"native_translated_bitwise\",\"equal\":%s}\n",same?"true":"false");
    return !failed && same;
}

static uint64_t now(void) {
    struct timespec ts; if (clock_gettime(CLOCK_MONOTONIC_RAW,&ts)) abort();
    return (uint64_t)ts.tv_sec*1000000000 + ts.tv_nsec;
}
static unsigned long vector_bytes(void) {
    unsigned long value; __asm__ volatile("csrr %0, vlenb":"=r"(value)); return value;
}
static void check_cpu(int cpu) {
    if (sched_getcpu()!=cpu || vector_bytes()!=128) { fputs("wrong CPU/VLEN\n",stderr); exit(3); }
}

int main(int argc, char **argv) {
    int k=256,n=64,samples=50,rounds=0,verify_only=0;
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"--verify-only")) { verify_only=1; continue; }
        if(i+1==argc) return 2;
        const char *key=argv[i++]; int value=atoi(argv[i]);
        if(!strcmp(key,"--k")) k=value;
        else if(!strcmp(key,"--n")) n=value;
        else if(!strcmp(key,"--samples")) samples=value;
        else if(!strcmp(key,"--rounds")) rounds=value;
        else return 2;
    }
    if(k<256 || k>MAX_K || k%256 || n<64 || n>MAX_N || n%64 || samples<1 || samples>1000 || rounds<0 || rounds>100000) return 2;
    cpu_set_t cpus; if(sched_getaffinity(0,sizeof(cpus),&cpus) || CPU_COUNT(&cpus)!=1) { fputs("pin one A100 CPU before launch\n",stderr); return 3; }
    int cpu=sched_getcpu(); check_cpu(cpu);
    printf("{\"event\":\"environment\",\"cpu\":%d,\"vlenb\":%lu,\"compiler\":\"%s\"}\n",cpu,vector_bytes(),__VERSION__);
    for(int vk=256;vk<=1024;vk*=2) for(int vn=64;vn<=128;vn*=2) for(unsigned seed=1;seed<=4;seed++) {
        initialize(vk,vn,seed); check_cpu(cpu);
        if(!verify(seed)) { fputs("validation failed; no timings produced\n",stderr); return 1; }
    }
    if(verify_only) return 0;
    initialize(k,n,12345); if(!verify(12345)) return 1;
    uint64_t before_hash=input_hash();
    if(!rounds) {
        uint64_t fastest=UINT64_MAX;
        for(int impl=0;impl<3;impl++) { uint64_t t=now(); for(int j=0;j<8;j++) invoke(impl); t=(now()-t)/8; if(t<fastest) fastest=t; }
        rounds=(int)(2000000/(fastest?fastest:1)); if(rounds<1) rounds=1; if(rounds>4096) rounds=4096;
    }
    printf("{\"event\":\"config\",\"M\":4,\"N\":%d,\"K\":%d,\"ldc\":%d,\"rounds\":%d,\"samples\":%d,\"warmup\":5}\n",n,k,leading,rounds,samples);
    for(int pass=-5;pass<samples;pass++) {
        for(int order=0;order<3;order++) {
            int impl=(pass+6+order)%3; check_cpu(cpu);
            uint64_t begin=now(); for(int r=0;r<rounds;r++) invoke(impl); uint64_t elapsed=now()-begin;
            check_cpu(cpu);
            if(pass>=0) printf("{\"event\":\"timing\",\"impl\":\"%s\",\"sample\":%d,\"ns_per_call\":%.3f}\n",names[impl],pass,(double)elapsed/rounds);
        }
        fflush(stdout);
    }
    if(input_hash()!=before_hash || !verify(12345)) return 1;
    for(int p=0;p<2;p++) {
        uint64_t begin=now(); for(int i=0;i<50;i++) { if(p) pack_ime(); else pack_rvv(); }
        printf("{\"event\":\"packing\",\"layout\":\"%s\",\"ns_per_call\":%.3f}\n",p?"ime":"rvv",(double)(now()-begin)/50);
    }
    return 0;
}
