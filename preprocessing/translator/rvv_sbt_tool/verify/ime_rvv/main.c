#include <stdint.h>
#ifdef IME_LINUX
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#endif

_Alignas(16) unsigned char input[4096], output[4096], expected[4096];
uint64_t before_gpr[32], after_gpr[32], before_fpr[32], after_fpr[32];
uint64_t before_csr[5], after_csr[5];
uint64_t stack_canary[2];
uint64_t config_vtype, config_vl, config_vstart, config_vcsr;
uint64_t trap_expected, trapped, trap_resume;

#include "cases.h"

static void puts_uart(const char *s) {
#ifdef IME_LINUX
    fputs(s, stdout);
#else
    while (*s) *(volatile unsigned char *)0x10000000 = *s++;
#endif
}

static void number(unsigned value) {
    char digits[16];
    unsigned count = 0;
    do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
    while (count) {
        char text[2] = {digits[--count], 0};
        puts_uart(text);
    }
}

static void fail(unsigned case_id, unsigned index, const char *kind) {
    puts_uart("FAIL "); puts_uart(kind); puts_uart(" case="); number(case_id);
    puts_uart(" index="); number(index); puts_uart("\n");
#ifdef IME_LINUX
    exit(1);
#else
    *(volatile unsigned *)0x100000 = 0x13333;
    for (;;) {}
#endif
}

static uint32_t read32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void write32(unsigned char *p, uint32_t value) {
    for (unsigned j = 0; j < 4; j++) p[j] = value >> (8 * j);
}

static int element(unsigned reg, unsigned index, unsigned bits, unsigned is_signed) {
    unsigned bit_offset = index * bits;
    unsigned value = expected[reg * 128 + bit_offset / 8];
    value = (value >> (bit_offset % 8)) & ((1u << bits) - 1);
    return is_signed && value >= (1u << (bits - 1)) ? (int)value - (1 << bits) : (int)value;
}

static void reference(const struct Operation *test) {
    if (!trap_expected) {
        unsigned depth = test->bits == 4 ? 32 : 16;
        for (unsigned row = 0; row < 8; row++) {
            for (unsigned col = 0; col < 8; col++) {
                unsigned char *p = expected + test->vd * 128 + (row * 8 + col) * 4;
                uint32_t sum = read32(p);
                for (unsigned k = 0; k < depth; k++) {
                    int a = element(test->vs1, (row + test->slide) * depth + k, test->bits, test->sa);
                    int b = element(test->vs2, col * depth + k, test->bits, test->sb);
                    sum += (uint32_t)(a * b);
                }
                write32(p, sum);
            }
        }
    }
}

static uint64_t read_le(const unsigned char *p, unsigned width) {
    uint64_t value = 0;
    for (unsigned i = 0; i < width / 8; i++) value |= (uint64_t)p[i] << (8 * i);
    return value;
}

static uint64_t narrow_value(uint64_t value, unsigned src, unsigned dst, unsigned saturating) {
    if (saturating) {
        uint64_t mask = src == 64 ? UINT64_MAX : (UINT64_C(1) << src) - 1;
        int64_t signed_value = value & (UINT64_C(1) << (src - 1)) ? -(int64_t)(~value & mask) - 1 : (int64_t)value;
        int64_t maximum = (INT64_C(1) << (dst - 1)) - 1;
        int64_t minimum = -(INT64_C(1) << (dst - 1));
        if (signed_value > maximum) signed_value = maximum;
        if (signed_value < minimum) signed_value = minimum;
        value = (uint64_t)signed_value;
    }
    return value & ((UINT64_C(1) << dst) - 1);
}

static void reference_layout(const struct Operation *test, unsigned sew) {
    unsigned char a[128], b[128], result[256];
    for (unsigned i = 0; i < 128; i++) {
        a[i] = expected[test->vs1 * 128 + i];
        b[i] = expected[test->vs2 * 128 + i];
    }
    unsigned size = test->kind <= 2 ? 256 : 128;
    unsigned chunk = test->kind <= 2 ? (test->imm ? 8u << test->imm : sew / 8) : 4u << test->imm;
    if (test->kind == 1) {
        for (unsigned i = 0; i < size; i++) {
            unsigned block = i / chunk;
            unsigned index = block / 2 * chunk + i % chunk;
            result[i] = block % 2 ? b[index] : a[index];
        }
    } else if (test->kind == 2) {
        for (unsigned i = 0; i < size; i++) {
            unsigned lane = i % 64;
            unsigned index = lane / chunk * (2 * chunk) + (i / 128) * chunk + lane % chunk;
            result[i] = (i % 128) >= 64 ? b[index] : a[index];
        }
    } else {
        unsigned src = test->kind >= 5 ? 8 : sew * 2;
        unsigned dst = test->kind >= 5 ? 4 : sew;
        unsigned lanes = chunk * 8 / src;
        for (unsigned block = 0; block < 128 / chunk; block++) {
            for (unsigned stream = 0; stream < 2; stream++) {
                const unsigned char *source = stream ? b : a;
                for (unsigned lane = 0; lane < lanes; lane++) {
                    uint64_t value = read_le(source + block * chunk + lane * src / 8, src);
                    value = narrow_value(value, src, dst, test->kind == 4 || test->kind == 6);
                    unsigned output_bit = ((block * 2 + stream) * lanes + lane) * dst;
                    if (dst == 4) {
                        if (output_bit % 8) result[output_bit / 8] |= value << 4;
                        else result[output_bit / 8] = value;
                    }
                    else for (unsigned byte = 0; byte < dst / 8; byte++)
                        result[output_bit / 8 + byte] = value >> (byte * 8);
                }
            }
        }
    }
    for (unsigned i = 0; i < size; i++) expected[test->vd * 128 + i] = result[i];
}

static int layout_supported(const struct Operation *op, unsigned sew) {
    if (op->kind >= 5) return sew == 8;
    if (op->kind >= 3) return sew <= 32 && (32u << op->imm) >= 2 * sew;
    return 1;
}

static void saturation_inputs(const struct Operation *op, unsigned sew) {
    unsigned src = op->kind == 6 ? 8 : sew * 2;
    unsigned dst = op->kind == 6 ? 4 : sew;
    int64_t maximum = (INT64_C(1) << (dst - 1)) - 1;
    int64_t minimum = -(INT64_C(1) << (dst - 1));
    const int64_t values[] = {minimum - 1, minimum, minimum + 1, -1, 0, 1, maximum - 1, maximum, maximum + 1};
    for (unsigned stream = 0; stream < 2; stream++) {
        unsigned base = (stream ? op->vs2 : op->vs1) * 128;
        for (unsigned i = 0; i < 128 / (src / 8); i++) {
            uint64_t value = (uint64_t)values[(i + stream) % 9];
            for (unsigned byte = 0; byte < src / 8; byte++)
                input[base + i * src / 8 + byte] = expected[base + i * src / 8 + byte] = value >> (8 * byte);
        }
    }
}

int main(void) {
    unsigned count = 0;
    unsigned rejected = 0;
    uint64_t vlenb;
    __asm__ volatile("csrr %0, vlenb" : "=r"(vlenb));
    if (vlenb != 128) fail(0, vlenb, "vlenb");
#ifdef IME_LINUX
    printf("cpu=%d vlenb=%llu", sched_getcpu(), (unsigned long long)vlenb);
#ifdef IME_NATIVE
    puts_uart(" native_ime_comparison=enabled\n");
#else
    puts_uart(" translated_oracle_comparison=enabled\n");
#endif
#endif
    for (unsigned c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        for (unsigned mode = 0; mode < 51; mode++) {
#ifdef IME_NATIVE
            /* Keep native comparisons at full vl, covering every supported
               SEW/policy and all eight initial vcsr values. */
            if (mode >= 48 || mode % 12 < 8) continue;
#endif
#ifdef IME_LINUX
            if (mode >= 48) continue;
#endif
            for (unsigned seed = 0; seed < 5; seed++) {
                unsigned bits = 8u << (mode % 4);
                unsigned vl_case = (mode / 4) % 3;
                config_vtype = (mode % 4) * 8 + ((mode / 12) % 4) * 64;
                config_vl = vl_case == 0 ? 0 : vl_case == 1 ? 1 : 1024 / bits;
                config_vstart = mode == 48 ? 1 : 0;
                config_vcsr = (seed * 2 + mode % 2) % 8;
                if (mode == 49) config_vtype = 1; /* m2 */
                if (mode == 50) config_vtype = UINT64_MAX; /* vill */
                trap_expected = mode >= 48;
                trapped = 0;
                uint32_t random = 0x12345678u + seed * 1789 + c;
                for (unsigned i = 0; i < sizeof(input); i++) {
                    random = random * 1664525u + 1013904223u;
                    input[i] = expected[i] = seed == 0 ? (i % 2 ? 0x80 : 0xff) : random >> 24;
                    /* Distinct halves expose nibble swaps; all byte values and
                       row markers expose stride or sliding-boundary errors. */
                    if (seed == 3) input[i] = expected[i] = (i * 37 + i / 128) & 255;
                    if (seed == 4) input[i] = expected[i] = i % 2 ? 0x78 : 0xf0;
                }
                /* Force both unsigned wraparound and signed-boundary crossings
                   even for small Int4 dot products. */
                if (seed == 4) {
                    static const uint32_t accumulators[] = {UINT32_MAX - 3, 0x7ffffffe, 0x80000001, 1};
                    for (unsigned op = 0; op < cases[c].length; op++) {
                        if (cases[c].operations[op].kind != 0) continue;
                        unsigned base = cases[c].operations[op].vd * 128;
                        for (unsigned lane = 0; lane < 64; lane++) {
                            write32(input + base + lane * 4, accumulators[lane % 4]);
                            write32(expected + base + lane * 4, accumulators[lane % 4]);
                        }
                    }
                    for (unsigned op = 0; op < cases[c].length; op++) {
                        const struct Operation *test = &cases[c].operations[op];
                        if ((test->kind == 4 || test->kind == 6) && layout_supported(test, bits))
                            saturation_inputs(test, bits);
                    }
                }
                /* The native prefix increments v31 before IME reads its inputs. */
                for (unsigned i = 31 * 128; i < 4096; i++) expected[i]++;
                for (unsigned op = 0; op < cases[c].length && !trap_expected; op++) {
                    const struct Operation *test = &cases[c].operations[op];
                    if (!layout_supported(test, bits)) trap_expected = 1;
                    else if (test->kind) reference_layout(test, bits);
                    else reference(test);
                }
                unsigned implementations = 1;
#ifdef IME_LINUX
                /* Rejection paths run under QEMU's trap handler. The Linux
                   oracle suite validates every supported positive state. */
                if (trap_expected) continue;
#endif
#ifdef IME_NATIVE
                implementations = 2;
#endif
                for (unsigned implementation = 0; implementation < implementations; implementation++) {
                    for (unsigned i = 0; i < sizeof(output); i++) output[i] = (unsigned char)~expected[i];
                    if (implementation == 0) cases[c].run();
#ifdef IME_NATIVE
                    else cases[c].native();
#endif
                    if (trapped != trap_expected) fail(count, trapped, "trap");
                    if (stack_canary[0] != UINT64_C(0x76543210)
                        || stack_canary[1] != ~UINT64_C(0x76543210)) fail(count, 0, "stack-canary");
                    for (unsigned i = 0; i < 4096; i++)
                        if (output[i] != expected[i]) fail(count, i, "vector");
                    for (unsigned i = 0; i < 32; i++) {
                        if (before_gpr[i] != after_gpr[i]) fail(count, i, "gpr");
                        if (before_fpr[i] != after_fpr[i]) fail(count, i, "fpr");
                    }
                    for (unsigned i = 0; i < 5; i++)
                        if (before_csr[i] != after_csr[i]) fail(count, i, "csr");
                    rejected += trapped != 0;
                    count++;
                }
            }
        }
    }
    puts_uart("PASS cases="); number(count);
    puts_uart(" vectors=32x128B gprs=32 fprs=32 csr=vl,vtype,vstart,vcsr,fcsr");
    puts_uart(" completed="); number(count - rejected);
    puts_uart(" rejected="); number(rejected); puts_uart("\n");
    return 0;
}
