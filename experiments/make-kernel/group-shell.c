/* Experiment-only scalar exec trampoline, not a migration runtime.
 * No libc, TLS, constructors, or vector instructions before/after group change.
 * A new shell/ELF starts only after placement; it then stays within that group.
 */
typedef unsigned long ulong;
static long call3(long nr, long x, long y, long z) {
    register long a0 __asm__("a0") = x;
    register long a1 __asm__("a1") = y;
    register long a2 __asm__("a2") = z;
    register long a7 __asm__("a7") = nr;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a7) : "memory");
    return a0;
}
static int prefix(const char *s, const char *p) {
    while (*p) if (*s++ != *p++) return 0;
    return 1;
}
__attribute__((noreturn)) static void fail(void) {
    static const char message[] = "group-shell: placement/exec failed\n";
    call3(64, 2, (long)message, sizeof(message)-1);
    call3(94, 125, 0, 0);
    __builtin_unreachable();
}
__attribute__((used,noreturn)) void group_main(ulong *stack) {
    ulong argc = *stack;
    char **argv = (char **)(stack+1);
    char **envp = argv+argc+1;
    int mixed = 0, found = 0;
    for (char **p = envp; *p; ++p) {
        if (prefix(*p,"CHIMERA_PERF_LAYOUT=")) {
            const char *v = *p+sizeof("CHIMERA_PERF_LAYOUT=")-1;
            if (prefix(v,"mixed") && v[5]==0) mixed=1;
            else if (!(prefix(v,"x100") && v[4]==0)) fail();
            found=1;
        }
    }
    if (!found || argc<2) fail();
    ulong hash=1469598103934665603UL;
    for (ulong i=1; i<argc; ++i) {
        for (unsigned char *s=(unsigned char *)argv[i]; *s; ++s) hash=(hash ^ *s)*1099511628211UL;
        hash=(hash ^ 255)*1099511628211UL;
    }
    int ai=mixed && (hash&1);
    long pid=call3(172,0,0,0);
    if (pid<=0) fail();
    char digits[32], text[32]; int n=0,j=0;
    do {digits[n++]=(char)('0'+pid%10);pid/=10;} while(pid);
    if (!ai) text[j++]='-';
    while(n) text[j++]=digits[--n];
    text[j++]='\n';
    long fd=call3(56,-100,(long)"/proc/set_ai_thread",1); /* openat */
    if (fd<0 || call3(64,fd,(long)text,j)!=j) fail();
    if (call3(57,fd,0,0)<0) fail();
    ulong mask=ai?0xff00UL:0xffUL;
    if (call3(122,0,sizeof(mask),(long)&mask)<0) fail();
    argv[0]="/bin/sh";
    call3(221,(long)"/bin/sh",(long)argv,(long)envp);
    fail();
}
__asm__(".global _start\n.type _start,@function\n_start:\n"
        "mv a0,sp\ncall group_main\nunimp\n.size _start,.-_start\n");
