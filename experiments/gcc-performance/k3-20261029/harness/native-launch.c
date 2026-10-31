/* Experiment-only scalar syscall trampoline. No libc/TLS/vector state before
 * choosing a static group or enabling the official per-exec ready protocol. */
typedef unsigned long U;
static long syscall3(long n, long x, long y, long z) {
    register long a0 __asm__("a0")=x;
    register long a1 __asm__("a1")=y;
    register long a2 __asm__("a2")=z;
    register long a7 __asm__("a7")=n;
    __asm__ volatile("ecall":"+r"(a0):"r"(a1),"r"(a2),"r"(a7):"memory");
    return a0;
}
static int eq(const char *a,const char *b) {while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int prefix(const char *a,const char *b) {while(*b)if(*a++!=*b++)return 0;return 1;}
static int copy(char *out,const char *in) {int n=0;while(in[n]){out[n]=in[n];n++;}return n;}
static int decimal(char *out,U value) {char reverse[32];int n=0,j=0;do{reverse[n++]=(char)('0'+value%10);value/=10;}while(value);while(n)out[j++]=reverse[--n];return j;}
__attribute__((noreturn)) static void fail(void) {
    static const char text[]="chimera-perf native-launch: placement or exec failed\n";
    syscall3(64,2,(long)text,sizeof(text)-1);syscall3(94,125,0,0);__builtin_unreachable();
}
static void write_control(const char *path,const char *text,int length) {
    long fd=syscall3(56,-100,(long)path,1);if(fd<0)fail();
    long rc;do{rc=syscall3(64,fd,(long)text,length);}while(rc==-4);
    if(rc!=length||syscall3(57,fd,0,0)<0)fail();
}
__attribute__((used,noreturn)) void launch_main(U *stack) {
    U argc=*stack;char **argv=(char **)(stack+1);char **envp=argv+argc+1;
    if(argc<3||argv[2][0]!='/')fail();
    int auto_x=eq(argv[1],"auto-x100"),auto_a=eq(argv[1],"auto-a100");
    int ai=eq(argv[1],"a100");
    if(!ai&&!eq(argv[1],"x100")&&!auto_x&&!auto_a)fail();
    long pid=syscall3(172,0,0,0);if(pid<=0)fail();
    char number[32],request[64],pid_env[64];int digits=decimal(number,(U)pid),n=0;
    if(!ai)request[n++]='-';for(int i=0;i<digits;i++)request[n++]=number[i];request[n++]='\n';
    write_control("/proc/set_ai_thread",request,n);
    U mask=ai?0xff00UL:0xffUL;
    if(syscall3(122,0,sizeof(mask),(long)&mask)<0)fail();
    U actual=0;if(syscall3(123,0,sizeof(actual),(long)&actual)<0||!actual||(actual&~mask))fail();
    char *environment[1024];int entries=0,trace=0;
    for(char **p=envp;*p;p++) {
        if(eq(*p,"CHIMERA_PERF_TRACE=1"))trace=1;
        if(prefix(*p,"LD_PRELOAD=")||prefix(*p,"CHIMERA_WORKSPACE=")||prefix(*p,"CHIMERA_RESOURCES=")||
           prefix(*p,"CHIMERA_AUTOMIGRATE=")||prefix(*p,"CHIMERA_LAUNCH_PID=")||prefix(*p,"CHIMERA_VERIFY_TABLES_ONLY=")||
           prefix(*p,"CHIMERA_REGISTRY=")||prefix(*p,"CHIMERA_BOOTSTRAP=")||prefix(*p,"CHIMERA_BOOTSTRAP_TRACE=")||
           prefix(*p,"GLIBC_TUNABLES="))continue;
        if(entries>=1000)fail();environment[entries++]=*p;
    }
    /* The controller checks this exact tunable against bootstrap_tunables(). */
    environment[entries++]="GLIBC_TUNABLES=glibc.rtld.optional_static_tls=65536";
    if(auto_x||auto_a) {
        n=copy(request,"inherit:");for(int i=0;i<digits;i++)request[n++]=number[i];request[n++]='\n';
        write_control(auto_x?"/proc/prefer_x100":"/proc/prefer_a100",request,n);
        n=copy(pid_env,"CHIMERA_LAUNCH_PID=");for(int i=0;i<digits;i++)pid_env[n++]=number[i];pid_env[n]=0;
        environment[entries++]="LD_PRELOAD=/root/chimera-gcc-validation-578ab8321/build/runtime/libchimera-bootstrap.so";
        environment[entries++]="CHIMERA_BOOTSTRAP=/root/chimera-gcc-validation-578ab8321/build/runtime/libchimera-bootstrap.so";
        environment[entries++]="CHIMERA_REGISTRY=/root/chimera-gcc-validation-578ab8321/runtime-validation/registry.tsv";
        environment[entries++]=pid_env;
        if(trace)environment[entries++]="CHIMERA_BOOTSTRAP_TRACE=1";
    }
    environment[entries]=0;
    syscall3(221,(long)argv[2],(long)(argv+2),(long)environment);fail();
}
__asm__(".global _start\n.type _start,@function\n_start:\n"
        ".option push\n.option norelax\nla gp,__global_pointer$\n.option pop\n"
        "mv a0,sp\ncall launch_main\nunimp\n.size _start,.-_start\n");
