#include <stdio.h>

typedef void (*fn_t)(int);

__attribute__((noinline))
static void foo(int x) {
    printf("foo %d\n", x);
}

__attribute__((noinline))
static void bar(int x) {
    printf("bar %d\n", x);
}

__attribute__((noinline))
static void baz(int x) {
    printf("baz %d\n", x);
}

volatile fn_t fp1;
volatile fn_t fp2;

int main(int argc, char **argv) {
    fp1 = argc > 1 ? foo : bar;
    fp2 = argc > 2 ? bar : baz;

    fp1(argc);
    fp2(argc);

    return 0;
}