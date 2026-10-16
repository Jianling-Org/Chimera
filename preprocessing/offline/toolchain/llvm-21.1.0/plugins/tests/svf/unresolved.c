#include <stdio.h>

typedef int (*fn_t)(const char *);

volatile fn_t fp;

int main(void) {
    fp = puts;
    return fp("hello");
}
