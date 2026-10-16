#include <dlfcn.h>
#include <stdio.h>

typedef int (*fn_t)(const char *);

int main(void) {
    void *sym = dlsym(RTLD_DEFAULT, "puts");
    fn_t fp = (fn_t)sym;

    return fp("hello");
}
