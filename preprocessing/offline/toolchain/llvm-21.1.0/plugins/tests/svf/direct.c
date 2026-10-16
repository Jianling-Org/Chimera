__attribute__((noinline))
static int direct_target(int value) {
    return value + 1;
}

int main(int argc, char **argv) {
    (void)argv;
    return direct_target(argc);
}
