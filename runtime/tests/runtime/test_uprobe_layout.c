#include "chimera_uprobe.h"

int main(void) {
    struct chimera_uprobe_info info = {0};
    return sizeof(info) == 176 ? 0 : 1;
}
