int util_compute(int n) { return n * 2 + 1; }

/* stub so the demo links for riscv64 */
unsigned long __riscv_vsetvl_e32m1(unsigned long avl) { return avl < 16 ? avl : 16; }
