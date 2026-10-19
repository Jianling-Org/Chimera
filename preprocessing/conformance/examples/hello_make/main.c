extern unsigned long __riscv_vsetvl_e32m1(unsigned long);
int util_compute(int n);
unsigned long g_vl;
int main(void) {
    unsigned long vl = __riscv_vsetvl_e32m1(16);
    g_vl = vl;                 /* GLOBAL escape candidate */
    return util_compute((int)vl);
}
