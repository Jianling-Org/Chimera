#define _GNU_SOURCE

#include "chimera_dynamic_loader.h"

#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct range_query { const char *name; int main; uint64_t base; uint64_t end; int found; };

static const char *basename_of(const char *path) {
    const char *slash = path ? strrchr(path, '/') : NULL;
    return slash ? slash + 1 : path;
}

static int range_callback(struct dl_phdr_info *info, size_t size, void *data) {
    struct range_query *query = data;
    uint64_t low = UINT64_MAX, high = 0;
    ElfW(Half) index;
    int is_main = !info->dlpi_name || !info->dlpi_name[0];
    (void)size;
    if ((query->main && !is_main) || (!query->main && (is_main || strcmp(basename_of(info->dlpi_name), query->name)))) return 0;
    for (index = 0; index < info->dlpi_phnum; ++index) {
        uint64_t begin, end;
        if (info->dlpi_phdr[index].p_type != PT_LOAD) continue;
        begin = info->dlpi_addr + info->dlpi_phdr[index].p_vaddr;
        end = begin + info->dlpi_phdr[index].p_memsz;
        if (begin < low) low = begin;
        if (end > high) high = end;
    }
    if (low == UINT64_MAX || low >= high) return 0;
    query->base = low; query->end = high; query->found = 1; return 1;
}

void *chimera_linux_open_workspace_library(const char *workspace, const char *relative_name) {
    char path[4096]; int length;
    if (!workspace || !relative_name) return NULL;
    length = snprintf(path, sizeof(path), "%s/%s", workspace, relative_name);
    if (length < 0 || (size_t)length >= sizeof(path)) return NULL;
    return dlopen(path, RTLD_NOW | RTLD_GLOBAL);
}

void *chimera_linux_lookup_symbol(void *handle, const char *symbol) {
    if (!handle || !symbol) return NULL;
    dlerror(); return dlsym(handle, symbol);
}

int chimera_linux_module_range(const char *runtime_name, int is_main, uint64_t *base, uint64_t *end) {
    struct range_query query = {basename_of(runtime_name), is_main, 0, 0, 0};
    if (!runtime_name || !base || !end) return 0;
    dl_iterate_phdr(range_callback, &query);
    if (!query.found) return 0;
    *base = query.base; *end = query.end; return 1;
}
