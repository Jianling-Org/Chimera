#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <unistd.h>
#include "integrity.h"

/* v1 TSV: executable, sha256, workspace, runtime, runtime-sha256.
 * All paths are absolute. Unregistered programs remain ordinary processes. */
static int matches(const char *workspace, const char *path, const char *digest) {
    struct chimera_manifest_artifact artifact = {0};
    if (path[0] != '/' || strlen(path) >= sizeof(artifact.path)
        || strlen(digest) != 64) return 0;
    strcpy(artifact.path, path);
    strcpy(artifact.sha256, digest);
    return chimera_artifact_matches(workspace, &artifact);
}

static int ready(pid_t task) {
    char tid[32];
    int length = snprintf(tid, sizeof(tid), "ready:%ld\n", (long)task);
    int fd = open("/proc/prefer_a100", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n;
    do { n = write(fd, tid, (size_t)length); } while (n < 0 && errno == EINTR);
    int saved_errno = errno;
    close(fd);
    return n == length || (n < 0 && (saved_errno == ESRCH || saved_errno == EBUSY || saved_errno == EPERM));
}

static void publish_ready_tasks(void) {
    /* Earlier DSO constructors may already have created threads. The kernel
     * accepts only current-thread-group TIDs with their inherited policy on. */
    DIR *tasks = opendir("/proc/self/task");
    struct dirent *entry;
    if (!tasks) {
        if (!ready(getpid())) fprintf(stderr, "chimera bootstrap: migration registration failed\n");
        return;
    }
    while ((entry = readdir(tasks))) {
        char *end;
        long task = strtol(entry->d_name, &end, 10);
        if (*end || task <= 0 || task > INT_MAX) continue;
        if (!ready((pid_t)task))
            fprintf(stderr, "chimera bootstrap: migration registration failed for tid=%ld\n", task);
    }
    closedir(tasks);
}

static int inherited_preference(void) {
    FILE *status = fopen("/proc/self/status", "re");
    char line[512];
    int enabled = 0;
    if (!status) return 0;
    while (fgets(line, sizeof(line), status)) {
        if (!strncmp(line, "Prefer_a100:", 12)) {
            enabled = strtol(line + 12, NULL, 10) == 1;
            break;
        }
    }
    fclose(status);
    return enabled;
}

__attribute__((constructor))
static void initialize_bootstrap(void) {
    const char *registry = getenv("CHIMERA_REGISTRY");
    char executable[PATH_MAX], line[16384], selected[16384] = {0};
    FILE *source;
    ssize_t length;
    if (!registry || getauxval(AT_SECURE)) return;
    /* A parent workspace must never initialize an unrelated child. */
    unsetenv("CHIMERA_WORKSPACE");
    unsetenv("CHIMERA_RESOURCES");
    length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (length <= 0 || (size_t)length >= sizeof(executable) - 1) return;
    executable[length] = 0;
    source = fopen(registry, "re");
    if (!source) return;
    if (!fgets(line, sizeof(line), source) || strcmp(line, "chimera-registry-v1\n")) {
        fclose(source); return;
    }
    while (fgets(line, sizeof(line), source)) {
        char *tab = strchr(line, '\t');
        if (!strchr(line, '\n')) { fclose(source); return; }
        if (tab && (size_t)(tab-line) == strlen(executable)
            && !strncmp(line, executable, (size_t)(tab-line))) {
            if (selected[0]) { fclose(source); return; }
            strcpy(selected, line);
        }
    }
    int failed = ferror(source);
    fclose(source);
    if (failed || !selected[0]) return;
    char *fields[5], *cursor = selected;
    for (int i = 0; i < 5; ++i) {
        fields[i] = strsep(&cursor, "\t\n");
        if (!fields[i] || !fields[i][0]) return;
    }
    if (!cursor || *cursor || fields[2][0] != '/' || fields[3][0] != '/') return;
    if (!matches(fields[2], "/proc/self/exe", fields[1]) || !matches(fields[2], fields[3], fields[4])) return;
    if (dlsym(RTLD_DEFAULT, "chimera_runtime_abi_v1")) {
        fprintf(stderr, "chimera bootstrap: another runtime is already loaded\n");
        return;
    }
    void *handle = dlopen(fields[3], RTLD_NOW | RTLD_GLOBAL);
    if (!handle) { fprintf(stderr, "chimera bootstrap: %s\n", dlerror()); return; }
    const unsigned long long *abi = dlsym(handle, "chimera_runtime_abi_v1");
    int (*initialize)(const char *) = dlsym(handle, "chimera_runtime_initialize_v1");
    if (!abi || *abi != 1 || !initialize || !initialize(fields[2])) {
        fprintf(stderr, "chimera bootstrap: runtime initialization failed for %s\n", executable);
        return;
    }
    if (getenv("CHIMERA_BOOTSTRAP_TRACE"))
        fprintf(stderr, "chimera bootstrap: initialized pid=%ld executable=%s workspace=%s\n",
                (long)getpid(), executable, fields[2]);
    if (setenv("CHIMERA_WORKSPACE", fields[2], 1)) return;
    char resources[PATH_MAX];
    struct stat resource_info;
    int written = snprintf(resources, sizeof(resources), "%s/resources", fields[2]);
    if (written > 0 && (size_t)written < sizeof(resources)
        && !stat(resources, &resource_info) && S_ISDIR(resource_info.st_mode)
        && setenv("CHIMERA_RESOURCES", resources, 1)) return;
    if (inherited_preference()) publish_ready_tasks();
    /* Keep the DSO alive: signal handlers and maps point into it. */
}
