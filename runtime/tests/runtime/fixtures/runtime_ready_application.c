#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "scene_lifecycle.h"

static void emit(const char *message) {
    size_t length = strlen(message);
    assert(write(STDOUT_FILENO, message, length) == (ssize_t)length);
}

static void migration_handler(int number) {
    (void)number;
}

/* Only initialization is controlled: inject.c's real constructor decides
 * whether and when to publish the launch PID. */
int chimera_scene_initialize_runtime(const char *workspace) {
    const char *result = getenv("CHIMERA_TEST_INIT_RESULT");
    assert(workspace != NULL);
    emit("runtime-initializing\n");
    if (!result || strcmp(result, "1") != 0) return 0;
    assert(signal(SIGTRAP, migration_handler) != SIG_ERR);
    assert(signal(41, migration_handler) != SIG_ERR);
    emit("handlers-installed\n");
    return 1;
}

int main(int argc, char **argv) {
    emit("application-started\n");
    if (argc > 1 && strcmp(argv[1], "exec-child") == 0) {
        pid_t child = fork();
        int status;
        assert(child >= 0);
        if (child == 0) {
            execl(argv[0], argv[0], "child", (char *)NULL);
            _exit(127);
        }
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    return 0;
}
