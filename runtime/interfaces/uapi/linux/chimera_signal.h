#ifndef CHIMERA_LINUX_SIGNAL_H
#define CHIMERA_LINUX_SIGNAL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>

#ifdef _WIN32
/* The portable contract tests run with the host compiler and only need the
 * si_ptr payload field; Linux builds use the system siginfo_t definition. */
typedef struct { void *si_ptr; } chimera_test_siginfo_t;
#define siginfo_t chimera_test_siginfo_t
#ifdef CHIMERA_PORTABLE_SIGNAL_TEST
struct sigaction {
    void (*sa_sigaction)(int, siginfo_t *, void *);
    unsigned long sa_flags;
};
#endif
#endif

typedef void (*chimera_linux_signal_callback)(
    int number, siginfo_t *info, void *raw_context);

struct chimera_linux_signal_binding {
    int number;
    chimera_linux_signal_callback callback;
};

#ifdef CHIMERA_PORTABLE_SIGNAL_TEST
typedef int (*chimera_linux_sigaction_hook)(
    int number, const struct sigaction *action, struct sigaction *old_action);
void chimera_linux_set_sigaction_hook(chimera_linux_sigaction_hook hook);
#endif

/* Linux owns sigaction installation only.  Scene code supplies the bindings
 * and remains responsible for interpreting the OS context. */
int chimera_linux_install_signal_bindings(
    const struct chimera_linux_signal_binding *bindings,
    unsigned long count);
void chimera_linux_signal_log(const char *literal, unsigned long length);

#define CHIMERA_SIGNAL_LOG(literal) chimera_linux_signal_log((literal), sizeof(literal) - 1U)

#endif
