#define _GNU_SOURCE

#include "chimera_signal.h"

#include <signal.h>
#include <unistd.h>

#if defined(CHIMERA_PORTABLE_SIGNAL_TEST)
/* The portable hook models the target's signal range even when the host C
 * library exposes a smaller signal range. */
#define CHIMERA_SIGNAL_LIMIT 128
#elif defined(NSIG)
#define CHIMERA_SIGNAL_LIMIT NSIG
#elif defined(_NSIG)
#define CHIMERA_SIGNAL_LIMIT _NSIG
#else
/* The portable test ABI has no host signal table; all POSIX signal numbers
 * used by the scene are below this conservative upper bound. */
#define CHIMERA_SIGNAL_LIMIT 128
#endif

#ifdef CHIMERA_PORTABLE_SIGNAL_TEST
static chimera_linux_sigaction_hook sigaction_hook;

void chimera_linux_set_sigaction_hook(chimera_linux_sigaction_hook hook) {
    sigaction_hook = hook;
}

static int invoke_sigaction(
    int number, const struct sigaction *action, struct sigaction *old_action
) {
    return sigaction_hook ? sigaction_hook(number, action, old_action) : -1;
}
#else
static int invoke_sigaction(
    int number, const struct sigaction *action, struct sigaction *old_action
) {
    return sigaction(number, action, old_action);
}
#endif

static int install_one(
    int number,
    chimera_linux_signal_callback callback,
    struct sigaction *old_action
) {
    struct sigaction action = {0};
    action.sa_sigaction = callback;
#ifdef CHIMERA_PORTABLE_SIGNAL_TEST
    action.sa_flags = 1UL;
#else
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
#endif
    return invoke_sigaction(number, &action, old_action) == 0;
}

int chimera_linux_install_signal_bindings(
    const struct chimera_linux_signal_binding *bindings,
    unsigned long count
) {
    unsigned long index;
    unsigned long installed = 0;
    int rollback_failed = 0;
    /* There can be at most one binding per signal number.  Bound the count
     * before allocating the rollback table so an untrusted caller cannot
     * turn this API into an unbounded VLA stack allocation. */
    if (count > (unsigned long)CHIMERA_SIGNAL_LIMIT) {
        CHIMERA_SIGNAL_LOG("chimera: too many signal bindings\n");
        return 0;
    }
    struct sigaction old_actions[count ? count : 1];
    if (!bindings && count != 0) return 0;
    for (index = 0; index < count; ++index) {
        if (bindings[index].number <= 0
            || bindings[index].number >= CHIMERA_SIGNAL_LIMIT) {
            CHIMERA_SIGNAL_LOG("chimera: signal binding has an invalid number\n");
            return 0;
        }
        if (!bindings[index].callback) {
            CHIMERA_SIGNAL_LOG("chimera: signal binding has no callback\n");
            return 0;
        }
        for (unsigned long prior = 0; prior < index; ++prior) {
            if (bindings[prior].number == bindings[index].number) {
                CHIMERA_SIGNAL_LOG("chimera: duplicate signal binding\n");
                return 0;
            }
        }
    }
    for (index = 0; index < count; ++index) {
        if (!install_one(
                bindings[index].number, bindings[index].callback,
                &old_actions[index]
            )) {
            CHIMERA_SIGNAL_LOG(
                "chimera: failed to install signal disposition\n"
            );
            while (installed != 0) {
                --installed;
                if (invoke_sigaction(
                        bindings[installed].number, &old_actions[installed], NULL
                    ) != 0) {
                    rollback_failed = 1;
                }
            }
            if (rollback_failed) {
                CHIMERA_SIGNAL_LOG(
                    "chimera: failed to restore signal disposition\n"
                );
            }
            return 0;
        }
        ++installed;
    }
    return 1;
}

void chimera_linux_signal_log(const char *literal, unsigned long length) {
    if (literal) {
        ssize_t result = write(STDERR_FILENO, literal, length);
        (void)result;
    }
}
