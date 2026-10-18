#ifndef CHIMERA_LINUX_CONTEXT_H
#define CHIMERA_LINUX_CONTEXT_H

#include <linux/ptrace.h>
#include <ucontext.h>

/* The UAPI only transports the host context.  Architecture-specific state
 * interpretation belongs to the selected scene implementation. */
typedef ucontext_t chimera_linux_context;

#endif /* CHIMERA_LINUX_CONTEXT_H */
