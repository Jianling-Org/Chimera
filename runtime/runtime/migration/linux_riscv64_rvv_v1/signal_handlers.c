#define _GNU_SOURCE

#include "signal_handlers.h"

#include <signal.h>
#include <stdint.h>
#ifndef CHIMERA_PORTABLE_SIGNAL_TEST
#include <sys/syscall.h>
#endif
#include <unistd.h>

#include "chimera_debug.h"
#include "chimera_signal.h"
#include "module_registry.h"
#include "runtime_v1.h"
#include "translation_control.h"
#include "vector_state.h"

/* Scene policy: ebreak traps are the exit signal and the kernel's real-time
 * signal carries the packed source vector state for entry. */
#ifdef CHIMERA_PORTABLE_SIGNAL_TEST
/* MinGW's signal constants are not part of the portable test contract.  The
 * test uses the Linux value so the scene binding table remains deterministic;
 * production Linux always takes the SIGTRAP definition below. */
#define SIGNAL_EXIT_TRANSLATION 5
#else
#define SIGNAL_EXIT_TRANSLATION SIGTRAP
#endif
#define SIGNAL_ENTER_TRANSLATION 41

/* A partial sigaction installation must never enable scene migration.  The
 * wrappers become live only after the Linux UAPI has installed every binding.
 */
static volatile sig_atomic_t signal_handlers_ready;

void chimera_scene_disable_signal_handlers(void) {
    signal_handlers_ready = 0;
}

#ifdef CHIMERA_DEBUG
#ifdef CHIMERA_PORTABLE_SIGNAL_TEST
static uint64_t debug_thread_id(void) {
    return UINT64_C(0);
}
#else
static uint64_t debug_thread_id(void) {
    return (uint64_t)syscall(SYS_gettid);
}
#endif

struct debug_pc_location {
    const char *body;
    const char *module;
    uint64_t offset;
};

static struct debug_pc_location debug_describe_pc(uint64_t pc) {
    struct chimera_address_info info;
    struct debug_pc_location location;
    if (chimera_registry_describe_address(chimera_scene_registry(), pc, &info)
        && info.body_label) {
        location.body = info.body_label;
        location.module = info.runtime_name;
        location.offset = pc - info.region_base;
    } else {
        location.body = "unknown";
        location.module = "unknown";
        location.offset = pc;
    }
    return location;
}

static void debug_exit_decision(
    int number, uint64_t current_pc, int rewrite, uint64_t next_pc
) {
    const struct debug_pc_location current = debug_describe_pc(current_pc);
    if (rewrite) {
        const struct debug_pc_location next = debug_describe_pc(next_pc);
        const struct chimera_debug_field fields[] = {
            CHIMERA_DEBUG_U64("signal", (uint64_t)number),
            CHIMERA_DEBUG_U64("tid", debug_thread_id()),
            CHIMERA_DEBUG_HEX("current_pc", current_pc),
            CHIMERA_DEBUG_TEXT("current_body", current.body),
            CHIMERA_DEBUG_TEXT("current_module", current.module),
            CHIMERA_DEBUG_HEX("current_off", current.offset),
            CHIMERA_DEBUG_TEXT("action", "rewrite"),
            CHIMERA_DEBUG_HEX("next_pc", next_pc),
            CHIMERA_DEBUG_TEXT("next_body", next.body),
            CHIMERA_DEBUG_TEXT("next_module", next.module),
            CHIMERA_DEBUG_HEX("next_off", next.offset),
        };
        CHIMERA_DEBUG_EVENT("runtime.signal.exit", fields, 11U);
    } else {
        const struct chimera_debug_field fields[] = {
            CHIMERA_DEBUG_U64("signal", (uint64_t)number),
            CHIMERA_DEBUG_U64("tid", debug_thread_id()),
            CHIMERA_DEBUG_HEX("current_pc", current_pc),
            CHIMERA_DEBUG_TEXT("current_body", current.body),
            CHIMERA_DEBUG_TEXT("current_module", current.module),
            CHIMERA_DEBUG_HEX("current_off", current.offset),
            CHIMERA_DEBUG_TEXT("action", next_pc ? "no-change" : "unmapped-trap"),
        };
        CHIMERA_DEBUG_EVENT("runtime.signal.exit", fields, 7U);
    }
}

static void debug_enter_decision(
    int number, uint64_t current_pc, int has_vlen,
    uint64_t source_vlen_bits, int rewrite, uint64_t next_pc
) {
    const struct debug_pc_location current = debug_describe_pc(current_pc);
    if (!has_vlen) {
        const struct chimera_debug_field fields[] = {
            CHIMERA_DEBUG_U64("signal", (uint64_t)number),
            CHIMERA_DEBUG_U64("tid", debug_thread_id()),
            CHIMERA_DEBUG_HEX("current_pc", current_pc),
            CHIMERA_DEBUG_TEXT("current_body", current.body),
            CHIMERA_DEBUG_TEXT("current_module", current.module),
            CHIMERA_DEBUG_HEX("current_off", current.offset),
            CHIMERA_DEBUG_TEXT("action", "context-unavailable"),
        };
        CHIMERA_DEBUG_EVENT("runtime.signal.enter", fields, 7U);
    } else if (rewrite) {
        const struct debug_pc_location next = debug_describe_pc(next_pc);
        const struct chimera_debug_field fields[] = {
            CHIMERA_DEBUG_U64("signal", (uint64_t)number),
            CHIMERA_DEBUG_U64("tid", debug_thread_id()),
            CHIMERA_DEBUG_HEX("current_pc", current_pc),
            CHIMERA_DEBUG_TEXT("current_body", current.body),
            CHIMERA_DEBUG_TEXT("current_module", current.module),
            CHIMERA_DEBUG_HEX("current_off", current.offset),
            CHIMERA_DEBUG_U64("source_vlen_bits", source_vlen_bits),
            CHIMERA_DEBUG_TEXT("action", "rewrite"),
            CHIMERA_DEBUG_HEX("next_pc", next_pc),
            CHIMERA_DEBUG_TEXT("next_body", next.body),
            CHIMERA_DEBUG_TEXT("next_module", next.module),
            CHIMERA_DEBUG_HEX("next_off", next.offset),
        };
        CHIMERA_DEBUG_EVENT("runtime.signal.enter", fields, 12U);
    } else {
        const struct chimera_debug_field fields[] = {
            CHIMERA_DEBUG_U64("signal", (uint64_t)number),
            CHIMERA_DEBUG_U64("tid", debug_thread_id()),
            CHIMERA_DEBUG_HEX("current_pc", current_pc),
            CHIMERA_DEBUG_TEXT("current_body", current.body),
            CHIMERA_DEBUG_TEXT("current_module", current.module),
            CHIMERA_DEBUG_HEX("current_off", current.offset),
            CHIMERA_DEBUG_U64("source_vlen_bits", source_vlen_bits),
            CHIMERA_DEBUG_TEXT("action", "no-change"),
        };
        CHIMERA_DEBUG_EVENT("runtime.signal.enter", fields, 8U);
    }
}
#else
#define debug_exit_decision(number, current_pc, rewrite, next_pc) ((void)0)
#define debug_enter_decision(number, current_pc, has_vlen, source_vlen_bits, rewrite, next_pc) ((void)0)
#endif

static _Noreturn void stop_unmapped_exit_trap(uint64_t pc) {
    char message[] =
        "chimera: exit trap has no reverse offset-map entry; "
        "pc=0x0000000000000000; execution stopped\n";
    static const char hex[] = "0123456789abcdef";
    const unsigned long start = sizeof(
        "chimera: exit trap has no reverse offset-map entry; pc=0x") - 1U;
    for (unsigned long index = 0; index < 16U; ++index) {
        message[start + index] = hex[(pc >> ((15U - index) * 4U)) & 15U];
    }
    /* Only async-signal-safe operations here.  An unmapped trap can be a
     * translator fallback inside a helper with saved registers and an extra
     * stack frame.  Neither skipping it nor mapping to a nearby instruction
     * restores that state.  Returning unchanged just re-traps forever. */
    chimera_linux_signal_log(message, sizeof(message) - 1U);
    _exit(128 + SIGNAL_EXIT_TRANSLATION);
}

void chimera_linux_handle_exit_translation(void *raw_context) {
    uint64_t current_pc;
    uint64_t next_pc;
    int rewrite;
    if (!chimera_scene_context_pc(raw_context, &current_pc)) return;
    next_pc = query_original_translated_map(CHIMERA_CODE_ORIGINAL, current_pc);
    rewrite = next_pc != UINT64_C(0) && next_pc != current_pc;
    debug_exit_decision(SIGNAL_EXIT_TRANSLATION, current_pc, rewrite, next_pc);
    if (next_pc == UINT64_C(0)) stop_unmapped_exit_trap(current_pc);
    if (rewrite) (void)chimera_scene_set_context_pc(raw_context, next_pc);
}

void chimera_linux_handle_enter_translation(
    const siginfo_t *info, void *raw_context
) {
    CHIMERA_SIGNAL_LOG("chimera: enter-translation handler invoked\n");
    const struct chimera_registry *registry;
    struct chimera_migration_decision decision;
    uint32_t packed;
    uint64_t current_pc;
    uint64_t source_vlen_bits;
    uint64_t next_pc;
    if (!info) return;
    if (!chimera_scene_context_pc(raw_context, &current_pc)) return;
    packed = (uint32_t)(uintptr_t)info->si_ptr;
    if (!chimera_scene_vlen_bits_from_packed(packed, &source_vlen_bits)) {
        debug_enter_decision(
            SIGNAL_ENTER_TRANSLATION, current_pc, 0, UINT64_C(0), 0, UINT64_C(0));
        return;
    }
    registry = chimera_scene_registry();
    if (!chimera_decide_migration(
            registry, current_pc, source_vlen_bits, &decision)) {
        debug_enter_decision(
            SIGNAL_ENTER_TRANSLATION, current_pc, 1, source_vlen_bits, 0, UINT64_C(0));
        return;
    }
    next_pc = query_original_translated_map(decision.target_type, current_pc);
    if (next_pc == current_pc) {
        debug_enter_decision(
            SIGNAL_ENTER_TRANSLATION, current_pc, 1, source_vlen_bits, 0, next_pc);
        return;
    }
    if (!chimera_scene_save_vector_state_packed(
            decision.direction, raw_context, packed)) {
        debug_enter_decision(
            SIGNAL_ENTER_TRANSLATION, current_pc, 1, source_vlen_bits, 0, next_pc);
        return;
    }
    debug_enter_decision(
        SIGNAL_ENTER_TRANSLATION, current_pc, 1, source_vlen_bits, 1, next_pc);
    (void)chimera_scene_set_context_pc(raw_context, next_pc);
}

static void exit_translation(int number, siginfo_t *info, void *raw_context) {
    (void)number;
    (void)info;
    if (!signal_handlers_ready) return;
    chimera_linux_handle_exit_translation(raw_context);
}

static void enter_translation(int number, siginfo_t *info, void *raw_context) {
    (void)number;
    if (!signal_handlers_ready) return;
    chimera_linux_handle_enter_translation(info, raw_context);
}

int chimera_scene_initialize_signal_handlers(void) {
    const struct chimera_linux_signal_binding bindings[] = {
        {SIGNAL_EXIT_TRANSLATION, exit_translation},
        {SIGNAL_ENTER_TRANSLATION, enter_translation},
    };
    /* Keep callbacks inert while a fresh installation is in progress.  If
     * an earlier installation was live, a later partial failure must not
     * leave migration enabled while dispositions are being rolled back. */
    chimera_scene_disable_signal_handlers();
    if (!chimera_linux_install_signal_bindings(
            bindings, sizeof(bindings) / sizeof(bindings[0]))) {
        return 0;
    }
    signal_handlers_ready = 1;
    return 1;
}
