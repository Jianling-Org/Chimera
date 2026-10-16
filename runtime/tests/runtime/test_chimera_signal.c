#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "chimera_signal.h"
#include "signal_handlers.h"
#include "module_registry.h"
#include "translation_control.h"
#include "vector_state.h"

enum event {
    EVENT_REGISTRY,
    EVENT_READ_PC,
    EVENT_READ_VLEN,
    EVENT_DECIDE,
    EVENT_QUERY,
    EVENT_SAVE,
    EVENT_WRITE_PC,
};

static enum event events[16];
static size_t event_count;
static struct chimera_registry registry;
static struct chimera_migration_decision next_decision;
static uint64_t current_pc;
static uint32_t current_packed;
static uint32_t saved_packed;
static uint64_t query_result;
static uint64_t written_pc;
static int decision_result;
static int query_target;
static int save_result;

#ifdef CHIMERA_PORTABLE_SIGNAL_TEST
struct fake_signal_slot {
    int number;
    struct sigaction action;
    int installed;
};

static struct fake_signal_slot fake_slots[4];
static unsigned long fake_calls;
static unsigned long fake_fail_call;

static struct fake_signal_slot *fake_slot(int number) {
    size_t index;
    for (index = 0; index < sizeof(fake_slots) / sizeof(fake_slots[0]); ++index) {
        if (fake_slots[index].installed && fake_slots[index].number == number) {
            return &fake_slots[index];
        }
    }
    for (index = 0; index < sizeof(fake_slots) / sizeof(fake_slots[0]); ++index) {
        if (!fake_slots[index].installed) {
            fake_slots[index].number = number;
            fake_slots[index].installed = 1;
            return &fake_slots[index];
        }
    }
    return NULL;
}

static int fake_sigaction(
    int number, const struct sigaction *action, struct sigaction *old_action
) {
    struct fake_signal_slot *slot;
    ++fake_calls;
    if (fake_fail_call != 0 && fake_calls == fake_fail_call) return -1;
    slot = fake_slot(number);
    assert(slot != NULL);
    if (old_action) *old_action = slot->action;
    if (action) slot->action = *action;
    return 0;
}
#endif

static void record(enum event event) {
    assert(event_count < sizeof(events) / sizeof(events[0]));
    events[event_count++] = event;
}

static void reset(void) {
    event_count = 0;
    current_pc = UINT64_C(0x1010);
    /* vlenb=128（VLEN=1024）、vl=4 的打包值：低 14 位 vlenb，bit 14~30 vl */
    current_packed = UINT32_C(128) | (UINT32_C(4) << 14);
    saved_packed = 0;
    query_result = UINT64_C(0x5010);
    written_pc = UINT64_MAX;
    decision_result = 1;
    query_target = -1;
    save_result = 1;
    next_decision.direction = CHIMERA_DIR_1024_TO_256;
    next_decision.target_type = CHIMERA_CODE_TRANSLATED_1024_TO_256;
}

const struct chimera_registry *chimera_scene_registry(void) {
    record(EVENT_REGISTRY);
    return &registry;
}

int chimera_scene_context_pc(const void *raw_context, uint64_t *pc) {
    (void)raw_context;
    record(EVENT_READ_PC);
    *pc = current_pc;
    return 1;
}

int chimera_scene_vlen_bits_from_packed(uint32_t packed, uint64_t *vlen_bits) {
    record(EVENT_READ_VLEN);
    if (!packed) return 0;
    *vlen_bits = (uint64_t)(packed & UINT32_C(0x3fff)) * UINT64_C(8);
    return 1;
}

int chimera_scene_set_context_pc(void *raw_context, uint64_t pc) {
    (void)raw_context;
    record(EVENT_WRITE_PC);
    written_pc = pc;
    return 1;
}

int chimera_decide_migration(
    const struct chimera_registry *candidate,
    uint64_t pc,
    uint64_t source_vlen_bits,
    struct chimera_migration_decision *out
) {
    record(EVENT_DECIDE);
    assert(candidate == &registry);
    assert(pc == current_pc);
    assert(source_vlen_bits == (uint64_t)(current_packed & UINT32_C(0x3fff)) * 8);
    if (!decision_result) return 0;
    *out = next_decision;
    return 1;
}

uint64_t query_original_translated_map(int target_type, uint64_t addr_in) {
    record(EVENT_QUERY);
    query_target = target_type;
    assert(addr_in == current_pc);
    return query_result;
}

int chimera_scene_save_vector_state_packed(
    enum chimera_direction direction,
    void *raw_context,
    uint32_t packed
) {
    (void)raw_context;
    record(EVENT_SAVE);
    assert(direction == next_decision.direction);
    saved_packed = packed;
    assert(((packed >> 14) & UINT32_C(0x1ffff)) == UINT32_C(4));
    return save_result;
}

static siginfo_t signal_info(void) {
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    info.si_ptr = (void *)(uintptr_t)current_packed;
    return info;
}

static void assert_events(const enum event *expected, size_t count) {
    size_t index;
    assert(event_count == count);
    for (index = 0; index < count; ++index) assert(events[index] == expected[index]);
}

static void portable_callback(int number, siginfo_t *info, void *raw_context) {
    (void)number;
    (void)info;
    (void)raw_context;
}

int main(int argc, char **argv) {
    static const enum event successful_enter[] = {
        EVENT_READ_PC, EVENT_READ_VLEN, EVENT_REGISTRY, EVENT_DECIDE,
        EVENT_QUERY, EVENT_SAVE, EVENT_WRITE_PC,
    };
    static const enum event unchanged_enter[] = {
        EVENT_READ_PC, EVENT_READ_VLEN, EVENT_REGISTRY, EVENT_DECIDE,
        EVENT_QUERY,
    };
    static const enum event rejected_enter[] = {
        EVENT_READ_PC, EVENT_READ_VLEN, EVENT_REGISTRY, EVENT_DECIDE,
    };
    static const enum event successful_exit[] = {
        EVENT_READ_PC, EVENT_QUERY, EVENT_WRITE_PC,
    };
    static const enum event unchanged_exit[] = {
        EVENT_READ_PC, EVENT_QUERY,
    };

    /* Run fatal paths in separate processes: returning from an unmapped
     * synchronous trap would execute the same ebreak indefinitely. */
    if (argc == 2 && strcmp(argv[1], "--unmapped-exit") == 0) {
        reset();
        current_pc = UINT64_C(0x50f0);
        query_result = UINT64_C(0);
        chimera_linux_handle_exit_translation((void *)(uintptr_t)1);
        return 7; /* The handler must not return to an unmapped trap. */
    }
#ifndef CHIMERA_PORTABLE_SIGNAL_TEST
    if (argc == 2 && strcmp(argv[1], "--unmapped-trap") == 0) {
        reset();
        current_pc = UINT64_C(0x50f0);
        query_result = UINT64_C(0);
        assert(chimera_scene_initialize_signal_handlers());
        raise(SIGTRAP);
        return 7;
    }
#endif
    assert(argc == 1);

#ifdef CHIMERA_PORTABLE_SIGNAL_TEST
    const struct chimera_linux_signal_binding bindings[] = {
        {41, portable_callback}, {5, portable_callback},
    };
    const struct chimera_linux_signal_binding duplicate[] = {
        {41, portable_callback}, {41, portable_callback},
    };
    const struct chimera_linux_signal_binding missing_callback[] = {
        {41, NULL},
    };
    const struct chimera_linux_signal_binding invalid_number[] = {
        {0, portable_callback},
    };
    const struct chimera_linux_signal_binding too_large[] = {
        {999, portable_callback},
    };
    chimera_linux_set_sigaction_hook(fake_sigaction);
    assert(chimera_linux_install_signal_bindings(bindings, 2));
    assert(fake_calls == 2);
    assert(fake_slots[0].action.sa_sigaction == portable_callback);
    assert(fake_slots[1].action.sa_sigaction == portable_callback);
    assert(!chimera_linux_install_signal_bindings(duplicate, 2));
    assert(!chimera_linux_install_signal_bindings(missing_callback, 1));
    assert(!chimera_linux_install_signal_bindings(invalid_number, 1));
    assert(!chimera_linux_install_signal_bindings(too_large, 1));

    /* The scene entry point uses the same installer; portable builds must
     * exercise that path instead of treating initialization as an unconditional
     * success shim. */
    fake_calls = 0;
    assert(chimera_scene_initialize_signal_handlers());
    assert(fake_calls == 2);

    fake_calls = 0;
    fake_fail_call = 2;
    struct sigaction before_first = fake_slots[0].action;
    struct sigaction before_second = fake_slots[1].action;
    assert(!chimera_linux_install_signal_bindings(bindings, 2));
    assert(fake_calls == 3); /* first install, failed second, rollback first */
    assert(memcmp(&fake_slots[0].action, &before_first, sizeof(before_first)) == 0);
    assert(memcmp(&fake_slots[1].action, &before_second, sizeof(before_second)) == 0);
    fake_fail_call = 0;
#else
    const struct chimera_linux_signal_binding bindings[] = {
        {41, portable_callback}, {SIGTRAP, portable_callback},
    };
    assert(chimera_linux_install_signal_bindings(bindings, 2));
#endif

    reset();
    siginfo_t info = signal_info();
    chimera_linux_handle_enter_translation(&info, (void *)(uintptr_t)1);
    assert_events(successful_enter, sizeof(successful_enter) / sizeof(successful_enter[0]));
    assert(query_target == CHIMERA_CODE_TRANSLATED_1024_TO_256);
    assert(written_pc == query_result);
    assert(saved_packed == current_packed);

    /* A rejected state save must not publish a translated PC.  Before
     * the fix the handler ignored save failure and entered with stale TLS. */
    reset();
    info = signal_info();
    save_result = 0;
    chimera_linux_handle_enter_translation(&info, (void *)(uintptr_t)1);
    assert(written_pc == UINT64_MAX);
    assert_events(successful_enter,
        sizeof(successful_enter) / sizeof(successful_enter[0]) - 1);

    reset();
    info = signal_info();
    query_result = current_pc;
    chimera_linux_handle_enter_translation(&info, (void *)(uintptr_t)1);
    assert_events(unchanged_enter, sizeof(unchanged_enter) / sizeof(unchanged_enter[0]));
    assert(written_pc == UINT64_MAX);

    reset();
    info = signal_info();
    decision_result = 0;
    chimera_linux_handle_enter_translation(&info, (void *)(uintptr_t)1);
    assert_events(rejected_enter, sizeof(rejected_enter) / sizeof(rejected_enter[0]));
    assert(query_target == -1);
    assert(written_pc == UINT64_MAX);

    reset();
    query_result = UINT64_C(0x1010);
    current_pc = UINT64_C(0x5010);
    chimera_linux_handle_exit_translation((void *)(uintptr_t)1);
    assert_events(successful_exit, sizeof(successful_exit) / sizeof(successful_exit[0]));
    assert(query_target == CHIMERA_CODE_ORIGINAL);
    assert(written_pc == query_result);

    reset();
    current_pc = UINT64_C(0x5010);
    query_result = current_pc;
    chimera_linux_handle_exit_translation((void *)(uintptr_t)1);
    assert_events(unchanged_exit, sizeof(unchanged_exit) / sizeof(unchanged_exit[0]));
    assert(written_pc == UINT64_MAX);
    return 0;
}
