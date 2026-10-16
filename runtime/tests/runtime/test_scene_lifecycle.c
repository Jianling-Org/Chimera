#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "scene_lifecycle.h"

enum event {
    EVENT_ENVIRONMENT,
    EVENT_WORKSPACE,
    EVENT_SIGNAL,
    EVENT_LOG,
};

static enum event events[8];
static size_t event_count;
static int environment_result = 1;
static int workspace_result = 1;
static int signal_result = 1;

static void reset(void) {
    event_count = 0;
    environment_result = 1;
    workspace_result = 1;
    signal_result = 1;
}

static void record(enum event event) {
    assert(event_count < sizeof(events) / sizeof(events[0]));
    events[event_count++] = event;
}

int chimera_linux_prepare_environment(void) {
    record(EVENT_ENVIRONMENT);
    return environment_result;
}

int chimera_scene_load_workspace(const char *workspace) {
    assert(workspace != NULL);
    record(EVENT_WORKSPACE);
    return workspace_result;
}

int chimera_scene_initialize_signal_handlers(void) {
    record(EVENT_SIGNAL);
    return signal_result;
}

void chimera_scene_disable_signal_handlers(void) {
    /* The lifecycle test supplies the scene signal hook; ready-state behavior
     * is covered by test_chimera_signal with the real installer. */
}

void chimera_linux_signal_log(const char *literal, unsigned long length) {
    (void)literal;
    (void)length;
    record(EVENT_LOG);
}

static void assert_events(const enum event *expected, size_t count) {
    size_t index;
    assert(event_count == count);
    for (index = 0; index < count; ++index) assert(events[index] == expected[index]);
}

int main(void) {
    static const enum event success[] = {
        EVENT_ENVIRONMENT, EVENT_WORKSPACE, EVENT_SIGNAL,
    };
    static const enum event workspace_failure[] = {
        EVENT_ENVIRONMENT, EVENT_WORKSPACE, EVENT_LOG,
    };
    static const enum event signal_failure[] = {
        EVENT_ENVIRONMENT, EVENT_WORKSPACE, EVENT_SIGNAL, EVENT_LOG,
    };
    static const enum event environment_failure[] = {
        EVENT_ENVIRONMENT, EVENT_LOG,
    };
    static const enum event missing_workspace[] = {EVENT_LOG};

    reset();
    assert(chimera_scene_initialize_runtime("workspace"));
    assert_events(success, sizeof(success) / sizeof(success[0]));

    reset();
    environment_result = 0;
    assert(!chimera_scene_initialize_runtime("workspace"));
    assert_events(environment_failure, sizeof(environment_failure) / sizeof(environment_failure[0]));

    reset();
    workspace_result = 0;
    assert(!chimera_scene_initialize_runtime("workspace"));
    assert_events(workspace_failure, 3);

    reset();
    signal_result = 0;
    assert(!chimera_scene_initialize_runtime("workspace"));
    assert_events(signal_failure, sizeof(signal_failure) / sizeof(signal_failure[0]));

    reset();
    assert(!chimera_scene_initialize_runtime(NULL));
    assert_events(missing_workspace, sizeof(missing_workspace) / sizeof(missing_workspace[0]));
    return 0;
}
