#ifndef CHIMERA_RVV_SIGNAL_HANDLERS_H
#define CHIMERA_RVV_SIGNAL_HANDLERS_H

#include "chimera_signal.h"

int chimera_scene_initialize_signal_handlers(void);
void chimera_scene_disable_signal_handlers(void);
void chimera_linux_handle_enter_translation(
    const siginfo_t *info, void *raw_context);
void chimera_linux_handle_exit_translation(void *raw_context);

#endif
