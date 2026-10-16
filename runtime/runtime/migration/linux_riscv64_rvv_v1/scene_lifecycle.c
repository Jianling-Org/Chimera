#include "scene_lifecycle.h"

#include "chimera_environment.h"
#include "chimera_signal.h"
#include "runtime_v1.h"
#include "signal_handlers.h"

int chimera_scene_initialize_runtime(const char *workspace) {
    /* A failed re-initialization must not leave handlers from an earlier
     * successful initialization able to migrate code. */
    chimera_scene_disable_signal_handlers();
    if (!workspace) {
        CHIMERA_SIGNAL_LOG(
            "chimera: runtime initialization failed; workspace is missing\n"
        );
        return 0;
    }
    if (!chimera_linux_prepare_environment()) {
        CHIMERA_SIGNAL_LOG(
            "chimera: runtime initialization failed; environment setup failed\n"
        );
        return 0;
    }
    if (!chimera_scene_load_workspace(workspace)) {
        CHIMERA_SIGNAL_LOG(
            "chimera: runtime initialization failed; workspace load failed\n"
        );
        return 0;
    }
    if (!chimera_scene_initialize_signal_handlers()) {
        CHIMERA_SIGNAL_LOG(
            "chimera: runtime initialization failed; signal setup failed\n"
        );
        return 0;
    }
    return 1;
}
