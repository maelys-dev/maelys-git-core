#include "agent_internal.h"

#include <time.h>

int64_t mg_now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) return 0;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

uint64_t mg_retry_delay_ms(const char *key,
                           unsigned attempt,
                           uint64_t base_ms,
                           uint64_t maximum_ms) {
    uint64_t delay = base_ms;
    unsigned shifts = attempt > 16u ? 16u : attempt;
    for (unsigned i = 0u; i < shifts && delay < maximum_ms; ++i) {
        delay = delay > maximum_ms / 2u ? maximum_ms : delay * 2u;
    }
    if (delay > maximum_ms) delay = maximum_ms;
    uint64_t hash = 1469598103934665603ULL;
    for (const unsigned char *p = (const unsigned char *)(key ? key : ""); *p; ++p) {
        hash ^= *p;
        hash *= 1099511628211ULL;
    }
    uint64_t spread = delay / 4u;
    uint64_t jittered = spread == 0u ? delay : delay - spread / 2u + hash % (spread + 1u);
    return jittered > maximum_ms ? maximum_ms : jittered;
}
