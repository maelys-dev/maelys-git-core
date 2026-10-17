#include "internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

const char *maelys_git_result_name(maelys_git_result_t result) {
    switch (result) {
        case MAELYS_GIT_OK: return "ok";
        case MAELYS_GIT_ERR_INVALID_ARGUMENT: return "invalid_argument";
        case MAELYS_GIT_ERR_INVALID_COMMAND: return "invalid_command";
        case MAELYS_GIT_ERR_INVALID_REPOSITORY: return "invalid_repository";
        case MAELYS_GIT_ERR_POLICY: return "policy_error";
        case MAELYS_GIT_ERR_DENIED: return "denied";
        case MAELYS_GIT_ERR_IO: return "io_error";
        case MAELYS_GIT_ERR_PROCESS: return "process_error";
        case MAELYS_GIT_ERR_PROTOCOL: return "protocol_error";
        case MAELYS_GIT_ERR_LIMIT: return "limit_exceeded";
        case MAELYS_GIT_ERR_NOT_FOUND: return "not_found";
    }
    return "unknown";
}

const char *maelys_git_failure_kind_name(maelys_git_failure_kind_t kind) {
    switch (kind) {
        case MAELYS_GIT_FAILURE_NONE: return "none";
        case MAELYS_GIT_FAILURE_CAPACITY: return "capacity";
        case MAELYS_GIT_FAILURE_SYNTAX: return "syntax";
        case MAELYS_GIT_FAILURE_SEMANTICS: return "semantics";
        case MAELYS_GIT_FAILURE_MANIFEST: return "manifest";
        case MAELYS_GIT_FAILURE_VALUE: return "value";
        case MAELYS_GIT_FAILURE_ENGINE: return "engine";
    }
    return "unknown";
}

void maelys_git_error_clear(maelys_git_error_t *error) {
    if (error) memset(error, 0, sizeof(*error));
}

void mg_error_set(maelys_git_error_t *error,
                  maelys_git_result_t code,
                  int system_error,
                  const char *format,
                  ...) {
    if (!error) return;
    error->code = code;
    error->system_error = system_error;
    error->message[0] = '\0';
    memset(&error->detail, 0, sizeof(error->detail));
    if (format) {
        va_list args;
        va_start(args, format);
        (void)vsnprintf(error->message, sizeof(error->message), format, args);
        va_end(args);
    }
}

void mg_error_set_detail(maelys_git_error_t *error, const maelys_git_failure_detail_t *detail) {
    if (error && detail && error->code == MAELYS_GIT_ERR_POLICY) error->detail = *detail;
}
