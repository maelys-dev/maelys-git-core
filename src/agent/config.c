#include "agent_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static int object_has_only(json_t *object, const char *const *allowed) {
    const char *key;
    json_t *value;
    json_object_foreach(object, key, value) {
        (void)value;
        int found = 0;
        for (size_t i = 0u; allowed[i]; ++i) {
            if (strcmp(key, allowed[i]) == 0) { found = 1; break; }
        }
        if (!found) return 0;
    }
    return 1;
}

/* kind: 0=config, 1=secret token, 2=trusted input that may be a system symlink. */
static int secure_regular_file(const char *path, int kind, maelys_git_error_t *error) {
    struct stat status;
    if ((kind == 2 ? stat(path, &status) : lstat(path, &status)) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_NOT_FOUND, errno,
                     "cannot inspect %s: %s", path, strerror(errno));
        return 0;
    }
    mode_t forbidden = kind == 1 ? 077u : 022u;
    int owner_ok = kind == 1 ? status.st_uid == geteuid() :
                   (status.st_uid == geteuid() || status.st_uid == 0u);
    if (!S_ISREG(status.st_mode) || !owner_ok ||
        (status.st_mode & forbidden) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0,
                     "%s must be a regular file owned by the agent%s",
                     path, kind == 1 ? " with no group/world permissions" :
                                       " and not group/world-writable");
        return 0;
    }
    return 1;
}

static int copy_json_string(json_t *root,
                            const char *name,
                            char *out,
                            size_t capacity,
                            int required) {
    json_t *value = json_object_get(root, name);
    if (!value && !required) return 1;
    return json_is_string(value) && json_string_length(value) > 0u &&
           mg_copy_string(out, capacity, json_string_value(value));
}

static int absolute_path(const char *path) { return path && path[0] == '/'; }

static int authority_valid(const char *authority) {
    if (!authority || !*authority || strchr(authority, '/') || strchr(authority, '@') ||
        strstr(authority, "://")) return 0;
    for (const unsigned char *p = (const unsigned char *)authority; *p; ++p) {
        if (*p <= 0x20u || *p == 0x7fu) return 0;
    }
    return 1;
}

static int identifier_valid(const char *value) {
    size_t length = value ? strlen(value) : 0u;
    if (length == 0u || length >= MG_AGENT_ID_MAX) return 0;
    for (size_t i = 0u; i < length; ++i) {
        unsigned char ch = (unsigned char)value[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == ':'))
            return 0;
    }
    return 1;
}

static int target_valid(const char *target) {
    if (!target || target[0] != '/' || target[1] == '/') return 0;
    for (const unsigned char *p = (const unsigned char *)target; *p; ++p)
        if (*p <= 0x20u || *p == 0x7fu || *p == '#') return 0;
    return 1;
}

maelys_git_result_t mg_config_load(const char *path,
                                   maelys_git_agent_config_t **out,
                                   maelys_git_error_t *error) {
    static const char *const allowed[] = {
        "version", "agent_id", "authority", "ca_file", "token_file",
        "database_path", "manifest_path", "repository_root", "git_executable",
        "executor_path", "command_target", "event_target", "poll_timeout_ms",
        "request_timeout_ms", NULL
    };
    if (!path || !out) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out = NULL;
    if (!secure_regular_file(path, 0, error)) return error ? error->code : MAELYS_GIT_ERR_DENIED;
    json_error_t json_error;
    json_t *root = json_load_file(path, JSON_REJECT_DUPLICATES, &json_error);
    if (!root) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid config: %.180s", json_error.text);
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    maelys_git_agent_config_t *config = calloc(1u, sizeof(*config));
    json_t *version = json_object_get(root, "version");
    json_t *poll = json_object_get(root, "poll_timeout_ms");
    json_t *request = json_object_get(root, "request_timeout_ms");
    int valid = config && json_is_object(root) && object_has_only(root, allowed) &&
                json_is_integer(version) && json_integer_value(version) == 1 &&
                copy_json_string(root, "agent_id", config->agent_id, sizeof(config->agent_id), 1) &&
                copy_json_string(root, "authority", config->authority, sizeof(config->authority), 1) &&
                copy_json_string(root, "ca_file", config->ca_file, sizeof(config->ca_file), 1) &&
                copy_json_string(root, "token_file", config->token_file, sizeof(config->token_file), 1) &&
                copy_json_string(root, "database_path", config->database_path, sizeof(config->database_path), 1) &&
                copy_json_string(root, "manifest_path", config->manifest_path, sizeof(config->manifest_path), 1) &&
                copy_json_string(root, "repository_root", config->repository_root, sizeof(config->repository_root), 1) &&
                copy_json_string(root, "git_executable", config->git_executable, sizeof(config->git_executable), 1) &&
                copy_json_string(root, "executor_path", config->executor_path, sizeof(config->executor_path), 1) &&
                copy_json_string(root, "command_target", config->command_target, sizeof(config->command_target), 1) &&
                copy_json_string(root, "event_target", config->event_target, sizeof(config->event_target), 1) &&
                json_is_integer(poll) && json_is_integer(request);
    if (valid) {
        config->poll_timeout_ms = (uint64_t)json_integer_value(poll);
        config->request_timeout_ms = (uint64_t)json_integer_value(request);
        valid = identifier_valid(config->agent_id) && authority_valid(config->authority) &&
                absolute_path(config->ca_file) &&
                absolute_path(config->token_file) && absolute_path(config->database_path) &&
                absolute_path(config->manifest_path) && absolute_path(config->repository_root) &&
                absolute_path(config->git_executable) && absolute_path(config->executor_path) &&
                target_valid(config->command_target) && target_valid(config->event_target) &&
                config->poll_timeout_ms >= 1000u && config->poll_timeout_ms <= 120000u &&
                config->request_timeout_ms >= 1000u && config->request_timeout_ms <= 120000u;
    }
    json_decref(root);
    if (!valid) {
        free(config);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "configuration does not match version 1 schema");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    if (!secure_regular_file(config->token_file, 1, error) ||
        !secure_regular_file(config->ca_file, 2, error) ||
        !secure_regular_file(config->manifest_path, 2, error)) {
        free(config);
        return error ? error->code : MAELYS_GIT_ERR_DENIED;
    }
    *out = config;
    return MAELYS_GIT_OK;
}

void mg_config_free(maelys_git_agent_config_t *config) {
    if (!config) return;
    memset(config, 0, sizeof(*config));
    free(config);
}

maelys_git_result_t mg_token_load(const char *path,
                                  char *out,
                                  size_t capacity,
                                  maelys_git_error_t *error) {
    if (!path || !out || capacity < 2u) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    out[0] = '\0';
    if (!secure_regular_file(path, 1, error)) return error ? error->code : MAELYS_GIT_ERR_DENIED;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot open token: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    struct stat opened;
    if (fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
        opened.st_uid != geteuid() || (opened.st_mode & 077u) != 0) {
        int saved = errno;
        (void)close(fd);
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, saved, "opened token file is not secure");
        return MAELYS_GIT_ERR_DENIED;
    }
    ssize_t count = 0;
    while ((size_t)count < capacity) {
        ssize_t chunk = read(fd, out + count, capacity - (size_t)count);
        if (chunk < 0 && errno == EINTR) continue;
        if (chunk < 0) { count = -1; break; }
        if (chunk == 0) break;
        count += chunk;
    }
    int saved = errno;
    (void)close(fd);
    if (count <= 0 || (size_t)count >= capacity) {
        memset(out, 0, capacity);
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, saved, "token is empty or too long");
        return MAELYS_GIT_ERR_LIMIT;
    }
    while (count > 0 && (out[count - 1] == '\n' || out[count - 1] == '\r')) --count;
    out[count] = '\0';
    if (count == 0) return MAELYS_GIT_ERR_PROTOCOL;
    for (ssize_t i = 0; i < count; ++i) {
        unsigned char ch = (unsigned char)out[i];
        if (ch <= 0x20u || ch == 0x7fu) {
            memset(out, 0, capacity);
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "token contains forbidden characters");
            return MAELYS_GIT_ERR_PROTOCOL;
        }
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_agent_provision(
    const char *config_path, const char *agent_id, const char *authority,
    const char *ca_file, const char *token_file, const char *database_path,
    const char *manifest_path, const char *repository_root, const char *executor_path,
    maelys_git_error_t *error) {
    maelys_git_result_t validation = maelys_git_agent_validate_provision(
        config_path, agent_id, authority, ca_file, token_file, database_path,
        manifest_path, repository_root, executor_path, error);
    if (validation != MAELYS_GIT_OK) return validation;

    json_t *root = json_pack("{s:i,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:s,s:I,s:I}",
        "version", 1, "agent_id", agent_id, "authority", authority,
        "ca_file", ca_file, "token_file", token_file, "database_path", database_path,
        "manifest_path", manifest_path, "repository_root", repository_root,
        "git_executable", "/usr/bin/git", "executor_path", executor_path,
        "command_target", "/v1/agent/commands", "event_target", "/v1/agent/events",
        "poll_timeout_ms", (json_int_t)30000, "request_timeout_ms", (json_int_t)30000);
    if (!root) return MAELYS_GIT_ERR_IO;
    int fd = open(config_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        json_decref(root);
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot create config: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    FILE *stream = fdopen(fd, "w");
    int failed = !stream || json_dumpf(root, stream, JSON_INDENT(2) | JSON_SORT_KEYS) != 0 ||
                 fputc('\n', stream) == EOF || fflush(stream) != 0 || fsync(fd) != 0;
    if (stream) (void)fclose(stream); else (void)close(fd);
    json_decref(root);
    if (failed) {
        (void)unlink(config_path);
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot write config");
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_agent_validate_provision(
    const char *config_path, const char *agent_id, const char *authority,
    const char *ca_file, const char *token_file, const char *database_path,
    const char *manifest_path, const char *repository_root, const char *executor_path,
    maelys_git_error_t *error) {
    if (!config_path || !agent_id || !authority || !ca_file || !token_file ||
        !database_path || !manifest_path || !repository_root || !executor_path ||
        !absolute_path(config_path) || !absolute_path(ca_file) || !absolute_path(token_file) ||
        !absolute_path(database_path) || !absolute_path(manifest_path) ||
        !absolute_path(repository_root) || !absolute_path(executor_path) ||
        !authority_valid(authority) || !identifier_valid(agent_id)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0,
                     "provisioning values must use valid identifiers and absolute paths");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    if (!secure_regular_file(token_file, 1, error)) return error ? error->code : MAELYS_GIT_ERR_DENIED;
    if (!secure_regular_file(ca_file, 2, error) || !secure_regular_file(manifest_path, 2, error))
        return error ? error->code : MAELYS_GIT_ERR_DENIED;
    struct stat status;
    if (stat(repository_root, &status) != 0 || !S_ISDIR(status.st_mode)) {
        mg_error_set(error, MAELYS_GIT_ERR_NOT_FOUND, errno, "repository root is not a directory");
        return MAELYS_GIT_ERR_NOT_FOUND;
    }
    if (stat(executor_path, &status) != 0 || !S_ISREG(status.st_mode) || access(executor_path, X_OK) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_NOT_FOUND, errno, "executor is not an executable regular file");
        return MAELYS_GIT_ERR_NOT_FOUND;
    }
    if (lstat(config_path, &status) == 0 || errno != ENOENT) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, errno,
                     "configuration target already exists or is inaccessible");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    return MAELYS_GIT_OK;
}
