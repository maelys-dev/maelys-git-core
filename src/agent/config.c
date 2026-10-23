#include "agent_internal.h"

#include <maelys/json.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef enum {
    FILE_TRUST_CONFIG,  /* owned by the agent or root, not writable by others */
    FILE_TRUST_SECRET,  /* owned by the agent, no group or world permissions */
    FILE_TRUST_SYSTEM   /* trusted input that may be reached through a symlink */
} file_trust_t;

static int file_status_secure(const struct stat *status, file_trust_t kind) {
    mode_t forbidden = kind == FILE_TRUST_SECRET ? 077u : 022u;
    int owner_ok = kind == FILE_TRUST_SECRET ? status->st_uid == geteuid() :
                   (status->st_uid == geteuid() || status->st_uid == 0u);
    return S_ISREG(status->st_mode) && owner_ok &&
           (status->st_mode & forbidden) == 0;
}

static int secure_regular_file(const char *path, file_trust_t kind, maelys_git_error_t *error) {
    struct stat status;
    if ((kind == FILE_TRUST_SYSTEM ? stat(path, &status) : lstat(path, &status)) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_NOT_FOUND, errno,
                     "cannot inspect %s: %s", path, strerror(errno));
        return 0;
    }
    if (!file_status_secure(&status, kind)) {
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0,
                     "%s must be a regular file owned by the agent%s",
                     path, kind == FILE_TRUST_SECRET ? " with no group/world permissions" :
                                       " and not group/world-writable");
        return 0;
    }
    return 1;
}

static int copy_config_string(const maelys_json_document_t *document,
                            maelys_json_value_t root,
                            const char *name,
                            char *out,
                            size_t capacity) {
    maelys_json_view_t value;
    if (maelys_json_object_get_string(document, root, name, &value) != MAELYS_JSON_OK ||
        value.size == 0u || value.size >= capacity) return 0;
    memcpy(out, value.data, value.size);
    out[value.size] = '\0';
    return 1;
}

static maelys_git_result_t read_config_document(const char *path,
                                               maelys_json_document_t **out,
                                               maelys_git_error_t *error) {
    /* O_NONBLOCK lets fstat reject a FIFO without waiting for a writer.
     * Never reopen the path after inspecting this descriptor. */
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        int saved = errno;
        maelys_git_result_t result = saved == ENOENT || saved == ENOTDIR ?
            MAELYS_GIT_ERR_NOT_FOUND :
            saved == ELOOP || saved == EACCES || saved == EPERM ?
            MAELYS_GIT_ERR_DENIED : MAELYS_GIT_ERR_IO;
        mg_error_set(error, result, saved, "cannot open config: %s", strerror(saved));
        return result;
    }
    maelys_git_result_t result = MAELYS_GIT_OK;
    char *bytes = NULL;
    struct stat status;
    if (fstat(fd, &status) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot inspect opened config");
        result = MAELYS_GIT_ERR_IO;
        goto done;
    }
    if (!file_status_secure(&status, FILE_TRUST_CONFIG)) {
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0,
                     "opened config must be a regular file owned by the agent or root"
                     " and not group/world-writable");
        result = MAELYS_GIT_ERR_DENIED;
        goto done;
    }
    if (status.st_size > (off_t)MG_CONFIG_MAX_BYTES) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "config exceeds 64 KiB");
        result = MAELYS_GIT_ERR_LIMIT;
        goto done;
    }
    /* One extra byte also detects growth after fstat. */
    bytes = malloc(MG_CONFIG_MAX_BYTES + 1u);
    if (!bytes) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, ENOMEM, "cannot allocate config buffer");
        result = MAELYS_GIT_ERR_IO;
        goto done;
    }
    size_t size = 0u;
    while (size < MG_CONFIG_MAX_BYTES + 1u) {
        ssize_t count = read(fd, bytes + size, MG_CONFIG_MAX_BYTES + 1u - size);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot read config");
            result = MAELYS_GIT_ERR_IO;
            goto done;
        }
        if (count == 0) break;
        size += (size_t)count;
    }
    if (size > MG_CONFIG_MAX_BYTES) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "config exceeds 64 KiB");
        result = MAELYS_GIT_ERR_LIMIT;
        goto done;
    }
    const maelys_json_limits_t limits = {
        .maximum_bytes = MG_CONFIG_MAX_BYTES,
        .maximum_depth = MG_CONFIG_MAX_DEPTH,
        .maximum_tokens = MG_CONFIG_MAX_TOKENS
    };
    maelys_json_error_t json_error;
    maelys_json_result_t parsed = maelys_json_document_parse(
        bytes, size, MAELYS_JSON_PROFILE_RFC8259, &limits, out, &json_error);
    if (parsed != MAELYS_JSON_OK) {
        char diagnostic[192];
        (void)maelys_json_error_format(&json_error, diagnostic, sizeof(diagnostic));
        result = parsed == MAELYS_JSON_ERR_LIMIT ? MAELYS_GIT_ERR_LIMIT :
                 parsed == MAELYS_JSON_ERR_MEMORY ? MAELYS_GIT_ERR_IO : MAELYS_GIT_ERR_PROTOCOL;
        mg_error_set(error, result, parsed == MAELYS_JSON_ERR_MEMORY ? ENOMEM : 0,
                     "invalid config: %s", diagnostic);
    }
done:
    free(bytes);
    if (close(fd) != 0 && result == MAELYS_GIT_OK) {
        int saved = errno;
        maelys_json_document_release(*out);
        *out = NULL;
        mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "cannot close config");
        result = MAELYS_GIT_ERR_IO;
    }
    return result;
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
    if (!path || !out) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out = NULL;
    maelys_json_document_t *document = NULL;
    maelys_git_result_t result = read_config_document(path, &document, error);
    if (result != MAELYS_GIT_OK) return result;
    maelys_git_agent_config_t *config = calloc(1u, sizeof(*config));
    if (!config) {
        maelys_json_document_release(document);
        mg_error_set(error, MAELYS_GIT_ERR_IO, ENOMEM, "cannot allocate config");
        return MAELYS_GIT_ERR_IO;
    }
    maelys_json_value_t root = maelys_json_document_root(document);
    size_t fields = 0u;
    uint64_t version = 0u;
    /* Unique keys, exactly 14 members (15 with grants_path, the optional
     * one) and all required getters together reject both missing and
     * unknown fields without a second key catalog. */
    maelys_json_value_t grants = 0;
    int has_grants = maelys_json_object_get(document, root, "grants_path", &grants) == MAELYS_JSON_OK;
    int valid = maelys_json_object_size(document, root, &fields) == MAELYS_JSON_OK &&
                fields == MG_CONFIG_FIELD_COUNT + (has_grants ? 1u : 0u) &&
                (!has_grants || (copy_config_string(document, root, "grants_path", config->grants_path,
                                                    sizeof(config->grants_path)) &&
                                 absolute_path(config->grants_path))) &&
                maelys_json_object_get_u64(document, root, "version", &version) == MAELYS_JSON_OK &&
                version == 1u &&
                copy_config_string(document, root, "agent_id", config->agent_id, sizeof(config->agent_id)) &&
                copy_config_string(document, root, "authority", config->authority, sizeof(config->authority)) &&
                copy_config_string(document, root, "ca_file", config->ca_file, sizeof(config->ca_file)) &&
                copy_config_string(document, root, "token_file", config->token_file, sizeof(config->token_file)) &&
                copy_config_string(document, root, "database_path", config->database_path, sizeof(config->database_path)) &&
                copy_config_string(document, root, "manifest_path", config->manifest_path, sizeof(config->manifest_path)) &&
                copy_config_string(document, root, "repository_root", config->repository_root, sizeof(config->repository_root)) &&
                copy_config_string(document, root, "git_executable", config->git_executable, sizeof(config->git_executable)) &&
                copy_config_string(document, root, "executor_path", config->executor_path, sizeof(config->executor_path)) &&
                copy_config_string(document, root, "command_target", config->command_target, sizeof(config->command_target)) &&
                copy_config_string(document, root, "event_target", config->event_target, sizeof(config->event_target)) &&
                maelys_json_object_get_u64(document, root, "poll_timeout_ms", &config->poll_timeout_ms) == MAELYS_JSON_OK &&
                maelys_json_object_get_u64(document, root, "request_timeout_ms", &config->request_timeout_ms) == MAELYS_JSON_OK;
    if (valid) {
        valid = identifier_valid(config->agent_id) && authority_valid(config->authority) &&
                absolute_path(config->ca_file) &&
                absolute_path(config->token_file) && absolute_path(config->database_path) &&
                absolute_path(config->manifest_path) && absolute_path(config->repository_root) &&
                absolute_path(config->git_executable) && absolute_path(config->executor_path) &&
                target_valid(config->command_target) && target_valid(config->event_target) &&
                config->poll_timeout_ms >= 1000u && config->poll_timeout_ms <= 120000u &&
                config->request_timeout_ms >= 1000u && config->request_timeout_ms <= 120000u;
    }
    maelys_json_document_release(document);
    if (!valid) {
        free(config);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "configuration does not match version 1 schema");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    if (!secure_regular_file(config->token_file, FILE_TRUST_SECRET, error) ||
        !secure_regular_file(config->ca_file, FILE_TRUST_SYSTEM, error) ||
        !secure_regular_file(config->manifest_path, FILE_TRUST_SYSTEM, error) ||
        (config->grants_path[0] && !secure_regular_file(config->grants_path, FILE_TRUST_SYSTEM, error))) {
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
    if (!secure_regular_file(path, FILE_TRUST_SECRET, error)) return error ? error->code : MAELYS_GIT_ERR_DENIED;
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

    /* The flat object mg_config_load reads back: 14 members, indented. */
    mg_json_t json;
    mg_json_begin(&json, MG_JSON_CONFIGURATION);
    mg_json_object(&json, NULL);
    mg_json_i64(&json, "version", 1);
    mg_json_string(&json, "agent_id", agent_id);
    mg_json_string(&json, "authority", authority);
    mg_json_string(&json, "ca_file", ca_file);
    mg_json_string(&json, "token_file", token_file);
    mg_json_string(&json, "database_path", database_path);
    mg_json_string(&json, "manifest_path", manifest_path);
    mg_json_string(&json, "repository_root", repository_root);
    mg_json_string(&json, "git_executable", "/usr/bin/git");
    mg_json_string(&json, "executor_path", executor_path);
    mg_json_string(&json, "command_target", "/v1/agent/commands");
    mg_json_string(&json, "event_target", "/v1/agent/events");
    mg_json_i64(&json, "poll_timeout_ms", 30000);
    mg_json_i64(&json, "request_timeout_ms", 30000);
    mg_json_end_object(&json);
    char *text = NULL;
    size_t size = 0u;
    if (mg_json_finish(&json, &text, &size) != MAELYS_JSON_OK) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "cannot encode config");
        return MAELYS_GIT_ERR_IO;
    }
    int fd = open(config_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        free(text);
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot create config: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    FILE *stream = fdopen(fd, "w");
    int failed = !stream || fwrite(text, 1u, size, stream) != size ||
                 fputc('\n', stream) == EOF || fflush(stream) != 0 || fsync(fd) != 0;
    if (stream) (void)fclose(stream); else (void)close(fd);
    free(text);
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
    if (!secure_regular_file(token_file, FILE_TRUST_SECRET, error)) return error ? error->code : MAELYS_GIT_ERR_DENIED;
    if (!secure_regular_file(ca_file, FILE_TRUST_SYSTEM, error) || !secure_regular_file(manifest_path, FILE_TRUST_SYSTEM, error))
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
