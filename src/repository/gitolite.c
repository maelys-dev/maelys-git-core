#include "internal.h"

#include "common/maelys_sha256.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MG_GITOLITE_MAX_CURRENT_REPOSITORIES 64u

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} text_buffer_t;

static int append_text(text_buffer_t *buffer, const char *format, ...) {
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int required = vsnprintf(NULL, 0u, format, copy);
    va_end(copy);
    if (required < 0) { va_end(args); return 0; }
    size_t wanted = buffer->length + (size_t)required + 1u;
    if (wanted > buffer->capacity) {
        size_t next = buffer->capacity ? buffer->capacity : 4096u;
        while (next < wanted) {
            if (next > SIZE_MAX / 2u) { va_end(args); return 0; }
            next *= 2u;
        }
        char *grown = realloc(buffer->data, next);
        if (!grown) { va_end(args); return 0; }
        buffer->data = grown;
        buffer->capacity = next;
    }
    (void)vsnprintf(buffer->data + buffer->length,
                    buffer->capacity - buffer->length, format, args);
    va_end(args);
    buffer->length += (size_t)required;
    return 1;
}

static char *trim(char *value) {
    while (isspace((unsigned char)*value)) ++value;
    char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    return value;
}

static int safe_atom(const char *value) {
    if (!value || !*value) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-')) return 0;
    return 1;
}

static int normalize_repository(const char *input, char output[512]) {
    if (!input || !*input || strchr(input, '*') || strchr(input, '?') ||
        strchr(input, '[') || strchr(input, ']') || strchr(input, '^') ||
        strchr(input, '$') || strchr(input, '(') || strchr(input, ')') ||
        strchr(input, '|') || strchr(input, '+')) return 0;
    size_t length = strlen(input);
    int has_suffix = length >= 4u && strcmp(input + length - 4u, ".git") == 0;
    int written = snprintf(output, 512u, "%s%s", input, has_suffix ? "" : ".git");
    return written > 0 && written < 512 && maelys_git_repository_name_is_valid(output);
}

static int add_unsupported(maelys_git_gitolite_migration_result_t *result,
                           size_t line_number,
                           const char *reason,
                           const char *source) {
    if (result->unsupported_count >= 1024u) return 0;
    char message[4608];
    int length = snprintf(message, sizeof(message), "line %zu: %s: %s",
                          line_number, reason, source);
    if (length < 0 || (size_t)length >= sizeof(message)) return 0;
    char **grown = realloc(result->unsupported,
                           (result->unsupported_count + 1u) * sizeof(*grown));
    if (!grown) return 0;
    result->unsupported = grown;
    grown[result->unsupported_count] = strdup(message);
    if (!grown[result->unsupported_count]) return 0;
    ++result->unsupported_count;
    return 1;
}

void maelys_git_gitolite_migration_result_clear(
    maelys_git_gitolite_migration_result_t *result) {
    if (!result) return;
    for (size_t i = 0u; i < result->unsupported_count; ++i)
        free(result->unsupported[i]);
    free(result->unsupported);
    memset(result, 0, sizeof(*result));
}

static int append_direct_grant(text_buffer_t *policy,
                               const char *right,
                               const char *subject,
                               const char *repository) {
    const char *prefix = subject[0] == '@' ? "group_" : "";
    const char *name = subject[0] == '@' ? subject + 1u : subject;
    if (!safe_atom(name)) return 0;
    if (!strcmp(right, "R"))
        return append_text(policy, "%sgrant_read(\"%s\", \"%s\").\n",
                           prefix, name, repository);
    if (!strcmp(right, "RW") || !strcmp(right, "RW+")) {
        if (!append_text(policy, "%sgrant_read(\"%s\", \"%s\").\n",
                         prefix, name, repository) ||
            !append_text(policy, "%sgrant_write(\"%s\", \"%s\").\n",
                         prefix, name, repository) ||
            !append_text(policy, "%sgrant_push(\"%s\", \"%s\").\n",
                         prefix, name, repository)) return 0;
        if (!strcmp(right, "RW+"))
            return append_text(policy, "%sgrant_force(\"%s\", \"%s\").\n",
                               prefix, name, repository);
        return 1;
    }
    return 0;
}

static int append_authorization_rules(text_buffer_t *policy) {
    return append_text(policy,
        "\nallow(R) :- request(R), user(U), repository(P), operation(\"read\"), grant_read(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), grant_write(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"create\"), grant_push(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"fast_forward\"), grant_push(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"force\"), grant_force(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"delete\"), grant_force(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), grant_push(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), grant_force(U, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"read\"), group_member(U, G), group_grant_read(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"write\"), group_member(U, G), group_grant_write(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"create\"), group_member(U, G), group_grant_push(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"fast_forward\"), group_member(U, G), group_grant_push(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"force\"), group_member(U, G), group_grant_force(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"push\"), update_kind(\"delete\"), group_member(U, G), group_grant_force(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"merge\"), group_member(U, G), group_grant_push(G, P).\n"
        "allow(R) :- request(R), user(U), repository(P), operation(\"update-ref\"), group_member(U, G), group_grant_force(G, P).\n");
}

static maelys_git_result_t parse_gitolite(FILE *input,
                                          text_buffer_t *policy,
                                          maelys_git_gitolite_migration_result_t *migration,
                                          maelys_git_error_t *error) {
    char line[4096];
    char repositories[MG_GITOLITE_MAX_CURRENT_REPOSITORIES][512];
    size_t repository_count = 0u, line_number = 0u;
    while (fgets(line, sizeof(line), input)) {
        ++line_number;
        size_t raw_length = strlen(line);
        if (raw_length && line[raw_length - 1u] != '\n' && !feof(input)) {
            mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                         "Gitolite line %zu exceeds 4095 bytes", line_number);
            return MAELYS_GIT_ERR_LIMIT;
        }
        while (raw_length && (line[raw_length - 1u] == '\n' ||
                              line[raw_length - 1u] == '\r'))
            line[--raw_length] = '\0';
        char original[4096];
        (void)mg_copy_string(original, sizeof(original), line);
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';
        char *content = trim(line);
        if (!*content || !strncmp(content, "include ", 8u) ||
            !strncmp(content, "subconf ", 8u)) {
            if (*content && !add_unsupported(migration, line_number,
                                             "include/subconf requires manual expansion", original))
                return MAELYS_GIT_ERR_IO;
            continue;
        }
        if (content[0] == '@') {
            char *equals = strchr(content, '=');
            if (!equals) {
                if (!add_unsupported(migration, line_number, "invalid group definition", original))
                    return MAELYS_GIT_ERR_IO;
                continue;
            }
            *equals = '\0';
            char *group = trim(content) + 1u;
            char *members = trim(equals + 1u);
            if (!safe_atom(group)) {
                if (!add_unsupported(migration, line_number, "unsupported group name", original))
                    return MAELYS_GIT_ERR_IO;
                continue;
            }
            int supported = 1;
            char *save = NULL;
            for (char *member = strtok_r(members, " \t", &save);
                 member; member = strtok_r(NULL, " \t", &save)) {
                if (member[0] == '@' || !safe_atom(member)) { supported = 0; break; }
                if (!append_text(policy, "group_member(\"%s\", \"%s\").\n",
                                 member, group)) return MAELYS_GIT_ERR_IO;
            }
            if (!supported) {
                if (!add_unsupported(migration, line_number,
                                     "nested or unsafe group member", original))
                    return MAELYS_GIT_ERR_IO;
            } else {
                ++migration->group_count;
            }
            continue;
        }
        if (!strncmp(content, "repo", 4u) && isspace((unsigned char)content[4])) {
            repository_count = 0u;
            char *save = NULL;
            for (char *repository = strtok_r(trim(content + 4u), " \t", &save);
                 repository; repository = strtok_r(NULL, " \t", &save)) {
                if (repository_count >= MG_GITOLITE_MAX_CURRENT_REPOSITORIES ||
                    !normalize_repository(repository, repositories[repository_count])) {
                    repository_count = 0u;
                    if (!add_unsupported(migration, line_number,
                                         "repository pattern is not an exact safe name", original))
                        return MAELYS_GIT_ERR_IO;
                    break;
                }
                ++repository_count;
                ++migration->repository_count;
            }
            continue;
        }
        char *equals = strchr(content, '=');
        if (!equals || repository_count == 0u) {
            if (!add_unsupported(migration, line_number,
                                 "rule is outside an exact repository block", original))
                return MAELYS_GIT_ERR_IO;
            continue;
        }
        *equals = '\0';
        char *right = trim(content);
        char *subjects = trim(equals + 1u);
        if (strpbrk(right, " \t") ||
            (strcmp(right, "R") && strcmp(right, "RW") && strcmp(right, "RW+"))) {
            if (!add_unsupported(migration, line_number,
                                 "ref/VREF, negative, or unknown permission", original))
                return MAELYS_GIT_ERR_IO;
            continue;
        }
        int supported = *subjects != '\0';
        char subjects_copy[4096];
        (void)mg_copy_string(subjects_copy, sizeof(subjects_copy), subjects);
        char *save = NULL;
        for (char *subject = strtok_r(subjects_copy, " \t,", &save);
             supported && subject; subject = strtok_r(NULL, " \t,", &save)) {
            const char *name = subject[0] == '@' ? subject + 1u : subject;
            if (!safe_atom(name)) supported = 0;
        }
        if (!supported) {
            if (!add_unsupported(migration, line_number,
                                 "empty or unsafe rule subject", original))
                return MAELYS_GIT_ERR_IO;
            continue;
        }
        save = NULL;
        for (char *subject = strtok_r(subjects, " \t,", &save);
             subject; subject = strtok_r(NULL, " \t,", &save)) {
            for (size_t i = 0u; i < repository_count; ++i)
                if (!append_direct_grant(policy, right, subject, repositories[i]))
                    return MAELYS_GIT_ERR_IO;
        }
        ++migration->rule_count;
    }
    if (ferror(input)) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot read Gitolite configuration");
        return MAELYS_GIT_ERR_IO;
    }
    return append_authorization_rules(policy) ? MAELYS_GIT_OK : MAELYS_GIT_ERR_IO;
}

static maelys_git_result_t write_file(const char *path,
                                      const char *data,
                                      size_t length,
                                      maelys_git_error_t *error) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot create %s: %s", path, strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    size_t offset = 0u;
    while (offset < length) {
        ssize_t written = write(fd, data + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            int saved = errno;
            close(fd);
            mg_error_set(error, MAELYS_GIT_ERR_IO, saved,
                         "cannot write %s: %s", path, strerror(saved));
            return MAELYS_GIT_ERR_IO;
        }
        offset += (size_t)written;
    }
    if (fsync(fd) != 0) {
        int saved = errno;
        close(fd);
        mg_error_set(error, MAELYS_GIT_ERR_IO, saved,
                     "cannot persist %s: %s", path, strerror(saved));
        return MAELYS_GIT_ERR_IO;
    }
    if (close(fd) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot close %s: %s", path, strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_migrate_gitolite(
    const char *input_path,
    const char *output_directory,
    int apply,
    maelys_git_gitolite_migration_result_t *out_result,
    maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!input_path || !*input_path || !output_directory || !*output_directory || !out_result)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_result, 0, sizeof(*out_result));
    struct stat existing;
    if (lstat(output_directory, &existing) == 0 || errno != ENOENT) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "migration output must not already exist: %s", output_directory);
        return MAELYS_GIT_ERR_IO;
    }
    FILE *input = fopen(input_path, "rb");
    if (!input) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot read Gitolite configuration: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    text_buffer_t policy = {0};
    maelys_git_result_t result = parse_gitolite(input, &policy, out_result, error);
    fclose(input);
    if (result != MAELYS_GIT_OK) {
        free(policy.data);
        maelys_git_gitolite_migration_result_clear(out_result);
        if (!error->message[0]) mg_error_set(error, result, errno, "cannot compile Gitolite policy");
        return result;
    }
    if (!apply) { free(policy.data); return MAELYS_GIT_OK; }
    if (out_result->unsupported_count) {
        free(policy.data);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "migration has %zu unsupported entries; apply is refused",
                     out_result->unsupported_count);
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    char policy_sha[65];
    if (maelys_sha256_hex((const unsigned char *)policy.data, policy.length, policy_sha) != 0) {
        free(policy.data);
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0,
                     "cannot hash generated Gitolite policy");
        return MAELYS_GIT_ERR_IO;
    }
    text_buffer_t manifest = {0};
    if (!append_text(&manifest,
        "{\n  \"policy_set_id\": \"maelys-git.gitolite-migration\",\n"
        "  \"policy_set_version\": \"1\",\n  \"manifest_version\": \"1\",\n"
        "  \"default_profile\": \"enforce\",\n  \"created_for\": \"maelys-git-core\",\n"
        "  \"strict_loading\": true,\n  \"fail_closed\": true,\n  \"capabilities\": [],\n"
        "  \"policies\": [{\n    \"policy_id\": \"maelys-git.gitolite.authorization\",\n"
        "    \"domain\": \"maelys_git\",\n    \"file\": \"gitolite-migrated.dl\",\n"
        "    \"sha256\": \"%s\",\n    \"mode\": \"enforce\",\n"
        "    \"enabled\": true,\n    \"description\": \"Safely migrated Gitolite ACL subset\",\n"
        "    \"queries\": [{\"name\":\"allow\",\"arity\":1},{\"name\":\"deny\",\"arity\":1}]\n"
        "  }]\n}\n", policy_sha)) {
        free(policy.data);
        return MAELYS_GIT_ERR_IO;
    }
    char temporary[PATH_MAX];
    int length = snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX", output_directory);
    int temporary_fd = length >= 0 && (size_t)length < sizeof(temporary) ?
        mkstemp(temporary) : -1;
    if (temporary_fd < 0 || close(temporary_fd) != 0 ||
        unlink(temporary) != 0 || mkdir(temporary, 0700) != 0) {
        free(policy.data); free(manifest.data);
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot create migration transaction");
        return MAELYS_GIT_ERR_IO;
    }
    char policy_path[PATH_MAX], manifest_path[PATH_MAX];
    int p = snprintf(policy_path, sizeof(policy_path), "%s/gitolite-migrated.dl", temporary);
    int m = snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", temporary);
    if (p < 0 || m < 0 || (size_t)p >= sizeof(policy_path) || (size_t)m >= sizeof(manifest_path))
        result = MAELYS_GIT_ERR_LIMIT;
    if (result == MAELYS_GIT_OK)
        result = write_file(policy_path, policy.data, policy.length, error);
    if (result == MAELYS_GIT_OK)
        result = write_file(manifest_path, manifest.data, manifest.length, error);
    if (result == MAELYS_GIT_OK && rename(temporary, output_directory) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot publish migration output: %s", strerror(errno));
        result = MAELYS_GIT_ERR_IO;
    }
    if (result != MAELYS_GIT_OK) (void)mg_remove_tree(temporary);
    free(policy.data); free(manifest.data);
    return result;
}
