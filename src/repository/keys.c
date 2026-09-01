#include "internal.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    char *principal;
    char *key;
} key_entry_t;

static void free_entries(key_entry_t *entries, size_t count) {
    for (size_t i = 0u; i < count; ++i) {
        free(entries[i].principal);
        free(entries[i].key);
    }
    free(entries);
}

static int compare_entries(const void *left, const void *right) {
    const key_entry_t *a = left;
    const key_entry_t *b = right;
    int principal = strcmp(a->principal, b->principal);
    return principal ? principal : strcmp(a->key, b->key);
}

static int safe_word(const char *value) {
    if (!value || !*value) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-')) return 0;
    return 1;
}

static int safe_quoted_value(const char *value) {
    if (!value || value[0] != '/') return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (!(isalnum(*p) || *p == '/' || *p == '.' || *p == '_' || *p == '-')) return 0;
    return 1;
}

static int supported_key(const char *line) {
    static const char *prefixes[] = {
        "ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-nistp256 ",
        "ecdsa-sha2-nistp384 ", "ecdsa-sha2-nistp521 ",
        "sk-ssh-ed25519@openssh.com ", "sk-ecdsa-sha2-nistp256@openssh.com "};
    for (size_t i = 0u; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i)
        if (strncmp(line, prefixes[i], strlen(prefixes[i])) == 0) return 1;
    return 0;
}

static char *read_key(const char *path, maelys_git_error_t *error) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot read key %s: %s", path, strerror(errno));
        return NULL;
    }
    char buffer[16385];
    size_t length = fread(buffer, 1u, sizeof(buffer) - 1u, file);
    int failed = ferror(file);
    int overflow = !feof(file);
    fclose(file);
    if (failed || overflow) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "SSH key file is too large: %s", path);
        return NULL;
    }
    buffer[length] = '\0';
    while (length && (buffer[length - 1u] == '\n' || buffer[length - 1u] == '\r'))
        buffer[--length] = '\0';
    if (!length || strchr(buffer, '\n') || strchr(buffer, '\r') || !supported_key(buffer)) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid SSH public key: %s", path);
        return NULL;
    }
    return strdup(buffer);
}

static maelys_git_result_t load_entries(const char *directory,
                                        key_entry_t **out_entries,
                                        size_t *out_count,
                                        maelys_git_error_t *error) {
    DIR *dir = opendir(directory);
    if (!dir) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot open key directory: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    key_entry_t *entries = NULL;
    size_t count = 0u, capacity = 0u;
    struct dirent *entry;
    maelys_git_result_t result = MAELYS_GIT_OK;
    while ((entry = readdir(dir)) != NULL) {
        size_t length = strlen(entry->d_name);
        if (length <= 4u || strcmp(entry->d_name + length - 4u, ".pub") != 0) continue;
        char principal[NAME_MAX + 1u];
        if (length - 4u >= sizeof(principal)) { result = MAELYS_GIT_ERR_LIMIT; break; }
        memcpy(principal, entry->d_name, length - 4u);
        principal[length - 4u] = '\0';
        if (!safe_word(principal)) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "unsafe SSH key filename: %s", entry->d_name);
            result = MAELYS_GIT_ERR_PROTOCOL;
            break;
        }
        char path[PATH_MAX];
        int written = snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        if (written < 0 || (size_t)written >= sizeof(path)) { result = MAELYS_GIT_ERR_LIMIT; break; }
        struct stat status;
        if (lstat(path, &status) != 0 || !S_ISREG(status.st_mode)) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, errno, "SSH key must be a regular file: %s", path);
            result = MAELYS_GIT_ERR_PROTOCOL;
            break;
        }
        char *key = read_key(path, error);
        if (!key) { result = error->code; break; }
        if (count == capacity) {
            size_t next = capacity ? capacity * 2u : 16u;
            key_entry_t *grown = realloc(entries, next * sizeof(*grown));
            if (!grown) { free(key); result = MAELYS_GIT_ERR_IO; break; }
            entries = grown;
            capacity = next;
        }
        entries[count].principal = strdup(principal);
        entries[count].key = key;
        if (!entries[count].principal) { free(key); result = MAELYS_GIT_ERR_IO; break; }
        ++count;
    }
    closedir(dir);
    if (result != MAELYS_GIT_OK) { free_entries(entries, count); return result; }
    qsort(entries, count, sizeof(*entries), compare_entries);
    *out_entries = entries;
    *out_count = count;
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_compile_authorized_keys(
    const char *key_directory,
    const char *output_path,
    const char *shell_path,
    const char *repository_root,
    const char *manifest_path,
    int apply,
    size_t *out_key_count,
    maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!key_directory || !output_path || !safe_quoted_value(shell_path) ||
        !safe_quoted_value(repository_root) || !safe_quoted_value(manifest_path) || !out_key_count)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    key_entry_t *entries = NULL;
    size_t count = 0u;
    maelys_git_result_t result = load_entries(key_directory, &entries, &count, error);
    if (result != MAELYS_GIT_OK) return result;
    *out_key_count = count;
    if (!apply) { free_entries(entries, count); return MAELYS_GIT_OK; }

    char temporary[PATH_MAX];
    int written = snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX", output_path);
    if (written < 0 || (size_t)written >= sizeof(temporary)) {
        free_entries(entries, count);
        return MAELYS_GIT_ERR_LIMIT;
    }
    int descriptor = mkstemp(temporary);
    if (descriptor < 0) {
        free_entries(entries, count);
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot create authorized_keys transaction: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    FILE *output = fdopen(descriptor, "w");
    if (!output) { close(descriptor); unlink(temporary); free_entries(entries, count); return MAELYS_GIT_ERR_IO; }
    for (size_t i = 0u; i < count; ++i) {
        if (fprintf(output,
                    "restrict,command=\"%s serve --user %s --root %s --manifest %s\" %s\n",
                    shell_path, entries[i].principal, repository_root, manifest_path,
                    entries[i].key) < 0) {
            result = MAELYS_GIT_ERR_IO;
            break;
        }
    }
    if (result == MAELYS_GIT_OK && fflush(output) != 0) result = MAELYS_GIT_ERR_IO;
    if (result == MAELYS_GIT_OK && fchmod(descriptor, 0600) != 0) result = MAELYS_GIT_ERR_IO;
    if (result == MAELYS_GIT_OK && fsync(descriptor) != 0) result = MAELYS_GIT_ERR_IO;
    if (fclose(output) != 0 && result == MAELYS_GIT_OK) result = MAELYS_GIT_ERR_IO;
    if (result == MAELYS_GIT_OK && rename(temporary, output_path) != 0) result = MAELYS_GIT_ERR_IO;
    if (result != MAELYS_GIT_OK) {
        unlink(temporary);
        mg_error_set(error, result, errno, "authorized_keys update failed: %s", strerror(errno));
    }
    free_entries(entries, count);
    return result;
}
