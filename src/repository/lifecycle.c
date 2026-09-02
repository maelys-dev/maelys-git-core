#include "internal.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MG_MAX_REPOSITORY_ENTRIES 10000u

const char *maelys_git_repository_state_name(maelys_git_repository_state_t state) {
    switch (state) {
        case MAELYS_GIT_REPOSITORY_ACTIVE: return "active";
        case MAELYS_GIT_REPOSITORY_ARCHIVE: return "archive";
        case MAELYS_GIT_REPOSITORY_TRASH: return "trash";
        default: return "unknown";
    }
}

int maelys_git_lifecycle_id_is_valid(const char *identifier) {
    if (!identifier || !*identifier || strlen(identifier) >= MAELYS_GIT_MAX_LIFECYCLE_ID)
        return 0;
    if (!strcmp(identifier, ".") || !strcmp(identifier, "..")) return 0;
    for (const unsigned char *p = (const unsigned char *)identifier; *p; ++p)
        if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-')) return 0;
    return 1;
}

static int bare_layout(const char *path) {
    char head[PATH_MAX], objects[PATH_MAX], refs[PATH_MAX];
    int hlen = snprintf(head, sizeof(head), "%s/HEAD", path);
    int olen = snprintf(objects, sizeof(objects), "%s/objects", path);
    int rlen = snprintf(refs, sizeof(refs), "%s/refs", path);
    if (hlen < 0 || olen < 0 || rlen < 0 || (size_t)hlen >= sizeof(head) ||
        (size_t)olen >= sizeof(objects) || (size_t)rlen >= sizeof(refs)) return 0;
    struct stat h, o, r;
    return lstat(head, &h) == 0 && S_ISREG(h.st_mode) &&
           lstat(objects, &o) == 0 && S_ISDIR(o.st_mode) && !S_ISLNK(o.st_mode) &&
           lstat(refs, &r) == 0 && S_ISDIR(r.st_mode) && !S_ISLNK(r.st_mode);
}

static maelys_git_result_t active_path(const char *root,
                                       const char *repository,
                                       char out[PATH_MAX],
                                       struct stat *out_status,
                                       maelys_git_error_t *error) {
    if (!maelys_git_repository_name_is_valid(repository)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, 0,
                     "invalid or reserved repository name");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    int written = snprintf(out, PATH_MAX, "%s/%s", root, repository);
    if (written < 0 || written >= PATH_MAX) return MAELYS_GIT_ERR_LIMIT;
    struct stat status;
    if (lstat(out, &status) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_NOT_FOUND, errno,
                     "repository does not exist: %s", repository);
        return MAELYS_GIT_ERR_NOT_FOUND;
    }
    if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode) || !bare_layout(out)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, 0,
                     "repository is not a direct bare Git directory");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    char resolved[PATH_MAX];
    if (!realpath(out, resolved) || strcmp(resolved, out) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, errno,
                     "repository path contains a symbolic link");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    if (out_status) *out_status = status;
    return MAELYS_GIT_OK;
}

static maelys_git_result_t require_identity(const char *expected,
                                            const char *actual,
                                            int apply,
                                            maelys_git_error_t *error) {
    if (!apply) return MAELYS_GIT_OK;
    if (!expected || !*expected) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0,
                     "apply requires the source identity returned by plan");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    if (strcmp(expected, actual) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "repository identity changed; run a new lifecycle plan");
        return MAELYS_GIT_ERR_PROCESS;
    }
    return MAELYS_GIT_OK;
}

static maelys_git_result_t require_absent(const char *path,
                                          maelys_git_error_t *error) {
    struct stat status;
    if (lstat(path, &status) == 0 || errno != ENOENT) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, errno,
                     "lifecycle target already exists or is inaccessible");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    return MAELYS_GIT_OK;
}

static maelys_git_result_t require_safe_directory(const char *path,
                                                  maelys_git_error_t *error) {
    struct stat status;
    if (lstat(path, &status) != 0 || !S_ISDIR(status.st_mode) ||
        S_ISLNK(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 0022u)) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "lifecycle directory is missing or unsafe: %s", path);
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}

static maelys_git_result_t ensure_directory(const char *path,
                                            mode_t mode,
                                            maelys_git_error_t *error) {
    struct stat status;
    if (lstat(path, &status) == 0) return require_safe_directory(path, error);
    if (errno != ENOENT || mkdir(path, mode) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot create lifecycle directory %s: %s", path, strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}

static void prune_empty_parents(const char *root, const char *source) {
    char path[PATH_MAX];
    if (!mg_copy_string(path, sizeof(path), source)) return;
    char *slash = strrchr(path, '/');
    while (slash && (size_t)(slash - path) > strlen(root)) {
        *slash = '\0';
        if (rmdir(path) != 0) break;
        slash = strrchr(path, '/');
    }
}

static int compare_entries(const void *left, const void *right) {
    const maelys_git_repository_entry_t *a = left;
    const maelys_git_repository_entry_t *b = right;
    if (a->state != b->state) return a->state < b->state ? -1 : 1;
    int repository = strcmp(a->repository, b->repository);
    return repository ? repository : strcmp(a->storage_id, b->storage_id);
}

static maelys_git_result_t add_entry(maelys_git_repository_list_t *list,
                                     size_t *capacity,
                                     const char *repository,
                                     maelys_git_repository_state_t state,
                                     const char *storage_id,
                                     maelys_git_error_t *error) {
    if (list->count >= MG_MAX_REPOSITORY_ENTRIES) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                     "repository inventory exceeds %u entries", MG_MAX_REPOSITORY_ENTRIES);
        return MAELYS_GIT_ERR_LIMIT;
    }
    if (list->count == *capacity) {
        size_t next = *capacity ? *capacity * 2u : 32u;
        maelys_git_repository_entry_t *grown = realloc(list->entries, next * sizeof(*grown));
        if (!grown) return MAELYS_GIT_ERR_IO;
        list->entries = grown;
        *capacity = next;
    }
    maelys_git_repository_entry_t *entry = &list->entries[list->count];
    memset(entry, 0, sizeof(*entry));
    if (!mg_copy_string(entry->repository, sizeof(entry->repository), repository) ||
        (storage_id && !mg_copy_string(entry->storage_id, sizeof(entry->storage_id), storage_id)))
        return MAELYS_GIT_ERR_LIMIT;
    entry->state = state;
    ++list->count;
    return MAELYS_GIT_OK;
}

static maelys_git_result_t scan_active(const char *root,
                                       const char *relative,
                                       maelys_git_repository_list_t *list,
                                       size_t *capacity,
                                       maelys_git_error_t *error) {
    char directory_path[PATH_MAX];
    int written = relative[0] ? snprintf(directory_path, sizeof(directory_path), "%s/%s", root, relative) :
                                snprintf(directory_path, sizeof(directory_path), "%s", root);
    if (written < 0 || (size_t)written >= sizeof(directory_path)) return MAELYS_GIT_ERR_LIMIT;
    DIR *directory = opendir(directory_path);
    if (!directory) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot read repository inventory: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    maelys_git_result_t result = MAELYS_GIT_OK;
    struct dirent *item;
    while ((item = readdir(directory)) != NULL) {
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..") ||
            (!relative[0] && !strcmp(item->d_name, ".maelys-git"))) continue;
        char child_relative[MAELYS_GIT_MAX_REPOSITORY];
        char child_path[PATH_MAX];
        int r = relative[0] ? snprintf(child_relative, sizeof(child_relative), "%s/%s", relative, item->d_name) :
                              snprintf(child_relative, sizeof(child_relative), "%s", item->d_name);
        int p = snprintf(child_path, sizeof(child_path), "%s/%s", root, child_relative);
        if (r < 0 || p < 0 || (size_t)r >= sizeof(child_relative) ||
            (size_t)p >= sizeof(child_path)) { result = MAELYS_GIT_ERR_LIMIT; break; }
        struct stat status;
        if (lstat(child_path, &status) != 0 || !S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode))
            continue;
        if (maelys_git_repository_name_is_valid(child_relative) && bare_layout(child_path))
            result = add_entry(list, capacity, child_relative,
                               MAELYS_GIT_REPOSITORY_ACTIVE, NULL, error);
        else
            result = scan_active(root, child_relative, list, capacity, error);
        if (result != MAELYS_GIT_OK) break;
    }
    closedir(directory);
    return result;
}

static char *read_repository_name(const char *entry, maelys_git_error_t *error) {
    char path[PATH_MAX];
    int written = snprintf(path, sizeof(path), "%s/repository-name", entry);
    if (written < 0 || (size_t)written >= sizeof(path)) return NULL;
    FILE *file = fopen(path, "rb");
    if (!file) {
        mg_error_set(error, errno == ENOENT ? MAELYS_GIT_ERR_NOT_FOUND : MAELYS_GIT_ERR_IO,
                     errno, "cannot read lifecycle metadata: %s", strerror(errno));
        return NULL;
    }
    char name[MAELYS_GIT_MAX_REPOSITORY + 2u];
    if (!fgets(name, sizeof(name), file) || ferror(file)) {
        int saved = errno;
        fclose(file);
        mg_error_set(error, MAELYS_GIT_ERR_IO, saved,
                     "cannot read lifecycle metadata: %s", strerror(saved));
        return NULL;
    }
    int extra = fgetc(file);
    fclose(file);
    size_t length = strlen(name);
    while (length && (name[length - 1u] == '\n' || name[length - 1u] == '\r'))
        name[--length] = '\0';
    if (extra != EOF || !maelys_git_repository_name_is_valid(name)) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "invalid lifecycle repository metadata: %s", path);
        return NULL;
    }
    return strdup(name);
}

static maelys_git_result_t scan_stored(const char *root,
                                       maelys_git_repository_state_t state,
                                       maelys_git_repository_list_t *list,
                                       size_t *capacity,
                                       maelys_git_error_t *error) {
    char internal[PATH_MAX], store[PATH_MAX];
    int iwritten = snprintf(internal, sizeof(internal), "%s/.maelys-git", root);
    int written = snprintf(store, sizeof(store), "%s/%s", internal,
                           maelys_git_repository_state_name(state));
    if (iwritten < 0 || written < 0 || (size_t)iwritten >= sizeof(internal) ||
        (size_t)written >= sizeof(store)) return MAELYS_GIT_ERR_LIMIT;
    struct stat status;
    if (lstat(internal, &status) != 0) {
        if (errno == ENOENT) return MAELYS_GIT_OK;
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot inspect lifecycle storage: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    maelys_git_result_t safe = require_safe_directory(internal, error);
    if (safe != MAELYS_GIT_OK) return safe;
    if (lstat(store, &status) != 0) {
        if (errno == ENOENT) return MAELYS_GIT_OK;
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot inspect lifecycle storage: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    safe = require_safe_directory(store, error);
    if (safe != MAELYS_GIT_OK) return safe;
    DIR *directory = opendir(store);
    if (!directory) {
        if (errno == ENOENT) return MAELYS_GIT_OK;
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot read lifecycle storage: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    maelys_git_result_t result = MAELYS_GIT_OK;
    struct dirent *item;
    while ((item = readdir(directory)) != NULL) {
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..") ||
            !maelys_git_lifecycle_id_is_valid(item->d_name)) continue;
        char entry[PATH_MAX], repository_path[PATH_MAX];
        int e = snprintf(entry, sizeof(entry), "%s/%s", store, item->d_name);
        int p = snprintf(repository_path, sizeof(repository_path), "%s/repository.git", entry);
        if (e < 0 || p < 0 || (size_t)e >= sizeof(entry) || (size_t)p >= sizeof(repository_path)) {
            result = MAELYS_GIT_ERR_LIMIT; break;
        }
        if (require_safe_directory(entry, error) != MAELYS_GIT_OK) {
            result = error->code; break;
        }
        if (lstat(repository_path, &status) != 0 || !S_ISDIR(status.st_mode) ||
            S_ISLNK(status.st_mode) || !bare_layout(repository_path)) continue;
        char *name = read_repository_name(entry, error);
        if (!name) { result = error->code ? error->code : MAELYS_GIT_ERR_IO; break; }
        result = add_entry(list, capacity, name, state, item->d_name, error);
        free(name);
        if (result != MAELYS_GIT_OK) break;
    }
    closedir(directory);
    return result;
}

void maelys_git_repository_list_clear(maelys_git_repository_list_t *list) {
    if (!list) return;
    free(list->entries);
    memset(list, 0, sizeof(*list));
}

maelys_git_result_t maelys_git_repository_list(
    const char *repository_root, int include_stored,
    maelys_git_repository_list_t *out_list, maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!out_list) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_list, 0, sizeof(*out_list));
    char root[PATH_MAX];
    maelys_git_result_t result = mg_canonical_directory(repository_root, root, "repository root", error);
    size_t capacity = 0u;
    if (result == MAELYS_GIT_OK)
        result = scan_active(root, "", out_list, &capacity, error);
    if (result == MAELYS_GIT_OK && include_stored)
        result = scan_stored(root, MAELYS_GIT_REPOSITORY_ARCHIVE,
                             out_list, &capacity, error);
    if (result == MAELYS_GIT_OK && include_stored)
        result = scan_stored(root, MAELYS_GIT_REPOSITORY_TRASH,
                             out_list, &capacity, error);
    if (result != MAELYS_GIT_OK) maelys_git_repository_list_clear(out_list);
    else if (out_list->count > 1u)
        qsort(out_list->entries, out_list->count, sizeof(*out_list->entries), compare_entries);
    return result;
}

static maelys_git_result_t capture_optional(const char *git,
                                            char *const argv[],
                                            char *out,
                                            size_t capacity,
                                            maelys_git_error_t *error) {
    unsigned char *data = NULL;
    size_t length = 0u;
    int status = 0;
    maelys_git_result_t result = mg_process_capture_status(
        git, argv, &data, &length, capacity, &status, error);
    if (result != MAELYS_GIT_OK) return result;
    if (status == 1) { free(data); out[0] = '\0'; return MAELYS_GIT_OK; }
    if (status != 0) {
        free(data);
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "Git inspection failed with status %d", status);
        return MAELYS_GIT_ERR_PROCESS;
    }
    while (length && (data[length - 1u] == '\n' || data[length - 1u] == '\r'))
        data[--length] = '\0';
    if (!mg_copy_string(out, capacity, (char *)data)) result = MAELYS_GIT_ERR_LIMIT;
    free(data);
    return result;
}

maelys_git_result_t maelys_git_repository_inspect(
    const char *git, const char *repository_root, const char *repository_name,
    maelys_git_repository_info_t *out_info, maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!git || !out_info) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_info, 0, sizeof(*out_info));
    char root[PATH_MAX];
    struct stat status;
    maelys_git_result_t result = mg_canonical_directory(repository_root, root, "repository root", error);
    if (result == MAELYS_GIT_OK)
        result = active_path(root, repository_name, out_info->path, &status, error);
    if (result != MAELYS_GIT_OK) return result;
    if (!mg_copy_string(out_info->repository, sizeof(out_info->repository), repository_name) ||
        !mg_identity_from_stat(&status, out_info->identity)) return MAELYS_GIT_ERR_LIMIT;

    char *head_ref_argv[] = {(char *)git, "--git-dir", out_info->path,
                             "symbolic-ref", "--quiet", "HEAD", NULL};
    result = capture_optional(git, head_ref_argv, out_info->head_ref,
                              sizeof(out_info->head_ref), error);
    char *head_oid_argv[] = {(char *)git, "--git-dir", out_info->path,
                             "rev-parse", "--verify", "--quiet", "HEAD", NULL};
    if (result == MAELYS_GIT_OK)
        result = capture_optional(git, head_oid_argv, out_info->head_oid,
                                  sizeof(out_info->head_oid), error);
    unsigned char *refs = NULL;
    size_t refs_length = 0u;
    char *refs_argv[] = {(char *)git, "--git-dir", out_info->path,
                         "for-each-ref", "--format=%(refname)", NULL};
    if (result == MAELYS_GIT_OK)
        result = mg_process_capture(git, refs_argv, &refs, &refs_length,
                                    16u * 1024u * 1024u, error);
    if (result == MAELYS_GIT_OK)
        for (size_t i = 0u; i < refs_length; ++i) if (refs[i] == '\n') ++out_info->ref_count;
    free(refs);

    unsigned char *objects = NULL;
    size_t objects_length = 0u;
    char *objects_argv[] = {(char *)git, "--git-dir", out_info->path,
                            "count-objects", "-v", NULL};
    if (result == MAELYS_GIT_OK)
        result = mg_process_capture(git, objects_argv, &objects, &objects_length,
                                    4096u, error);
    unsigned long long loose = 0u, packed = 0u, loose_kib = 0u, packed_kib = 0u;
    if (result == MAELYS_GIT_OK) {
        char *save = NULL;
        for (char *line = strtok_r((char *)objects, "\n", &save); line;
             line = strtok_r(NULL, "\n", &save)) {
            if (sscanf(line, "count: %llu", &loose) == 1) continue;
            if (sscanf(line, "in-pack: %llu", &packed) == 1) continue;
            if (sscanf(line, "size: %llu", &loose_kib) == 1) continue;
            (void)sscanf(line, "size-pack: %llu", &packed_kib);
        }
        if (loose > ULLONG_MAX - packed || loose_kib > ULLONG_MAX - packed_kib ||
            loose_kib + packed_kib > ULLONG_MAX / 1024u) {
            result = MAELYS_GIT_ERR_LIMIT;
        } else {
            out_info->object_count = loose + packed;
            out_info->object_bytes = (loose_kib + packed_kib) * 1024u;
        }
    }
    free(objects);
    return result;
}

static maelys_git_result_t initialize_transition(
    maelys_git_repository_transition_t *transition,
    const char *source_repository, const char *target_repository,
    const char *storage_id, maelys_git_repository_state_t source_state,
    maelys_git_repository_state_t target_state, const char *source_path,
    const char *target_path, const struct stat *source_status) {
    memset(transition, 0, sizeof(*transition));
    if (!mg_copy_string(transition->source_repository, sizeof(transition->source_repository), source_repository) ||
        !mg_copy_string(transition->target_repository, sizeof(transition->target_repository), target_repository) ||
        (storage_id && !mg_copy_string(transition->storage_id, sizeof(transition->storage_id), storage_id)) ||
        !mg_copy_string(transition->source_path, sizeof(transition->source_path), source_path) ||
        !mg_copy_string(transition->target_path, sizeof(transition->target_path), target_path) ||
        !mg_identity_from_stat(source_status, transition->source_identity)) return MAELYS_GIT_ERR_LIMIT;
    transition->source_state = source_state;
    transition->target_state = target_state;
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_repository_rename(
    const char *repository_root, const char *source_repository,
    const char *target_repository, const char *expected_source_identity, int apply,
    maelys_git_repository_transition_t *out_transition, maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!out_transition || !maelys_git_repository_name_is_valid(target_repository))
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    char root[PATH_MAX], source[PATH_MAX], target[PATH_MAX];
    struct stat source_status;
    maelys_git_result_t result = mg_canonical_directory(repository_root, root, "repository root", error);
    if (result == MAELYS_GIT_OK)
        result = active_path(root, source_repository, source, &source_status, error);
    int written = result == MAELYS_GIT_OK ?
        snprintf(target, sizeof(target), "%s/%s", root, target_repository) : -1;
    if (result == MAELYS_GIT_OK && (written < 0 || (size_t)written >= sizeof(target)))
        result = MAELYS_GIT_ERR_LIMIT;
    if (result == MAELYS_GIT_OK) result = require_absent(target, error);
    if (result == MAELYS_GIT_OK)
        result = initialize_transition(out_transition, source_repository, target_repository,
            NULL, MAELYS_GIT_REPOSITORY_ACTIVE, MAELYS_GIT_REPOSITORY_ACTIVE,
            source, target, &source_status);
    if (result == MAELYS_GIT_OK)
        result = require_identity(expected_source_identity,
                                  out_transition->source_identity, apply, error);
    if (result == MAELYS_GIT_OK && apply)
        result = mg_repository_ensure_parent_directories(root, target, error);
    if (result == MAELYS_GIT_OK && apply && mg_rename_no_replace(source, target) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot rename repository: %s", strerror(errno));
        result = MAELYS_GIT_ERR_IO;
    }
    if (result == MAELYS_GIT_OK && apply) prune_empty_parents(root, source);
    return result;
}

static maelys_git_result_t write_repository_name(const char *entry,
                                                 const char *repository,
                                                 maelys_git_error_t *error) {
    char path[PATH_MAX];
    int written = snprintf(path, sizeof(path), "%s/repository-name", entry);
    if (written < 0 || (size_t)written >= sizeof(path)) return MAELYS_GIT_ERR_LIMIT;
    char line[MAELYS_GIT_MAX_REPOSITORY + 2u];
    int length = snprintf(line, sizeof(line), "%s\n", repository);
    if (length < 0 || (size_t)length >= sizeof(line)) return MAELYS_GIT_ERR_LIMIT;
    return mg_write_file_exclusive(path, line, (size_t)length, 0600, error);
}

static maelys_git_result_t storage_paths(const char *root,
                                         maelys_git_repository_state_t state,
                                         const char *storage_id,
                                         char internal[PATH_MAX],
                                         char store[PATH_MAX],
                                         char entry[PATH_MAX],
                                         char repository[PATH_MAX]) {
    if ((state != MAELYS_GIT_REPOSITORY_ARCHIVE && state != MAELYS_GIT_REPOSITORY_TRASH) ||
        !maelys_git_lifecycle_id_is_valid(storage_id)) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    int a = snprintf(internal, PATH_MAX, "%s/.maelys-git", root);
    int b = snprintf(store, PATH_MAX, "%s/%s", internal, maelys_git_repository_state_name(state));
    int c = snprintf(entry, PATH_MAX, "%s/%s", store, storage_id);
    int d = snprintf(repository, PATH_MAX, "%s/repository.git", entry);
    return a > 0 && a < PATH_MAX && b > 0 && b < PATH_MAX && c > 0 && c < PATH_MAX &&
           d > 0 && d < PATH_MAX ? MAELYS_GIT_OK : MAELYS_GIT_ERR_LIMIT;
}

maelys_git_result_t maelys_git_repository_store(
    const char *repository_root, const char *repository_name,
    maelys_git_repository_state_t target_state, const char *storage_id,
    const char *expected_source_identity, int apply,
    maelys_git_repository_transition_t *out_transition, maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!out_transition) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    char root[PATH_MAX], source[PATH_MAX], internal[PATH_MAX], store[PATH_MAX];
    char entry[PATH_MAX], target[PATH_MAX];
    struct stat source_status;
    int entry_created = 0;
    maelys_git_result_t result = mg_canonical_directory(repository_root, root, "repository root", error);
    if (result == MAELYS_GIT_OK)
        result = storage_paths(root, target_state, storage_id,
                               internal, store, entry, target);
    if (result == MAELYS_GIT_OK)
        result = active_path(root, repository_name, source, &source_status, error);
    if (result == MAELYS_GIT_OK) result = require_absent(entry, error);
    if (result == MAELYS_GIT_OK)
        result = initialize_transition(out_transition, repository_name, repository_name,
            storage_id, MAELYS_GIT_REPOSITORY_ACTIVE, target_state,
            source, target, &source_status);
    if (result == MAELYS_GIT_OK)
        result = require_identity(expected_source_identity,
                                  out_transition->source_identity, apply, error);
    if (result == MAELYS_GIT_OK && apply) result = ensure_directory(internal, 0700, error);
    if (result == MAELYS_GIT_OK && apply) result = ensure_directory(store, 0700, error);
    if (result == MAELYS_GIT_OK && apply && mkdir(entry, 0700) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot reserve lifecycle entry: %s", strerror(errno));
        result = MAELYS_GIT_ERR_IO;
    } else if (result == MAELYS_GIT_OK && apply) {
        entry_created = 1;
    }
    if (result == MAELYS_GIT_OK && apply)
        result = write_repository_name(entry, repository_name, error);
    if (result == MAELYS_GIT_OK && apply && mg_rename_no_replace(source, target) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot store repository: %s", strerror(errno));
        result = MAELYS_GIT_ERR_IO;
    }
    if (result != MAELYS_GIT_OK && entry_created) {
        char metadata[PATH_MAX];
        if (snprintf(metadata, sizeof(metadata), "%s/repository-name", entry) > 0)
            (void)unlink(metadata);
        (void)rmdir(entry);
    }
    if (result == MAELYS_GIT_OK && apply) prune_empty_parents(root, source);
    return result;
}

maelys_git_result_t maelys_git_repository_restore(
    const char *repository_root, maelys_git_repository_state_t source_state,
    const char *storage_id, const char *target_repository,
    const char *expected_source_identity, int apply,
    maelys_git_repository_transition_t *out_transition, maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!out_transition) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    char root[PATH_MAX], internal[PATH_MAX], store[PATH_MAX], entry[PATH_MAX], source[PATH_MAX];
    maelys_git_result_t result = mg_canonical_directory(repository_root, root, "repository root", error);
    if (result == MAELYS_GIT_OK)
        result = storage_paths(root, source_state, storage_id,
                               internal, store, entry, source);
    if (result == MAELYS_GIT_OK) result = require_safe_directory(internal, error);
    if (result == MAELYS_GIT_OK) result = require_safe_directory(store, error);
    if (result == MAELYS_GIT_OK) result = require_safe_directory(entry, error);
    char *original = result == MAELYS_GIT_OK ? read_repository_name(entry, error) : NULL;
    if (result == MAELYS_GIT_OK && !original)
        result = error->code ? error->code : MAELYS_GIT_ERR_NOT_FOUND;
    const char *target_name = target_repository && *target_repository ? target_repository : original;
    if (result == MAELYS_GIT_OK && !maelys_git_repository_name_is_valid(target_name))
        result = MAELYS_GIT_ERR_INVALID_ARGUMENT;
    struct stat source_status;
    if (result == MAELYS_GIT_OK &&
        (lstat(source, &source_status) != 0 || !S_ISDIR(source_status.st_mode) ||
         S_ISLNK(source_status.st_mode) || !bare_layout(source))) {
        mg_error_set(error, MAELYS_GIT_ERR_NOT_FOUND, errno,
                     "stored repository is missing or invalid");
        result = MAELYS_GIT_ERR_NOT_FOUND;
    }
    char target[PATH_MAX];
    int written = result == MAELYS_GIT_OK ? snprintf(target, sizeof(target), "%s/%s", root, target_name) : -1;
    if (result == MAELYS_GIT_OK && (written < 0 || (size_t)written >= sizeof(target)))
        result = MAELYS_GIT_ERR_LIMIT;
    if (result == MAELYS_GIT_OK) result = require_absent(target, error);
    if (result == MAELYS_GIT_OK)
        result = initialize_transition(out_transition, original, target_name, storage_id,
            source_state, MAELYS_GIT_REPOSITORY_ACTIVE, source, target, &source_status);
    if (result == MAELYS_GIT_OK)
        result = require_identity(expected_source_identity,
                                  out_transition->source_identity, apply, error);
    if (result == MAELYS_GIT_OK && apply)
        result = mg_repository_ensure_parent_directories(root, target, error);
    if (result == MAELYS_GIT_OK && apply && mg_rename_no_replace(source, target) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot restore repository: %s", strerror(errno));
        result = MAELYS_GIT_ERR_IO;
    }
    if (result == MAELYS_GIT_OK && apply) {
        char metadata[PATH_MAX];
        if (snprintf(metadata, sizeof(metadata), "%s/repository-name", entry) > 0)
            (void)unlink(metadata);
        (void)rmdir(entry);
    }
    free(original);
    return result;
}
