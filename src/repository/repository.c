#include "internal.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int path_is_inside(const char *root, const char *path) {
    size_t root_length = strlen(root);
    return strncmp(root, path, root_length) == 0 &&
           (path[root_length] == '/' || path[root_length] == '\0');
}

maelys_git_result_t maelys_git_resolve_repository(const char *repository_root,
                                                   const char *repository_name,
                                                   char *out_path,
                                                   size_t out_capacity,
                                                   maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!repository_root || !repository_name || !out_path || out_capacity == 0u) {
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    if (!maelys_git_repository_name_is_valid(repository_name)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, 0, "invalid repository name");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    char canonical_root[PATH_MAX];
    if (!realpath(repository_root, canonical_root)) {
        mg_error_set(error, MAELYS_GIT_ERR_NOT_FOUND, errno, "cannot resolve repository root: %s", strerror(errno));
        return MAELYS_GIT_ERR_NOT_FOUND;
    }
    char candidate[PATH_MAX];
    int count = snprintf(candidate, sizeof(candidate), "%s/%s", canonical_root, repository_name);
    if (count < 0 || (size_t)count >= sizeof(candidate)) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "repository path is too long");
        return MAELYS_GIT_ERR_LIMIT;
    }
    char canonical_repository[PATH_MAX];
    if (!realpath(candidate, canonical_repository)) {
        mg_error_set(error, MAELYS_GIT_ERR_NOT_FOUND, errno, "cannot resolve repository: %s", strerror(errno));
        return MAELYS_GIT_ERR_NOT_FOUND;
    }
    if (!path_is_inside(canonical_root, canonical_repository)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, 0, "repository escapes configured root");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    struct stat status;
    if (stat(canonical_repository, &status) != 0 || !S_ISDIR(status.st_mode)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, errno, "repository is not a directory");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    if (!mg_copy_string(out_path, out_capacity, canonical_repository)) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "repository output buffer is too small");
        return MAELYS_GIT_ERR_LIMIT;
    }
    return MAELYS_GIT_OK;
}

void maelys_git_path_list_clear(maelys_git_path_list_t *paths) {
    if (!paths) return;
    for (size_t i = 0u; i < paths->count; ++i) free(paths->items[i]);
    free(paths->items);
    paths->items = NULL;
    paths->count = 0u;
}

typedef struct {
    maelys_git_path_list_t *paths;
    size_t capacity;
} path_collector_t;

static maelys_git_result_t collect_changed_path(const maelys_git_change_t *change,
                                                void *context,
                                                maelys_git_error_t *error) {
    path_collector_t *collector = context;
    size_t required = change->old_path[0] ? 2u : 1u;
    while (collector->paths->count + required > collector->capacity) {
        size_t next = collector->capacity ? collector->capacity * 2u : 32u;
        if (next < collector->capacity || next > SIZE_MAX / sizeof(char *)) {
            mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "changed path list is too large");
            return MAELYS_GIT_ERR_LIMIT;
        }
        char **items = realloc(collector->paths->items, next * sizeof(*items));
        if (!items) return MAELYS_GIT_ERR_IO;
        collector->paths->items = items;
        collector->capacity = next;
    }
    if (change->old_path[0]) {
        char *old_path = strdup(change->old_path);
        if (!old_path) return MAELYS_GIT_ERR_IO;
        collector->paths->items[collector->paths->count++] = old_path;
    }
    char *path = strdup(change->path);
    if (!path) return MAELYS_GIT_ERR_IO;
    collector->paths->items[collector->paths->count++] = path;
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_repository_changed_paths(const char *git_executable,
                                                         const char *repository_path,
                                                         const char *old_oid,
                                                         const char *new_oid,
                                                         maelys_git_path_list_t *out_paths,
                                                         maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!git_executable || !repository_path || !old_oid || !new_oid || !out_paths ||
        !mg_is_oid(old_oid) || !mg_is_oid(new_oid)) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_paths, 0, sizeof(*out_paths));
    path_collector_t collector = {.paths = out_paths};
    maelys_git_change_summary_t summary;
    maelys_git_result_t result = maelys_git_repository_visit_changes(
        git_executable, repository_path, old_oid, new_oid,
        collect_changed_path, &collector, &summary, error);
    if (result != MAELYS_GIT_OK) maelys_git_path_list_clear(out_paths);
    return result;
}

maelys_git_result_t maelys_git_repository_init_bare(const char *git_executable,
                                                     const char *repository_root,
                                                     const char *repository_name,
                                                     maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!git_executable || !repository_root || !repository_name ||
        !maelys_git_repository_name_is_valid(repository_name)) {
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    char canonical_root[PATH_MAX];
    if (!realpath(repository_root, canonical_root)) {
        mg_error_set(error, MAELYS_GIT_ERR_NOT_FOUND, errno, "cannot resolve repository root: %s", strerror(errno));
        return MAELYS_GIT_ERR_NOT_FOUND;
    }
    char target[PATH_MAX];
    int count = snprintf(target, sizeof(target), "%s/%s", canonical_root, repository_name);
    if (count < 0 || (size_t)count >= sizeof(target)) return MAELYS_GIT_ERR_LIMIT;
    struct stat status;
    if (lstat(target, &status) == 0 || errno != ENOENT) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, errno, "repository target already exists or is inaccessible");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    maelys_git_result_t result = mg_repository_ensure_parent_directories(
        canonical_root, target, error);
    if (result != MAELYS_GIT_OK) return result;
    char *const argv[] = {
        (char *)git_executable, "init", "--quiet", "--bare", "--", target, NULL};
    return mg_process_run(git_executable, argv, NULL, error);
}

maelys_git_result_t maelys_git_repository_update_ref(const char *git_executable,
                                                      const char *repository_path,
                                                      const char *ref_name,
                                                      const char *new_oid,
                                                      const char *expected_old_oid,
                                                      maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!git_executable || !repository_path || !maelys_git_ref_name_is_valid(ref_name) ||
        !mg_is_oid(new_oid) || !mg_is_oid(expected_old_oid)) {
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    char *update_argv[] = {
        (char *)git_executable, "--git-dir", (char *)repository_path,
        "update-ref", (char *)ref_name, (char *)new_oid, (char *)expected_old_oid, NULL};
    char *delete_argv[] = {
        (char *)git_executable, "--git-dir", (char *)repository_path,
        "update-ref", "-d", (char *)ref_name, (char *)expected_old_oid, NULL};
    return mg_process_run(git_executable,
                          mg_is_zero_oid(new_oid) ? delete_argv : update_argv,
                          NULL,
                          error);
}
