#include "internal.h"

#include <errno.h>
#include <limits.h>
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

static maelys_git_result_t split_nul_paths(unsigned char *data,
                                           size_t length,
                                           maelys_git_path_list_t *out_paths,
                                           maelys_git_error_t *error) {
    size_t count = 0u;
    for (size_t i = 0u; i < length; ++i) if (data[i] == '\0') ++count;
    if (length > 0u && data[length - 1u] != '\0') {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "Git returned an unterminated path");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    if (count > MAELYS_GIT_MAX_CHANGED_PATHS) {
        mg_error_set(error,
                     MAELYS_GIT_ERR_LIMIT,
                     0,
                     "push changes more than %u paths",
                     (unsigned)MAELYS_GIT_MAX_CHANGED_PATHS);
        return MAELYS_GIT_ERR_LIMIT;
    }
    char **items = count ? calloc(count, sizeof(*items)) : NULL;
    if (count && !items) return MAELYS_GIT_ERR_IO;
    size_t start = 0u;
    size_t item = 0u;
    for (size_t i = 0u; i < length; ++i) {
        if (data[i] != '\0') continue;
        size_t path_length = i - start;
        if (path_length == 0u || path_length >= PATH_MAX) {
            for (size_t j = 0u; j < item; ++j) free(items[j]);
            free(items);
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "Git returned an invalid path");
            return MAELYS_GIT_ERR_PROTOCOL;
        }
        items[item] = malloc(path_length + 1u);
        if (!items[item]) {
            for (size_t j = 0u; j < item; ++j) free(items[j]);
            free(items);
            return MAELYS_GIT_ERR_IO;
        }
        memcpy(items[item], data + start, path_length);
        items[item][path_length] = '\0';
        ++item;
        start = i + 1u;
    }
    out_paths->items = items;
    out_paths->count = count;
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
    if (mg_is_zero_oid(old_oid) && mg_is_zero_oid(new_oid)) return MAELYS_GIT_OK;

    char treeish[72];
    const char *tree_oid = mg_is_zero_oid(new_oid) ? old_oid : new_oid;
    int treeish_length = snprintf(treeish, sizeof(treeish), "%s^{tree}", tree_oid);
    if (treeish_length < 0 || (size_t)treeish_length >= sizeof(treeish)) {
        return MAELYS_GIT_ERR_LIMIT;
    }
    char *whole_tree_argv[] = {
        (char *)git_executable, "--git-dir", (char *)repository_path,
        "ls-tree", "--name-only", "-r", "-z", treeish, NULL};
    char *update_argv[] = {
        (char *)git_executable, "--git-dir", (char *)repository_path,
        "diff", "--name-only", "--no-renames", "-z",
        (char *)old_oid, (char *)new_oid, "--", NULL};
    unsigned char *data = NULL;
    size_t length = 0u;
    maelys_git_result_t result = mg_process_capture(
        git_executable,
        (mg_is_zero_oid(old_oid) || mg_is_zero_oid(new_oid)) ? whole_tree_argv : update_argv,
        &data,
        &length,
        1024u * 1024u,
        error);
    if (result != MAELYS_GIT_OK) return result;
    result = split_nul_paths(data, length, out_paths, error);
    free(data);
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
