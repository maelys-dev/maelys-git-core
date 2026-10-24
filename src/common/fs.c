/* File-system primitives shared by the repository modules: canonical
 * directories, directory identities, no-replace renames, private temporary
 * directories, exclusive file creation and directory syncs. */
#include "internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1u << 0)
#endif
#endif

maelys_git_result_t mg_canonical_directory(const char *path,
                                           char out[PATH_MAX],
                                           const char *what,
                                           maelys_git_error_t *error) {
    if (!path || !realpath(path, out)) {
        mg_error_set(error, MAELYS_GIT_ERR_NOT_FOUND, errno,
                     "cannot resolve %s: %s", what, strerror(errno));
        return MAELYS_GIT_ERR_NOT_FOUND;
    }
    struct stat status;
    if (lstat(out, &status) != 0 || !S_ISDIR(status.st_mode)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, errno,
                     "%s is not a direct directory", what);
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    return MAELYS_GIT_OK;
}

int mg_identity_from_stat(const struct stat *status, char out[MG_IDENTITY_MAX]) {
    int written = snprintf(out, MG_IDENTITY_MAX, "%" PRIxMAX ":%" PRIxMAX,
                           (uintmax_t)status->st_dev, (uintmax_t)status->st_ino);
    return written > 0 && (size_t)written < MG_IDENTITY_MAX;
}

int mg_path_identity(const char *path,
                     char out[MG_IDENTITY_MAX],
                     struct stat *out_status) {
    struct stat status;
    if (!path || lstat(path, &status) != 0 || !S_ISDIR(status.st_mode)) return 0;
    if (!mg_identity_from_stat(&status, out)) return 0;
    if (out_status) *out_status = status;
    return 1;
}

int mg_rename_no_replace(const char *source, const char *target) {
#if defined(__APPLE__)
    return renameatx_np(AT_FDCWD, source, AT_FDCWD, target, RENAME_EXCL);
#else
#if defined(__linux__) && defined(SYS_renameat2)
    long rc = syscall(SYS_renameat2, AT_FDCWD, source, AT_FDCWD, target,
                      (unsigned int)RENAME_NOREPLACE);
    if (rc == 0) return 0;
    /* EINVAL and ENOSYS mean the file system or kernel lacks the flag; any
     * other error is authoritative. */
    if (errno != EINVAL && errno != ENOSYS) return -1;
#endif
    struct stat status;
    if (lstat(target, &status) == 0) {
        errno = EEXIST;
        return -1;
    }
    if (errno != ENOENT) return -1;
    return rename(source, target);
#endif
}

const char *mg_temporary_root(void) {
    const char *candidate = getenv("TMPDIR");
    struct stat status;
    if (candidate && candidate[0] == '/' && strlen(candidate) < PATH_MAX / 2u &&
        stat(candidate, &status) == 0 && S_ISDIR(status.st_mode))
        return candidate;
    return "/tmp";
}

maelys_git_result_t mg_make_temporary_directory(const char *prefix,
                                                char out[PATH_MAX],
                                                maelys_git_error_t *error) {
    int written = snprintf(out, PATH_MAX, "%s.XXXXXX", prefix);
    if (written < 0 || written >= PATH_MAX) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "temporary directory path is too long");
        return MAELYS_GIT_ERR_LIMIT;
    }
    if (!mkdtemp(out)) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot create temporary directory: %s", strerror(errno));
        out[0] = '\0';
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}

static int write_all(int descriptor, const unsigned char *data, size_t length) {
    size_t offset = 0u;
    while (offset < length) {
        ssize_t count = write(descriptor, data + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        offset += (size_t)count;
    }
    return 1;
}

maelys_git_result_t mg_write_file_exclusive(const char *path,
                                            const void *data,
                                            size_t length,
                                            mode_t mode,
                                            maelys_git_error_t *error) {
    if (!path || (!data && length)) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (descriptor < 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot create %s: %s", path, strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    const char *failure = NULL;
    if (!write_all(descriptor, data, length)) failure = "cannot write";
    else if (fsync(descriptor) != 0) failure = "cannot persist";
    int saved = errno;
    if (close(descriptor) != 0 && !failure) {
        failure = "cannot close";
        saved = errno;
    }
    if (failure) {
        (void)unlink(path);
        mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "%s %s: %s", failure, path,
                     strerror(saved));
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}

int mg_sync_directory(const char *path) {
    int descriptor = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (descriptor < 0) return 0;
    int synced = fsync(descriptor) == 0;
    int saved = errno;
    (void)close(descriptor);
    errno = saved;
    return synced;
}

int mg_remove_tree(const char *path) {
    if (!path || !*path || !strcmp(path, "/")) return 0;
    struct stat status;
    if (lstat(path, &status) != 0) return errno == ENOENT;
    if (!S_ISDIR(status.st_mode)) return unlink(path) == 0;
    DIR *directory = opendir(path);
    if (!directory) return 0;
    int ok = 1;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char child[PATH_MAX];
        int count = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (count < 0 || (size_t)count >= sizeof(child) || !mg_remove_tree(child)) ok = 0;
    }
    (void)closedir(directory);
    return rmdir(path) == 0 && ok;
}

maelys_git_result_t mg_repository_ensure_parent_directories(
    const char *root, const char *target, maelys_git_error_t *error) {
    char path[PATH_MAX];
    if (!mg_copy_string(path, sizeof(path), target)) return MAELYS_GIT_ERR_LIMIT;
    size_t root_length = strlen(root);
    char *last = strrchr(path, '/');
    if (!last || (size_t)(last - path) < root_length) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    if ((size_t)(last - path) == root_length) return MAELYS_GIT_OK;
    *last = '\0';
    for (char *p = path + root_length + 1u;; ++p) {
        if (*p != '/' && *p != '\0') continue;
        char saved = *p;
        *p = '\0';
        struct stat status;
        if (lstat(path, &status) != 0) {
            if (errno != ENOENT || mkdir(path, 0750) != 0) {
                mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                             "cannot create repository parent %s: %s", path, strerror(errno));
                return MAELYS_GIT_ERR_IO;
            }
        } else if (!S_ISDIR(status.st_mode)) {
            mg_error_set(error, MAELYS_GIT_ERR_IO, 0,
                         "repository parent is not a direct directory: %s", path);
            return MAELYS_GIT_ERR_IO;
        }
        *p = saved;
        if (saved == '\0') break;
    }
    return MAELYS_GIT_OK;
}
