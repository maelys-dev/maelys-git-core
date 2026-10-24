/* The agent's store of grants snapshots: one immutable file per SHA-256,
 * beside the journal, written before the executor that reads it starts. */
#include "agent_internal.h"
#include "policy/grants.h"

#include <maelys/cli/digest.h>
#include <maelys/cli/files.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define STORE_DIRECTORY "grants-store"

static maelys_git_result_t code_of(int saved) {
    return saved == EACCES || saved == EPERM ? MAELYS_GIT_ERR_DENIED
         : saved == ENOENT || saved == ENOTDIR ? MAELYS_GIT_ERR_NOT_FOUND
         : saved == EFBIG ? MAELYS_GIT_ERR_LIMIT : MAELYS_GIT_ERR_IO;
}

static int sync_directory(const char *path) {
    int descriptor = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (descriptor < 0) return 0;
    int synced = fsync(descriptor) == 0;
    int saved = errno;
    (void)close(descriptor);
    errno = saved;
    return synced;
}

/* The store's directory, beside the journal: created private on first use,
 * and judged on every use, since the executor trusts what it holds. */
static maelys_git_result_t open_store(const char *database_path, char out[4096], maelys_git_error_t *error) {
    const char *slash = strrchr(database_path, '/');
    size_t parent_length = slash ? (size_t)(slash - database_path) : 0u;
    char parent[4096];
    int written = snprintf(parent, sizeof(parent), "%.*s", (int)parent_length, database_path);
    if (written < 0 || (size_t)written >= sizeof(parent) ||
        snprintf(out, 4096u, "%s/" STORE_DIRECTORY, parent) >= 4096) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "grants store path is too long");
        return MAELYS_GIT_ERR_LIMIT;
    }
    if (mkdir(out, 0700) == 0) {
        if (!sync_directory(parent[0] ? parent : "/")) {
            int saved = errno;
            mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "cannot make grants store %s durable: %s", out,
                         strerror(saved));
            return MAELYS_GIT_ERR_IO;
        }
    } else if (errno != EEXIST) {
        int saved = errno;
        mg_error_set(error, code_of(saved), saved, "cannot create grants store %s: %s", out, strerror(saved));
        return code_of(saved);
    }
    struct stat status;
    if (lstat(out, &status) != 0 || !S_ISDIR(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 077u) != 0u) {
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, errno,
                     "grants store %s is not a directory private to the agent's account", out);
        return MAELYS_GIT_ERR_DENIED;
    }
    return MAELYS_GIT_OK;
}

/* An entry already in the store holds the bytes its name says. */
static maelys_git_result_t verify_entry(const char *path, const char *sha256, maelys_git_error_t *error) {
    unsigned char *bytes = NULL;
    size_t size = 0u;
    const char *reason = NULL;
    if (maelys_cli_read_trusted_file(path,
                                     MAELYS_CLI_FILE_REGULAR | MAELYS_CLI_FILE_NO_SYMLINK |
                                         MAELYS_CLI_FILE_OWNER_CALLER |
                                         MAELYS_CLI_FILE_NOT_WRITABLE_BY_OTHERS |
                                         MAELYS_CLI_FILE_TRUSTED_DIRECTORY,
                                     1u, MG_GRANTS_MAX_BYTES, &bytes, &size, &reason) != 0) {
        int saved = errno;
        mg_error_set(error, code_of(saved), saved, "grants store entry %s refused: %s", path,
                     reason ? reason : strerror(saved));
        return code_of(saved);
    }
    char digest[MAELYS_CLI_SHA256_HEX_SIZE];
    maelys_cli_sha256_hex(bytes, size, digest);
    free(bytes);
    if (strcmp(digest, sha256) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "grants store entry %s does not hold the bytes its name says",
                     path);
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_grants_store_archive(const char *grants_path, const char *database_path,
                                            mg_grants_archive_t *out, maelys_git_error_t *error) {
    if (!grants_path || !database_path || !out) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    unsigned char *bytes = NULL;
    size_t size = 0u;
    maelys_git_result_t result = mg_grants_read(grants_path, &bytes, &size, error);
    if (result != MAELYS_GIT_OK) return result;
    char sha256[MAELYS_CLI_SHA256_HEX_SIZE];
    maelys_cli_sha256_hex(bytes, size, sha256);
    char directory[4096], path[4096];
    result = open_store(database_path, directory, error);
    if (result == MAELYS_GIT_OK && snprintf(path, sizeof(path), "%s/%s.json", directory, sha256) >= (int)sizeof(path)) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "grants store path is too long");
        result = MAELYS_GIT_ERR_LIMIT;
    }
    /* Written once, read-only, under its digest: never replaced. A file
     * already there, from an earlier command or another agent process, is
     * read again rather than trusted by its name. */
    if (result == MAELYS_GIT_OK) {
        if (maelys_cli_write_file_atomic(path, bytes, size, 0400, MAELYS_CLI_WRITE_NO_REPLACE) == 0) {
            if (!sync_directory(directory)) {
                int saved = errno;
                mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "cannot make grants store entry %s durable: %s",
                             path, strerror(saved));
                result = MAELYS_GIT_ERR_IO;
            }
        } else if (errno == EEXIST) {
            result = verify_entry(path, sha256, error);
        } else {
            int saved = errno;
            mg_error_set(error, code_of(saved), saved, "cannot write grants store entry %s: %s", path,
                         strerror(saved));
            result = code_of(saved);
        }
    }
    free(bytes);
    if (result != MAELYS_GIT_OK) return result;
    (void)mg_copy_string(out->sha256, sizeof(out->sha256), sha256);
    (void)mg_copy_string(out->path, sizeof(out->path), path);
    return MAELYS_GIT_OK;
}
