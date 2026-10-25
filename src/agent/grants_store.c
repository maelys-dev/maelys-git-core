/* The agent's store of grants snapshots: one immutable file per SHA-256,
 * beside the journal, written before the executor that reads it starts. */
#include "agent_internal.h"
#include "policy/grants.h"

#include <maelys/cli/digest.h>
#include <maelys/cli/files.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define STORE_DIRECTORY "grants-store"
#define STORE_LOCK ".lock"

static maelys_git_result_t code_of(int saved) {
    return saved == EACCES || saved == EPERM ? MAELYS_GIT_ERR_DENIED
         : saved == ENOENT || saved == ENOTDIR ? MAELYS_GIT_ERR_NOT_FOUND
         : saved == EFBIG ? MAELYS_GIT_ERR_LIMIT : MAELYS_GIT_ERR_IO;
}

/* The directory of the journal at DATABASE_PATH, and the store beside it. */
static maelys_git_result_t store_paths(const char *database_path, char parent[4096], char out[4096],
                                       maelys_git_error_t *error) {
    const char *slash = strrchr(database_path, '/');
    size_t parent_length = slash ? (size_t)(slash - database_path) : 0u;
    int written = snprintf(parent, 4096u, "%.*s", (int)parent_length, database_path);
    if (written < 0 || written >= 4096 || snprintf(out, 4096u, "%s/" STORE_DIRECTORY, parent) >= 4096) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "grants store path is too long");
        return MAELYS_GIT_ERR_LIMIT;
    }
    return MAELYS_GIT_OK;
}

/* The store is a directory private to the agent's account. */
static maelys_git_result_t judge_store(const char *store, maelys_git_error_t *error) {
    struct stat status;
    if (lstat(store, &status) != 0 || !S_ISDIR(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 077u) != 0u) {
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, errno,
                     "grants store %s is not a directory private to the agent's account", store);
        return MAELYS_GIT_ERR_DENIED;
    }
    return MAELYS_GIT_OK;
}

/* The store's directory, beside the journal: created private on first use,
 * and judged on every use, since the executor trusts what it holds. */
static maelys_git_result_t open_store(const char *database_path, char out[4096], maelys_git_error_t *error) {
    char parent[4096];
    maelys_git_result_t paths = store_paths(database_path, parent, out, error);
    if (paths != MAELYS_GIT_OK) return paths;
    if (mkdir(out, 0700) != 0 && errno != EEXIST) {
        int saved = errno;
        mg_error_set(error, code_of(saved), saved, "cannot create grants store %s: %s", out, strerror(saved));
        return code_of(saved);
    }
    maelys_git_result_t judged = judge_store(out, error);
    if (judged != MAELYS_GIT_OK) return judged;
    /* Synced on every use, not only after the mkdir: a store whose parent
     * sync failed once is made durable by the next attempt. */
    if (!mg_sync_directory(parent[0] ? parent : "/")) {
        int saved = errno;
        mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "cannot make grants store %s durable: %s", out,
                     strerror(saved));
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}

/* The store's lock: shared while an executor may read a file of the store,
 * from its archive to its exit; exclusive while a purge removes files. An
 * exclusive lock is tried until WAIT_MS have passed. */
static maelys_git_result_t lock_store(const char *store, int exclusive, uint64_t wait_ms, int *out_lock,
                                      maelys_git_error_t *error) {
    *out_lock = -1;
    char path[4200];
    (void)snprintf(path, sizeof(path), "%s/" STORE_LOCK, store);
    int lock = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0) {
        int saved = errno;
        mg_error_set(error, code_of(saved), saved, "cannot open the lock of grants store %s: %s", store,
                     strerror(saved));
        return code_of(saved);
    }
    int locked = 0;
    if (!exclusive) {
        while (!(locked = flock(lock, LOCK_SH) == 0) && errno == EINTR) {}
    } else {
        for (uint64_t waited = 0u;; waited += 20u) {
            if ((locked = flock(lock, LOCK_EX | LOCK_NB) == 0) || errno != EWOULDBLOCK || waited >= wait_ms) break;
            struct timespec pause = {0, 20000000L};
            (void)nanosleep(&pause, NULL);
        }
    }
    if (!locked) {
        int saved = errno;
        (void)close(lock);
        if (saved == EWOULDBLOCK) {
            mg_error_set(error, MAELYS_GIT_ERR_LIMIT, saved,
                         "grants store %s is in use by a running command; retry the purge", store);
            return MAELYS_GIT_ERR_LIMIT;
        }
        mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "cannot lock grants store %s: %s", store, strerror(saved));
        return MAELYS_GIT_ERR_IO;
    }
    *out_lock = lock;
    return MAELYS_GIT_OK;
}

void mg_grants_archive_release(mg_grants_archive_t *archive) {
    if (!archive || archive->lock < 0) return;
    (void)close(archive->lock); /* closing the descriptor releases its flock */
    archive->lock = -1;
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
    out->lock = -1;
    unsigned char *bytes = NULL;
    size_t size = 0u;
    maelys_git_result_t result = mg_grants_read(grants_path, &bytes, &size, error);
    if (result != MAELYS_GIT_OK) return result;
    char sha256[MAELYS_CLI_SHA256_HEX_SIZE];
    maelys_cli_sha256_hex(bytes, size, sha256);
    char directory[4096], path[4096];
    result = open_store(database_path, directory, error);
    int lock = -1;
    if (result == MAELYS_GIT_OK) result = lock_store(directory, 0, 0u, &lock, error);
    if (result == MAELYS_GIT_OK && snprintf(path, sizeof(path), "%s/%s.json", directory, sha256) >= (int)sizeof(path)) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "grants store path is too long");
        result = MAELYS_GIT_ERR_LIMIT;
    }
    /* Written once, read-only, under its digest: never replaced. A file
     * already there, from an earlier command or another agent process, is
     * read again rather than trusted by its name, and synced again with its
     * directory: an attempt whose sync failed left it published, and its
     * bytes being right says nothing of their durability. */
    /* A new file was synced by maelys_cli_write_file_atomic before it was
     * linked; an existing one is synced here. */
    if (result == MAELYS_GIT_OK &&
        maelys_cli_write_file_atomic(path, bytes, size, 0400, MAELYS_CLI_WRITE_NO_REPLACE) != 0) {
        if (errno == EEXIST) {
            result = verify_entry(path, sha256, error);
            if (result == MAELYS_GIT_OK && !mg_sync_file(path)) {
                int saved = errno;
                mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "cannot make grants store entry %s durable: %s",
                             path, strerror(saved));
                result = MAELYS_GIT_ERR_IO;
            }
        } else {
            int saved = errno;
            mg_error_set(error, code_of(saved), saved, "cannot write grants store entry %s: %s", path,
                         strerror(saved));
            result = code_of(saved);
        }
    }
    if (result == MAELYS_GIT_OK && !mg_sync_directory(directory)) {
        int saved = errno;
        mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "cannot make grants store entry %s durable: %s", path,
                     strerror(saved));
        result = MAELYS_GIT_ERR_IO;
    }
    free(bytes);
    if (result != MAELYS_GIT_OK) {
        if (lock >= 0) (void)close(lock);
        return result;
    }
    (void)mg_copy_string(out->sha256, sizeof(out->sha256), sha256);
    (void)mg_copy_string(out->path, sizeof(out->path), path);
    out->lock = lock;
    return MAELYS_GIT_OK;
}

/* ---- purge -------------------------------------------------------------------- */

static int is_entry_name(const char *name) {
    return strlen(name) == 69u && strspn(name, "0123456789abcdef") == 64u && !strcmp(name + 64, ".json");
}

typedef struct {
    mg_grants_store_entry_t *entries;
    size_t count;
} entries_t;

static void note_use(const char *sha256, int64_t at_ms, void *context) {
    entries_t *entries = context;
    for (size_t i = 0u; i < entries->count; ++i)
        if (!strncmp(entries->entries[i].sha256, sha256, 64u) && at_ms > entries->entries[i].last_used_ms)
            entries->entries[i].last_used_ms = at_ms;
}

/* Most recently used first; equal times by digest, so that a plan is the
 * same whatever order the directory lists. */
static int compare_entries(const void *a, const void *b) {
    const mg_grants_store_entry_t *x = a, *y = b;
    if (x->last_used_ms != y->last_used_ms) return x->last_used_ms > y->last_used_ms ? -1 : 1;
    return strcmp(x->sha256, y->sha256);
}

static maelys_git_result_t list_entries(const char *store, entries_t *out, maelys_git_error_t *error) {
    DIR *directory = opendir(store);
    if (!directory) {
        int saved = errno;
        mg_error_set(error, code_of(saved), saved, "cannot list grants store %s: %s", store, strerror(saved));
        return code_of(saved);
    }
    size_t capacity = 0u;
    maelys_git_result_t result = MAELYS_GIT_OK;
    for (struct dirent *entry; result == MAELYS_GIT_OK && (entry = readdir(directory)) != NULL;) {
        if (!is_entry_name(entry->d_name)) continue;
        char path[4200];
        struct stat status;
        (void)snprintf(path, sizeof(path), "%s/%s", store, entry->d_name);
        if (lstat(path, &status) != 0 || !S_ISREG(status.st_mode)) continue;
        if (out->count == capacity) {
            capacity = capacity ? capacity * 2u : 16u;
            mg_grants_store_entry_t *grown = realloc(out->entries, capacity * sizeof(*grown));
            if (!grown) {
                mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "out of memory while listing grants store %s", store);
                result = MAELYS_GIT_ERR_IO;
                break;
            }
            out->entries = grown;
        }
        mg_grants_store_entry_t *kept = &out->entries[out->count++];
        memset(kept, 0, sizeof(*kept));
        memcpy(kept->sha256, entry->d_name, 64u);
        kept->bytes = (int64_t)status.st_size;
#ifdef __APPLE__
        kept->last_used_ms = (int64_t)status.st_mtimespec.tv_sec * 1000 + status.st_mtimespec.tv_nsec / 1000000;
#else
        kept->last_used_ms = (int64_t)status.st_mtim.tv_sec * 1000 + status.st_mtim.tv_nsec / 1000000;
#endif
    }
    (void)closedir(directory);
    return result;
}

static maelys_git_result_t audit_purge(maelys_git_agent_store_t *journal, const mg_grants_store_prune_t *result,
                                       int64_t now_ms, maelys_git_error_t *error) {
    mg_json_t json;
    mg_json_begin(&json, MG_JSON_DATA);
    mg_json_object(&json, NULL);
    mg_json_array(&json, "removed");
    for (size_t i = 0u; i < result->count; ++i)
        if (!result->entries[i].keep) mg_json_string(&json, NULL, result->entries[i].sha256);
    mg_json_end_array(&json);
    mg_json_string(&json, "store", result->store);
    mg_json_end_object(&json);
    char *payload = NULL;
    size_t size = 0u;
    if (mg_json_finish(&json, &payload, &size) != MAELYS_JSON_OK) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "cannot encode the purge audit event");
        return MAELYS_GIT_ERR_IO;
    }
    char event_id[64];
    (void)snprintf(event_id, sizeof(event_id), "grants-store-prune:%lld", (long long)now_ms);
    maelys_git_result_t audited = mg_store_audit(journal, event_id, "grants_store_pruned", payload, now_ms, error);
    free(payload);
    return audited;
}

maelys_git_result_t mg_grants_store_prune(const maelys_git_agent_config_t *config, size_t keep,
                                          uint64_t max_age_ms, int64_t now_ms, uint64_t wait_ms, int apply,
                                          mg_grants_store_prune_t *out, maelys_git_error_t *error) {
    if (!config || !out) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    char parent[4096];
    maelys_git_result_t result = store_paths(config->database_path, parent, out->store, error);
    if (result != MAELYS_GIT_OK) return result;
    struct stat status;
    if (lstat(out->store, &status) != 0) {
        if (errno == ENOENT) return MAELYS_GIT_OK; /* nothing was ever kept */
        int saved = errno;
        mg_error_set(error, code_of(saved), saved, "cannot inspect grants store %s: %s", out->store,
                     strerror(saved));
        return code_of(saved);
    }
    if ((result = judge_store(out->store, error)) != MAELYS_GIT_OK) return result;
    /* The snapshot the next command would keep is never expired. */
    char current[MAELYS_CLI_SHA256_HEX_SIZE] = "";
    if (config->grants_path[0]) {
        unsigned char *bytes = NULL;
        size_t size = 0u;
        if ((result = mg_grants_read(config->grants_path, &bytes, &size, error)) != MAELYS_GIT_OK) return result;
        maelys_cli_sha256_hex(bytes, size, current);
        free(bytes);
    }
    int lock = -1;
    if (apply && (result = lock_store(out->store, 1, wait_ms, &lock, error)) != MAELYS_GIT_OK) return result;
    entries_t entries = {0};
    maelys_git_agent_store_t *journal = NULL;
    result = list_entries(out->store, &entries, error);
    /* A plan creates no journal; a purge records itself in it. */
    if (result == MAELYS_GIT_OK && (apply || access(config->database_path, F_OK) == 0))
        result = mg_store_open(config->database_path, &journal, error);
    if (result == MAELYS_GIT_OK && journal) result = mg_store_grants_uses(journal, note_use, &entries, error);
    out->entries = entries.entries;
    out->count = entries.count;
    if (result == MAELYS_GIT_OK && out->count)
        qsort(out->entries, out->count, sizeof(*out->entries), compare_entries);
    for (size_t i = 0u; result == MAELYS_GIT_OK && i < out->count; ++i) {
        mg_grants_store_entry_t *entry = &out->entries[i];
        entry->keep = 1;
        if (current[0] && !strcmp(entry->sha256, current)) entry->reason = "current";
        else if (i < keep) entry->reason = "latest";
        else if (entry->last_used_ms > now_ms || (uint64_t)(now_ms - entry->last_used_ms) < max_age_ms)
            entry->reason = "recent";
        else {
            entry->keep = 0;
            entry->reason = "expired";
            ++out->removed;
            out->freed_bytes += entry->bytes;
        }
    }
    if (result == MAELYS_GIT_OK && apply && out->removed) {
        /* A file that cannot be removed stays, and the others go: what was
         * removed is always synced and audited, then the failure reported. */
        maelys_git_error_t failure = {0};
        maelys_git_result_t removal = MAELYS_GIT_OK;
        for (size_t i = 0u; i < out->count; ++i) {
            mg_grants_store_entry_t *entry = &out->entries[i];
            if (entry->keep) continue;
            char path[4200];
            (void)snprintf(path, sizeof(path), "%s/%s.json", out->store, entry->sha256);
            if (unlink(path) != 0 && errno != ENOENT) {
                int saved = errno;
                if (removal == MAELYS_GIT_OK) {
                    mg_error_set(&failure, code_of(saved), saved, "cannot remove grants store entry %s: %s", path,
                                 strerror(saved));
                    removal = code_of(saved);
                }
                entry->keep = 1;
                --out->removed;
                out->freed_bytes -= entry->bytes;
            }
        }
        if (out->removed && !mg_sync_directory(out->store)) {
            int saved = errno;
            mg_error_set(error, MAELYS_GIT_ERR_IO, saved, "cannot make the purge of grants store %s durable: %s",
                         out->store, strerror(saved));
            result = MAELYS_GIT_ERR_IO;
        }
        if (result == MAELYS_GIT_OK && out->removed) result = audit_purge(journal, out, now_ms, error);
        if (result == MAELYS_GIT_OK && removal != MAELYS_GIT_OK) {
            if (error) *error = failure;
            result = removal;
        }
    }
    mg_store_close(journal);
    if (lock >= 0) (void)close(lock);
    if (result != MAELYS_GIT_OK) mg_grants_store_prune_clear(out);
    return result;
}

void mg_grants_store_prune_clear(mg_grants_store_prune_t *result) {
    if (!result) return;
    free(result->entries);
    result->entries = NULL;
    result->count = 0u;
}
