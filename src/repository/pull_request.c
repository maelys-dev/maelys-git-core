#include "internal.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
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
    char temporary_repository[PATH_MAX];
    maelys_git_pr_check_result_t result;
} prepared_pr_t;

static void trim_line(unsigned char *data, size_t *length) {
    while (*length && (data[*length - 1u] == '\n' || data[*length - 1u] == '\r'))
        data[--*length] = '\0';
}

static maelys_git_result_t capture_oid(const char *git,
                                       char *const argv[],
                                       char out[65],
                                       maelys_git_error_t *error) {
    unsigned char *data = NULL;
    size_t length = 0u;
    maelys_git_result_t result = mg_process_capture(git, argv, &data, &length, 256u, error);
    if (result != MAELYS_GIT_OK) return result;
    trim_line(data, &length);
    if (!mg_is_oid((char *)data)) {
        free(data);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "Git did not return an object identifier");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    memcpy(out, data, length + 1u);
    free(data);
    return MAELYS_GIT_OK;
}

static maelys_git_result_t capture_u64(const char *git,
                                       char *const argv[],
                                       uint64_t *out,
                                       maelys_git_error_t *error) {
    unsigned char *data = NULL;
    size_t length = 0u;
    maelys_git_result_t result = mg_process_capture(git, argv, &data, &length, 64u, error);
    if (result != MAELYS_GIT_OK) return result;
    trim_line(data, &length);
    char *end = NULL;
    errno = 0;
    uintmax_t value = strtoumax((char *)data, &end, 10);
    int valid = errno == 0 && end != (char *)data && *end == '\0' && value <= UINT64_MAX;
    free(data);
    if (!valid) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "Git did not return a valid unsigned counter");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    *out = (uint64_t)value;
    return MAELYS_GIT_OK;
}

static int repository_identity(const char *path, char out[128], struct stat *out_status) {
    struct stat status;
    if (!path || lstat(path, &status) != 0 || !S_ISDIR(status.st_mode) ||
        S_ISLNK(status.st_mode)) return 0;
    int written = snprintf(out, 128u, "%" PRIxMAX ":%" PRIxMAX,
                           (uintmax_t)status.st_dev, (uintmax_t)status.st_ino);
    if (written <= 0 || written >= 128) return 0;
    if (out_status) *out_status = status;
    return 1;
}

static maelys_git_result_t verify_repository_identity(
    const char *path,
    const char *expected,
    const char *role,
    maelys_git_error_t *error) {
    char current[128];
    if (!expected || !*expected || !repository_identity(path, current, NULL)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, errno,
                     "%s repository identity is unavailable", role);
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    if (strcmp(current, expected) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "%s repository identity changed; run a new pull request plan",
                     role);
        return MAELYS_GIT_ERR_PROCESS;
    }
    return MAELYS_GIT_OK;
}

static int config_key_has_prefix(const char *key, const char *prefix) {
    return strncmp(key, prefix, strlen(prefix)) == 0;
}

static int config_key_has_suffix(const char *key, const char *suffix) {
    size_t key_length = strlen(key);
    size_t suffix_length = strlen(suffix);
    return key_length >= suffix_length &&
           strcmp(key + key_length - suffix_length, suffix) == 0;
}

static int config_key_can_execute(const char *key) {
    return config_key_has_prefix(key, "include.") ||
           config_key_has_prefix(key, "includeif.") ||
           config_key_has_prefix(key, "alias.") ||
           config_key_has_prefix(key, "credential.") ||
           config_key_has_prefix(key, "filter.") ||
           config_key_has_prefix(key, "url.") ||
           config_key_has_prefix(key, "protocol.") ||
           config_key_has_prefix(key, "fsck.") ||
           strcmp(key, "core.hookspath") == 0 ||
           strcmp(key, "core.sshcommand") == 0 ||
           strcmp(key, "core.askpass") == 0 ||
           strcmp(key, "core.editor") == 0 ||
           strcmp(key, "core.pager") == 0 ||
           strcmp(key, "core.fsmonitor") == 0 ||
           strcmp(key, "core.gitproxy") == 0 ||
           strcmp(key, "core.worktree") == 0 ||
           strcmp(key, "core.alternaterefscommand") == 0 ||
           strcmp(key, "diff.external") == 0 ||
           strcmp(key, "gpg.program") == 0 ||
           strcmp(key, "gpg.ssh.defaultkeycommand") == 0 ||
           strcmp(key, "interactive.difffilter") == 0 ||
           strcmp(key, "uploadpack.packobjectshook") == 0 ||
           (config_key_has_prefix(key, "diff.") &&
            (config_key_has_suffix(key, ".command") ||
             config_key_has_suffix(key, ".textconv"))) ||
           (config_key_has_prefix(key, "remote.") &&
            (config_key_has_suffix(key, ".uploadpack") ||
             config_key_has_suffix(key, ".receivepack") ||
             config_key_has_suffix(key, ".proxy")));
}

static maelys_git_result_t require_direct_entry(
    const char *repository,
    const char *relative,
    int require_directory,
    const char *role,
    maelys_git_error_t *error) {
    char path[PATH_MAX];
    int written = snprintf(path, sizeof(path), "%s/%s", repository, relative);
    if (written < 0 || (size_t)written >= sizeof(path)) return MAELYS_GIT_ERR_LIMIT;
    struct stat status;
    if (lstat(path, &status) != 0 || S_ISLNK(status.st_mode) ||
        (require_directory ? !S_ISDIR(status.st_mode) : !S_ISREG(status.st_mode))) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, errno,
                     "%s repository %s must be a direct %s", role, relative,
                     require_directory ? "directory" : "regular file");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    return MAELYS_GIT_OK;
}

static maelys_git_result_t reject_repository_entry(
    const char *repository,
    const char *relative,
    const char *role,
    maelys_git_error_t *error) {
    char path[PATH_MAX];
    int written = snprintf(path, sizeof(path), "%s/%s", repository, relative);
    if (written < 0 || (size_t)written >= sizeof(path)) return MAELYS_GIT_ERR_LIMIT;
    struct stat status;
    if (lstat(path, &status) == 0) {
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0,
                     "%s repository uses forbidden Git object alternates", role);
        return MAELYS_GIT_ERR_DENIED;
    }
    if (errno != ENOENT) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot inspect %s repository alternates: %s", role,
                     strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}

static maelys_git_result_t validate_pr_repository(
    const char *git,
    const char *repository,
    const char *role,
    maelys_git_error_t *error) {
    maelys_git_result_t result = require_direct_entry(
        repository, "config", 0, role, error);
    if (result == MAELYS_GIT_OK)
        result = require_direct_entry(repository, "objects", 1, role, error);
    if (result == MAELYS_GIT_OK)
        result = reject_repository_entry(
            repository, "objects/info/alternates", role, error);
    if (result == MAELYS_GIT_OK)
        result = reject_repository_entry(
            repository, "objects/info/http-alternates", role, error);
    if (result != MAELYS_GIT_OK) return result;

    char *argv[] = {(char *)git, "--git-dir", (char *)repository, "config",
                    "--local", "--no-includes", "--name-only", "--list", NULL};
    unsigned char *keys = NULL;
    size_t length = 0u;
    result = mg_process_capture(git, argv, &keys, &length, 64u * 1024u, error);
    if (result != MAELYS_GIT_OK) return result;
    for (size_t offset = 0u; offset < length;) {
        size_t end = offset;
        while (end < length && keys[end] != '\n' && keys[end] != '\r') ++end;
        keys[end] = '\0';
        for (size_t i = offset; i < end; ++i)
            keys[i] = (unsigned char)tolower(keys[i]);
        if (end > offset && config_key_can_execute((char *)keys + offset)) {
            mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0,
                         "%s repository contains forbidden active Git configuration: %s",
                         role, keys + offset);
            free(keys);
            return MAELYS_GIT_ERR_DENIED;
        }
        offset = end + 1u;
        while (offset < length && (keys[offset] == '\n' || keys[offset] == '\r'))
            ++offset;
    }
    free(keys);
    return MAELYS_GIT_OK;
}

static maelys_git_result_t inspect_pr_source(
    const char *git,
    const char *target_repository,
    const char *head_oid,
    const maelys_git_pr_source_t *source,
    maelys_git_pr_check_result_t *result,
    maelys_git_error_t *error) {
    if (!source) return MAELYS_GIT_OK;
    if (!source->repository_path || !source->repository_name || !source->ref_name ||
        !maelys_git_repository_name_is_valid(source->repository_name) ||
        !maelys_git_ref_name_is_valid(source->ref_name) ||
        maelys_git_classify_ref(source->ref_name) != MAELYS_GIT_REF_BRANCH) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0,
                     "cross-repository PR requires a valid source repository and branch ref");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    maelys_git_result_t validation = validate_pr_repository(
        git, source->repository_path, "source", error);
    if (validation != MAELYS_GIT_OK) return validation;
    struct stat source_status, target_status;
    if (!repository_identity(source->repository_path, result->source_identity,
                             &source_status) ||
        !repository_identity(target_repository, (char[128]){0}, &target_status)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, errno,
                     "PR source or target is not a direct repository directory");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    if (source_status.st_dev == target_status.st_dev &&
        source_status.st_ino == target_status.st_ino) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0,
                     "cross-repository PR source must differ from the target repository");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    char source_commit[MAELYS_GIT_MAX_REF + 16u];
    int commit_length = snprintf(source_commit, sizeof(source_commit), "%s^{commit}",
                                 source->ref_name);
    if (commit_length < 0 || (size_t)commit_length >= sizeof(source_commit))
        return MAELYS_GIT_ERR_LIMIT;
    char *oid_argv[] = {(char *)git, "--git-dir", (char *)source->repository_path,
                        "rev-parse", "--verify", source_commit, NULL};
    maelys_git_result_t rc = capture_oid(git, oid_argv, result->source_oid, error);
    if (rc != MAELYS_GIT_OK) return rc;
    if (strcmp(result->source_oid, head_oid) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "source branch does not resolve to the requested PR head");
        return MAELYS_GIT_ERR_PROCESS;
    }
    uint64_t object_count = 0u, object_bytes = 0u;
    char *count_argv[] = {(char *)git, "--git-dir", (char *)source->repository_path,
                          "rev-list", "--objects", "--count", result->source_oid, NULL};
    rc = capture_u64(git, count_argv, &object_count, error);
    if (rc != MAELYS_GIT_OK) return rc;
    char *bytes_argv[] = {(char *)git, "--git-dir", (char *)source->repository_path,
                          "rev-list", "--objects", "--disk-usage", result->source_oid, NULL};
    rc = capture_u64(git, bytes_argv, &object_bytes, error);
    if (rc != MAELYS_GIT_OK) return rc;
    size_t max_objects = source->max_objects ? source->max_objects :
        MAELYS_GIT_PR_DEFAULT_MAX_SOURCE_OBJECTS;
    uint64_t max_bytes = source->max_bytes ? source->max_bytes :
        MAELYS_GIT_PR_DEFAULT_MAX_SOURCE_BYTES;
    if (object_count > max_objects || object_bytes > max_bytes) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                     "PR source exceeds quarantine quota (%" PRIu64 "/%zu objects, %" PRIu64 "/%" PRIu64 " bytes)",
                     object_count, max_objects, object_bytes, max_bytes);
        return MAELYS_GIT_ERR_LIMIT;
    }
    result->cross_repository = 1;
    result->source_object_count = (size_t)object_count;
    result->source_object_bytes = object_bytes;
    if (!mg_copy_string(result->source_repository, sizeof(result->source_repository),
                        source->repository_name) ||
        !mg_copy_string(result->source_ref, sizeof(result->source_ref), source->ref_name))
        return MAELYS_GIT_ERR_LIMIT;
    return MAELYS_GIT_OK;
}

static maelys_git_result_t fetch_pr_source(const char *git,
                                           const maelys_git_pr_source_t *source,
                                           prepared_pr_t *prepared,
                                           maelys_git_error_t *error) {
    if (!source) return MAELYS_GIT_OK;
    char refspec[MAELYS_GIT_MAX_REF * 2u];
    int refspec_length = snprintf(refspec, sizeof(refspec), "+%s:%s",
                                  source->ref_name,
                                  "refs/maelys/quarantine/source");
    if (refspec_length < 0 || (size_t)refspec_length >= sizeof(refspec))
        return MAELYS_GIT_ERR_LIMIT;
    char *fetch_argv[] = {
        (char *)git, "--git-dir", prepared->temporary_repository,
        "fetch", "--quiet", "--force", "--no-tags", "--no-write-fetch-head", "--",
        (char *)source->repository_path, refspec, NULL};
    maelys_git_result_t rc = mg_process_run(git, fetch_argv, NULL, error);
    if (rc != MAELYS_GIT_OK) return rc;
    char *fetched_argv[] = {
        (char *)git, "--git-dir", prepared->temporary_repository,
        "rev-parse", "--verify", "refs/maelys/quarantine/source^{commit}", NULL};
    char fetched_oid[65];
    rc = capture_oid(git, fetched_argv, fetched_oid, error);
    if (rc != MAELYS_GIT_OK) return rc;
    if (strcmp(fetched_oid, prepared->result.source_oid) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "source branch changed while populating PR quarantine");
        return MAELYS_GIT_ERR_PROCESS;
    }
    char *fsck_argv[] = {
        (char *)git, "--git-dir", prepared->temporary_repository,
        "fsck", "--strict", "--connectivity-only", "--no-dangling", "--no-progress",
        prepared->result.source_oid, NULL};
    rc = mg_process_run(git, fsck_argv, NULL, error);
    if (rc != MAELYS_GIT_OK) return rc;
    return verify_repository_identity(source->repository_path,
                                      prepared->result.source_identity,
                                      "source", error);
}

static int pr_id_is_valid(const char *pr_id) {
    if (!pr_id || !*pr_id || strlen(pr_id) >= 128u) return 0;
    for (const unsigned char *p = (const unsigned char *)pr_id; *p; ++p)
        if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
               (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' || *p == '-'))
            return 0;
    return 1;
}

static maelys_git_result_t set_pr_refs(maelys_git_pr_check_result_t *result,
                                       const char *pr_id,
                                       maelys_git_error_t *error) {
    if (!pr_id) return MAELYS_GIT_OK;
    if (!pr_id_is_valid(pr_id)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0,
                     "PR ID must contain only letters, digits, '.', '_' or '-'");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    int head_length = snprintf(result->pr_head_ref, sizeof(result->pr_head_ref),
                               "refs/maelys/pulls/%s/head", pr_id);
    int merged_length = snprintf(result->pr_merged_ref, sizeof(result->pr_merged_ref),
                                 "refs/maelys/pulls/%s/merged", pr_id);
    if (head_length < 0 || (size_t)head_length >= sizeof(result->pr_head_ref) ||
        merged_length < 0 || (size_t)merged_length >= sizeof(result->pr_merged_ref) ||
        !mg_copy_string(result->pr_id, sizeof(result->pr_id), pr_id)) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "PR reference is too long");
        return MAELYS_GIT_ERR_LIMIT;
    }
    if (!maelys_git_ref_name_is_valid(result->pr_head_ref) ||
        !maelys_git_ref_name_is_valid(result->pr_merged_ref)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0,
                     "PR ID does not form a valid Git reference");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    return MAELYS_GIT_OK;
}

static maelys_git_result_t optional_ref_oid(const char *git,
                                            const char *repository,
                                            const char *ref,
                                            char out[65],
                                            int *out_exists,
                                            maelys_git_error_t *error) {
    char *argv[] = {(char *)git, "--git-dir", (char *)repository,
                    "rev-parse", "--verify", "--quiet", (char *)ref, NULL};
    unsigned char *data = NULL;
    size_t length = 0u;
    int status = 0;
    maelys_git_result_t result = mg_process_capture_status(
        git, argv, &data, &length, 256u, &status, error);
    if (result != MAELYS_GIT_OK) return result;
    if (status == 1) {
        free(data);
        out[0] = '\0';
        *out_exists = 0;
        return MAELYS_GIT_OK;
    }
    if (status != 0) {
        free(data);
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "git rev-parse failed with status %d", status);
        return MAELYS_GIT_ERR_PROCESS;
    }
    trim_line(data, &length);
    if (!mg_is_oid((char *)data)) {
        free(data);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "Git did not return an object identifier for PR ref");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    memcpy(out, data, length + 1u);
    free(data);
    *out_exists = 1;
    return MAELYS_GIT_OK;
}

static maelys_git_result_t update_pr_refs(const char *git,
                                          const char *repository,
                                          const char *base_ref,
                                          const char *base_oid,
                                          const char *head_oid,
                                          const maelys_git_pr_check_result_t *result,
                                          maelys_git_error_t *error) {
    char old_head[65];
    char old_merged[65];
    int head_exists = 0;
    int merged_exists = 0;
    maelys_git_result_t rc = optional_ref_oid(
        git, repository, result->pr_head_ref, old_head, &head_exists, error);
    if (rc == MAELYS_GIT_OK)
        rc = optional_ref_oid(git, repository, result->pr_merged_ref,
                              old_merged, &merged_exists, error);
    if (rc != MAELYS_GIT_OK) return rc;
    size_t oid_length = strlen(base_oid);
    if (!head_exists) { memset(old_head, '0', oid_length); old_head[oid_length] = '\0'; }
    if (!merged_exists) { memset(old_merged, '0', oid_length); old_merged[oid_length] = '\0'; }

    FILE *input = tmpfile();
    FILE *output = tmpfile();
    if (!input || !output) {
        if (input) fclose(input);
        if (output) fclose(output);
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot create Git reference transaction stream: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    int failed = fprintf(input,
        "start\n"
        "update %s %s %s\n"
        "update %s %s %s\n"
        "update %s %s %s\n"
        "prepare\ncommit\n",
        base_ref, result->prepared_oid, base_oid,
        result->pr_head_ref, head_oid, old_head,
        result->pr_merged_ref, result->prepared_oid, old_merged) < 0;
    if (failed) {
        fclose(input);
        fclose(output);
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot write Git reference transaction");
        return MAELYS_GIT_ERR_IO;
    }
    char *argv[] = {(char *)git, "--git-dir", (char *)repository,
                    "update-ref", "--stdin", NULL};
    int status = 0;
    rc = mg_process_filter_spool_status(
        git, argv, input, output, 4096u, &status, error);
    fclose(input);
    fclose(output);
    if (rc != MAELYS_GIT_OK) return rc;
    if (status != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "atomic PR reference transaction failed with status %d", status);
        return MAELYS_GIT_ERR_PROCESS;
    }
    return MAELYS_GIT_OK;
}

static maelys_git_result_t capture_commit_epoch(const char *git,
                                                const char *repository,
                                                const char *oid,
                                                long long *out_epoch,
                                                maelys_git_error_t *error) {
    char *argv[] = {(char *)git, "--git-dir", (char *)repository,
                    "show", "-s", "--format=%ct", (char *)oid, NULL};
    unsigned char *data = NULL;
    size_t length = 0u;
    maelys_git_result_t result = mg_process_capture(git, argv, &data, &length, 64u, error);
    if (result != MAELYS_GIT_OK) return result;
    trim_line(data, &length);
    char *end = NULL;
    errno = 0;
    long long epoch = strtoll((char *)data, &end, 10);
    int valid = errno == 0 && end != (char *)data && *end == '\0' && epoch > 0;
    free(data);
    if (!valid) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "Git returned an invalid commit timestamp");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    *out_epoch = epoch;
    return MAELYS_GIT_OK;
}

static maelys_git_result_t create_deterministic_commit(
    const char *git,
    const char *repository,
    const char *tree_oid,
    const char *base_oid,
    const char *head_oid,
    int include_head_parent,
    const char *message,
    char out_oid[65],
    maelys_git_error_t *error) {
    long long base_epoch = 0;
    long long head_epoch = 0;
    maelys_git_result_t result = capture_commit_epoch(
        git, repository, base_oid, &base_epoch, error);
    if (result != MAELYS_GIT_OK) return result;
    result = capture_commit_epoch(git, repository, head_oid, &head_epoch, error);
    if (result != MAELYS_GIT_OK) return result;
    long long epoch = base_epoch > head_epoch ? base_epoch : head_epoch;
    if (epoch == LLONG_MAX) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                     "parent commit timestamp cannot be incremented");
        return MAELYS_GIT_ERR_LIMIT;
    }
    ++epoch;
    char template[] = "/tmp/maelys-git-commit-XXXXXX";
    int descriptor = mkstemp(template);
    if (descriptor < 0) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot create deterministic commit input: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    FILE *stream = fdopen(descriptor, "wb");
    if (!stream) {
        close(descriptor);
        unlink(template);
        return MAELYS_GIT_ERR_IO;
    }
    int failed = fprintf(stream, "tree %s\nparent %s\n", tree_oid, base_oid) < 0;
    if (!failed && include_head_parent)
        failed = fprintf(stream, "parent %s\n", head_oid) < 0;
    if (!failed)
        failed = fprintf(stream,
                         "author Maelys Forge <forge@maelys.local> %lld +0000\n"
                         "committer Maelys Forge <forge@maelys.local> %lld +0000\n\n",
                         epoch, epoch) < 0;
    size_t message_length = strlen(message);
    if (!failed && fwrite(message, 1u, message_length, stream) != message_length) failed = 1;
    if (!failed && (message_length == 0u || message[message_length - 1u] != '\n') &&
        fputc('\n', stream) == EOF) failed = 1;
    if (!failed && fflush(stream) != 0) failed = 1;
    if (fclose(stream) != 0) failed = 1;
    if (failed) {
        unlink(template);
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot write deterministic commit input");
        return MAELYS_GIT_ERR_IO;
    }
    char *hash_argv[] = {(char *)git, "--git-dir", (char *)repository,
                         "hash-object", "-t", "commit", "-w", "--", template, NULL};
    result = capture_oid(git, hash_argv, out_oid, error);
    unlink(template);
    return result;
}

static maelys_git_result_t parse_merge_tree(unsigned char *data,
                                            size_t length,
                                            maelys_git_pr_check_result_t *result,
                                            maelys_git_error_t *error) {
    size_t oid_length = 0u;
    while (oid_length < length && oid_length <= 64u && data[oid_length] != '\0')
        ++oid_length;
    if (oid_length >= length || oid_length > 64u || !mg_is_oid((char *)data)) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid git merge-tree output");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    memcpy(result->merge_tree_oid, data, oid_length + 1u);
    size_t count = 0u;
    for (size_t offset = oid_length + 1u; offset < length;) {
        size_t end = offset;
        while (end < length && data[end] != '\0') ++end;
        if (end == length || end == offset) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid merge conflict path stream");
            return MAELYS_GIT_ERR_PROTOCOL;
        }
        if (count >= MAELYS_GIT_MAX_CONFLICT_PATHS) {
            mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "too many merge conflict paths");
            return MAELYS_GIT_ERR_LIMIT;
        }
        char **grown = realloc(result->conflict_paths.items, (count + 1u) * sizeof(*grown));
        if (!grown) return MAELYS_GIT_ERR_IO;
        result->conflict_paths.items = grown;
        grown[count] = malloc(end - offset + 1u);
        if (!grown[count]) return MAELYS_GIT_ERR_IO;
        memcpy(grown[count], data + offset, end - offset);
        grown[count][end - offset] = '\0';
        ++count;
        offset = end + 1u;
    }
    result->conflict_paths.count = count;
    return MAELYS_GIT_OK;
}

static void prepared_clear(prepared_pr_t *prepared) {
    maelys_git_pr_check_result_clear(&prepared->result);
    if (prepared->temporary_repository[0])
        (void)mg_remove_tree(prepared->temporary_repository);
    memset(prepared, 0, sizeof(*prepared));
}

static maelys_git_result_t prepare_pr(const char *git,
                                      const char *repository,
                                      const char *base_oid,
                                      const char *head_oid,
                                      maelys_git_merge_style_t style,
                                      const char *message,
                                      const maelys_git_pr_source_t *source,
                                      prepared_pr_t *prepared,
                                      maelys_git_error_t *error) {
    memset(prepared, 0, sizeof(*prepared));
    if (!git || !repository || !mg_is_oid(base_oid) || !mg_is_oid(head_oid) ||
        mg_is_zero_oid(base_oid) || mg_is_zero_oid(head_oid) ||
        style < MAELYS_GIT_MERGE_FAST_FORWARD || style > MAELYS_GIT_MERGE_SQUASH)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    if (!repository_identity(repository, prepared->result.target_identity, NULL)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, errno,
                     "target repository identity is unavailable");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    maelys_git_result_t validation = validate_pr_repository(
        git, repository, "target", error);
    if (validation != MAELYS_GIT_OK) return validation;
    char template[] = "/tmp/maelys-git-pr-XXXXXX";
    int temporary_fd = mkstemp(template);
    if (temporary_fd < 0) return MAELYS_GIT_ERR_IO;
    close(temporary_fd);
    if (unlink(template) != 0 ||
        !mg_copy_string(prepared->temporary_repository,
                        sizeof(prepared->temporary_repository), template))
        return MAELYS_GIT_ERR_IO;
    char *clone_argv[] = {(char *)git, "clone", "--quiet", "--bare", "--shared",
                          (char *)repository, prepared->temporary_repository, NULL};
    maelys_git_result_t rc = mg_process_run(git, clone_argv, NULL, error);
    if (rc != MAELYS_GIT_OK) { prepared_clear(prepared); return rc; }
    rc = inspect_pr_source(git, repository, head_oid, source, &prepared->result, error);
    if (rc == MAELYS_GIT_OK)
        rc = fetch_pr_source(git, source, prepared, error);
    if (rc != MAELYS_GIT_OK) { prepared_clear(prepared); return rc; }
    char *base_argv[] = {(char *)git, "--git-dir", prepared->temporary_repository,
                         "merge-base", (char *)base_oid, (char *)head_oid, NULL};
    rc = capture_oid(git, base_argv, prepared->result.merge_base_oid, error);
    if (rc != MAELYS_GIT_OK) { prepared_clear(prepared); return rc; }

    int status = 0;
    char *empty_argv[] = {(char *)git, "--git-dir", prepared->temporary_repository,
                          "diff", "--quiet", prepared->result.merge_base_oid,
                          (char *)head_oid, "--", NULL};
    rc = mg_process_run_status(git, empty_argv, &status, error);
    if (rc != MAELYS_GIT_OK || (status != 0 && status != 1)) {
        if (rc == MAELYS_GIT_OK)
            mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0, "git diff failed with status %d", status);
        prepared_clear(prepared);
        return rc == MAELYS_GIT_OK ? MAELYS_GIT_ERR_PROCESS : rc;
    }
    prepared->result.empty = status == 0;
    rc = maelys_git_repository_visit_changes(
        git, prepared->temporary_repository, prepared->result.merge_base_oid, head_oid,
        NULL, NULL, &prepared->result.changes, error);
    if (rc != MAELYS_GIT_OK) { prepared_clear(prepared); return rc; }

    if (style == MAELYS_GIT_MERGE_FAST_FORWARD) {
        char *ancestor_argv[] = {(char *)git, "--git-dir", prepared->temporary_repository,
                                 "merge-base", "--is-ancestor", (char *)base_oid,
                                 (char *)head_oid, NULL};
        rc = mg_process_run_status(git, ancestor_argv, &status, error);
        if (rc != MAELYS_GIT_OK || (status != 0 && status != 1)) {
            prepared_clear(prepared);
            return rc == MAELYS_GIT_OK ? MAELYS_GIT_ERR_PROCESS : rc;
        }
        prepared->result.mergeable = status == 0;
        if (prepared->result.mergeable) {
            char treeish[72];
            (void)snprintf(treeish, sizeof(treeish), "%s^{tree}", head_oid);
            char *tree_argv[] = {(char *)git, "--git-dir", prepared->temporary_repository,
                                 "rev-parse", treeish, NULL};
            rc = capture_oid(git, tree_argv, prepared->result.merge_tree_oid, error);
            if (rc == MAELYS_GIT_OK)
                (void)mg_copy_string(prepared->result.prepared_oid,
                                     sizeof(prepared->result.prepared_oid), head_oid);
        }
        if (rc != MAELYS_GIT_OK) prepared_clear(prepared);
        return rc;
    }

    char *merge_tree_argv[] = {(char *)git, "--git-dir", prepared->temporary_repository,
                               "merge-tree", "--write-tree", "-z", "--name-only",
                               "--no-messages", (char *)base_oid, (char *)head_oid, NULL};
    unsigned char *merge_output = NULL;
    size_t merge_length = 0u;
    rc = mg_process_capture_status(git, merge_tree_argv, &merge_output, &merge_length,
                                   4u * 1024u * 1024u, &status, error);
    if (rc != MAELYS_GIT_OK || (status != 0 && status != 1)) {
        free(merge_output); prepared_clear(prepared);
        return rc == MAELYS_GIT_OK ? MAELYS_GIT_ERR_PROCESS : rc;
    }
    rc = parse_merge_tree(merge_output, merge_length, &prepared->result, error);
    free(merge_output);
    if (rc != MAELYS_GIT_OK) { prepared_clear(prepared); return rc; }
    prepared->result.mergeable = status == 0;
    if (!prepared->result.mergeable || prepared->result.empty) return MAELYS_GIT_OK;

    const char *commit_message = message && *message ? message :
        (style == MAELYS_GIT_MERGE_SQUASH ? "Squash merge" : "Merge pull request");
    rc = create_deterministic_commit(
        git, prepared->temporary_repository, prepared->result.merge_tree_oid,
        base_oid, head_oid, style == MAELYS_GIT_MERGE_COMMIT,
        commit_message, prepared->result.prepared_oid, error);
    if (rc != MAELYS_GIT_OK) { prepared_clear(prepared); return rc; }
    char *ref_argv[] = {(char *)git, "--git-dir", prepared->temporary_repository,
                        "update-ref", "refs/maelys/prepared",
                        prepared->result.prepared_oid, NULL};
    rc = mg_process_run(git, ref_argv, NULL, error);
    if (rc != MAELYS_GIT_OK) prepared_clear(prepared);
    return rc;
}

void maelys_git_pr_check_result_clear(maelys_git_pr_check_result_t *result) {
    if (!result) return;
    maelys_git_path_list_clear(&result->conflict_paths);
    memset(result, 0, sizeof(*result));
}

maelys_git_result_t maelys_git_pr_check(
    const char *git_executable, const char *repository_path,
    const char *base_oid, const char *head_oid, maelys_git_merge_style_t style,
    const char *message, maelys_git_pr_check_result_t *out_result,
    maelys_git_error_t *error) {
    return maelys_git_pr_check_with_source(
        git_executable, repository_path, base_oid, head_oid, style, message,
        NULL, out_result, error);
}

maelys_git_result_t maelys_git_pr_check_with_source(
    const char *git_executable, const char *repository_path,
    const char *base_oid, const char *head_oid, maelys_git_merge_style_t style,
    const char *message, const maelys_git_pr_source_t *source,
    maelys_git_pr_check_result_t *out_result, maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!out_result) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_result, 0, sizeof(*out_result));
    prepared_pr_t prepared;
    maelys_git_result_t result = prepare_pr(git_executable, repository_path, base_oid,
                                            head_oid, style, message, source,
                                            &prepared, error);
    if (result != MAELYS_GIT_OK) return result;
    result = verify_repository_identity(repository_path,
                                        prepared.result.target_identity,
                                        "target", error);
    if (result != MAELYS_GIT_OK) {
        prepared_clear(&prepared);
        return result;
    }
    *out_result = prepared.result;
    memset(&prepared.result, 0, sizeof(prepared.result));
    prepared_clear(&prepared);
    return MAELYS_GIT_OK;
}

typedef struct {
    maelys_git_policy_t *policy;
    const char *repository;
    const char *principal;
    const char *ref;
} pr_auth_context_t;

static maelys_git_result_t authorize_pr_request(pr_auth_context_t *context,
                                                const maelys_git_change_t *change,
                                                const maelys_git_change_summary_t *summary,
                                                maelys_git_error_t *error) {
    const char *paths[2] = {change ? change->path : NULL,
                            change && change->old_path[0] ? change->old_path : NULL};
    maelys_git_policy_request_t request = {
        .request_id = context->ref, .principal = context->principal,
        .repository = context->repository, .operation = "merge",
        .ref_name = context->ref, .ref_kind = "branch", .update_kind = "fast_forward",
        .change_kind = change ? maelys_git_change_kind_name(change->kind) : NULL,
        .old_path = change && change->old_path[0] ? change->old_path : NULL,
        .paths = change ? paths : NULL,
        .path_count = change ? (change->old_path[0] ? 2u : 1u) : 0u,
        .has_change_details = change != NULL,
        .change_blob_size = change ? change->new_blob_size : 0u,
        .old_mode = change ? change->old_mode : 0u,
        .new_mode = change ? change->new_mode : 0u,
        .change_binary = change ? change->binary : 0,
        .change_symlink = change ? change->symlink : 0,
        .change_submodule = change ? change->submodule : 0,
        .change_lfs_pointer = change ? change->lfs_pointer : 0,
        .has_summary = summary != NULL,
    };
    if (summary) {
        request.changed_count = summary->changed_count;
        request.added_count = summary->added_count;
        request.modified_count = summary->modified_count;
        request.deleted_count = summary->deleted_count;
        request.renamed_count = summary->renamed_count;
        request.max_new_blob_size = summary->max_new_blob_size;
        request.total_new_blob_size = summary->total_new_blob_size;
        request.has_binary = summary->has_binary;
    }
    maelys_git_policy_decision_t decision;
    maelys_git_result_t result = maelys_git_policy_authorize(context->policy, &request,
                                                             &decision, error);
    if (result != MAELYS_GIT_OK) return result;
    if (decision.allowed) return MAELYS_GIT_OK;
    mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0, "%s", decision.reason);
    return MAELYS_GIT_ERR_DENIED;
}

static maelys_git_result_t authorize_pr_change(const maelys_git_change_t *change,
                                               void *opaque,
                                               maelys_git_error_t *error) {
    return authorize_pr_request(opaque, change, NULL, error);
}

static maelys_git_result_t authorize_pr(const char *git, const char *repository_path,
                                        const char *base, const char *head,
                                        const maelys_git_change_summary_t *summary,
                                        pr_auth_context_t *context,
                                        maelys_git_error_t *error) {
    maelys_git_change_summary_t ignored;
    maelys_git_result_t result = authorize_pr_request(context, NULL, NULL, error);
    if (result == MAELYS_GIT_OK)
        result = maelys_git_repository_visit_changes(git, repository_path, base, head,
                                                      authorize_pr_change, context, &ignored, error);
    if (result == MAELYS_GIT_OK)
        result = authorize_pr_request(context, NULL, summary, error);
    return result;
}

static maelys_git_result_t promote_pr_objects(
    const char *git,
    const char *target_repository,
    const prepared_pr_t *prepared,
    maelys_git_merge_style_t style,
    maelys_git_error_t *error) {
    char *argv[14];
    size_t argc = 0u;
    argv[argc++] = (char *)git;
    argv[argc++] = "--git-dir";
    argv[argc++] = (char *)target_repository;
    argv[argc++] = "fetch";
    argv[argc++] = "--quiet";
    argv[argc++] = "--force";
    argv[argc++] = "--no-tags";
    argv[argc++] = "--no-write-fetch-head";
    argv[argc++] = "--";
    argv[argc++] = (char *)prepared->temporary_repository;
    if (prepared->result.cross_repository)
        argv[argc++] = "refs/maelys/quarantine/source";
    if (style != MAELYS_GIT_MERGE_FAST_FORWARD)
        argv[argc++] = "refs/maelys/prepared";
    argv[argc] = NULL;
    if (!prepared->result.cross_repository && style == MAELYS_GIT_MERGE_FAST_FORWARD)
        return MAELYS_GIT_OK;
    maelys_git_result_t rc = mg_process_run(git, argv, NULL, error);
    if (rc != MAELYS_GIT_OK) return rc;
    char prepared_commit[80];
    int length = snprintf(prepared_commit, sizeof(prepared_commit), "%s^{commit}",
                          prepared->result.prepared_oid);
    if (length < 0 || (size_t)length >= sizeof(prepared_commit))
        return MAELYS_GIT_ERR_LIMIT;
    char *verify_prepared[] = {(char *)git, "--git-dir", (char *)target_repository,
                               "cat-file", "-e", prepared_commit, NULL};
    rc = mg_process_run(git, verify_prepared, NULL, error);
    if (rc != MAELYS_GIT_OK) return rc;
    if (prepared->result.cross_repository && prepared->result.pr_id[0]) {
        char source_commit[80];
        length = snprintf(source_commit, sizeof(source_commit), "%s^{commit}",
                          prepared->result.source_oid);
        if (length < 0 || (size_t)length >= sizeof(source_commit))
            return MAELYS_GIT_ERR_LIMIT;
        char *verify_source[] = {(char *)git, "--git-dir", (char *)target_repository,
                                 "cat-file", "-e", source_commit, NULL};
        rc = mg_process_run(git, verify_source, NULL, error);
    }
    return rc;
}

maelys_git_result_t maelys_git_pr_merge(
    const char *git, const char *repository_path, const char *repository_name,
    const char *base_ref, const char *base_oid, const char *head_oid,
    maelys_git_merge_style_t style, const char *message, const char *principal,
    const maelys_git_pr_gates_t *gates, maelys_git_policy_t *policy, const char *pr_id,
    const char *expected_target_identity, const char *expected_prepared_oid,
    const char *expected_policy_fingerprint, int apply,
    maelys_git_pr_check_result_t *out_result, maelys_git_error_t *error) {
    return maelys_git_pr_merge_with_source(
        git, repository_path, repository_name, base_ref, base_oid, head_oid,
        style, message, principal, gates, policy, pr_id, NULL,
        expected_target_identity, expected_prepared_oid, expected_policy_fingerprint,
        apply, out_result, error);
}

maelys_git_result_t maelys_git_pr_merge_with_source(
    const char *git, const char *repository_path, const char *repository_name,
    const char *base_ref, const char *base_oid, const char *head_oid,
    maelys_git_merge_style_t style, const char *message, const char *principal,
    const maelys_git_pr_gates_t *gates, maelys_git_policy_t *policy, const char *pr_id,
    const maelys_git_pr_source_t *source,
    const char *expected_target_identity, const char *expected_prepared_oid,
    const char *expected_policy_fingerprint, int apply,
    maelys_git_pr_check_result_t *out_result, maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!repository_name || !base_ref || !maelys_git_ref_name_is_valid(base_ref) ||
        maelys_git_classify_ref(base_ref) != MAELYS_GIT_REF_BRANCH ||
        !principal || !*principal || !gates || !policy || !out_result)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_result, 0, sizeof(*out_result));
    if (gates->blocking_review || !gates->status_checks_passed ||
        gates->approvals < gates->required_approvals) {
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0, "pull request gates are not satisfied");
        return MAELYS_GIT_ERR_DENIED;
    }
    prepared_pr_t prepared;
    maelys_git_result_t result = prepare_pr(git, repository_path, base_oid, head_oid,
                                            style, message, source, &prepared, error);
    if (result != MAELYS_GIT_OK) return result;
    result = verify_repository_identity(repository_path,
                                        prepared.result.target_identity,
                                        "target", error);
    if (result != MAELYS_GIT_OK) {
        prepared_clear(&prepared);
        return result;
    }
    if (apply && (!expected_target_identity || !*expected_target_identity ||
                  strcmp(expected_target_identity,
                         prepared.result.target_identity) != 0)) {
        maelys_git_result_t identity_error =
            expected_target_identity && *expected_target_identity ?
            MAELYS_GIT_ERR_PROCESS : MAELYS_GIT_ERR_INVALID_ARGUMENT;
        mg_error_set(error, identity_error, 0,
                     expected_target_identity && *expected_target_identity ?
                     "target repository identity changed; run a new pull request plan" :
                     "apply requires the target repository identity returned by plan");
        prepared_clear(&prepared);
        return identity_error;
    }
    if (source && apply &&
        (!source->expected_identity || !*source->expected_identity ||
         strcmp(source->expected_identity, prepared.result.source_identity) != 0)) {
        maelys_git_result_t identity_error =
            source->expected_identity && *source->expected_identity ?
            MAELYS_GIT_ERR_PROCESS : MAELYS_GIT_ERR_INVALID_ARGUMENT;
        mg_error_set(error, identity_error, 0,
                     source->expected_identity && *source->expected_identity ?
                     "source repository identity changed; run a new pull request plan" :
                     "cross-repository apply requires the source identity returned by plan");
        prepared_clear(&prepared);
        return identity_error;
    }
    result = maelys_git_policy_fingerprint(policy, prepared.result.policy_fingerprint,
                                           error);
    if (result != MAELYS_GIT_OK) {
        prepared_clear(&prepared);
        return result;
    }
    result = set_pr_refs(&prepared.result, pr_id, error);
    if (result != MAELYS_GIT_OK) {
        prepared_clear(&prepared);
        return result;
    }
    if (apply && (!expected_prepared_oid || !*expected_prepared_oid ||
                  !expected_policy_fingerprint || !*expected_policy_fingerprint)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0,
                     "apply requires the prepared OID and policy fingerprint returned by plan");
        prepared_clear(&prepared);
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    if (apply && strcmp(expected_prepared_oid, prepared.result.prepared_oid) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "prepared result changed; run a new pull request plan");
        prepared_clear(&prepared);
        return MAELYS_GIT_ERR_PROCESS;
    }
    if (apply && strcmp(expected_policy_fingerprint,
                        prepared.result.policy_fingerprint) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "policy set changed; run a new pull request plan");
        prepared_clear(&prepared);
        return MAELYS_GIT_ERR_PROCESS;
    }
    if (!prepared.result.mergeable || prepared.result.empty) {
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0,
                     prepared.result.empty ? "pull request is empty" : "pull request is not mergeable");
        prepared_clear(&prepared);
        return MAELYS_GIT_ERR_DENIED;
    }
    pr_auth_context_t auth = {.policy = policy, .repository = repository_name,
                              .principal = principal, .ref = base_ref};
    result = authorize_pr(git, prepared.temporary_repository,
                          prepared.result.merge_base_oid, head_oid,
                          &prepared.result.changes, &auth, error);
    if (result != MAELYS_GIT_OK) { prepared_clear(&prepared); return result; }
    char *current_argv[] = {(char *)git, "--git-dir", (char *)repository_path,
                            "rev-parse", "--verify", (char *)base_ref, NULL};
    char current[65];
    result = capture_oid(git, current_argv, current, error);
    if (result != MAELYS_GIT_OK || strcmp(current, base_oid) != 0) {
        if (result == MAELYS_GIT_OK)
            mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0, "base reference changed; refresh the pull request");
        prepared_clear(&prepared);
        return result == MAELYS_GIT_OK ? MAELYS_GIT_ERR_PROCESS : result;
    }
    if (apply) {
        /* Authorization is deliberately repeated immediately before the state change. */
        result = authorize_pr(git, prepared.temporary_repository,
                              prepared.result.merge_base_oid, head_oid,
                              &prepared.result.changes, &auth, error);
        if (result == MAELYS_GIT_OK)
            result = verify_repository_identity(repository_path,
                                                prepared.result.target_identity,
                                                "target", error);
        if (result == MAELYS_GIT_OK)
            result = validate_pr_repository(git, repository_path,
                                            "target", error);
        if (result == MAELYS_GIT_OK && source)
            result = verify_repository_identity(source->repository_path,
                                                prepared.result.source_identity,
                                                "source", error);
        if (result == MAELYS_GIT_OK && source)
            result = validate_pr_repository(git, source->repository_path,
                                            "source", error);
        if (result == MAELYS_GIT_OK)
            result = promote_pr_objects(git, repository_path, &prepared, style, error);
        if (result == MAELYS_GIT_OK) {
            if (prepared.result.pr_id[0])
                result = update_pr_refs(git, repository_path, base_ref, base_oid,
                                        head_oid, &prepared.result, error);
            else
                result = maelys_git_repository_update_ref(git, repository_path, base_ref,
                                                           prepared.result.prepared_oid,
                                                           base_oid, error);
        }
    }
    if (result == MAELYS_GIT_OK) {
        *out_result = prepared.result;
        memset(&prepared.result, 0, sizeof(prepared.result));
    }
    prepared_clear(&prepared);
    return result;
}
