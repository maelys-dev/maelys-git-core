#include "internal.h"

#include <maelys/cli/digest.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MG_MIRROR_MAX_REFS_BYTES (16u * 1024u * 1024u)

typedef struct {
    int symbolic;
    char value[MAELYS_GIT_MAX_REF];
} mirror_head_t;

static maelys_git_result_t mirror_head(const char *git_executable,
                                       const char *repository_path,
                                       mirror_head_t *out,
                                       maelys_git_error_t *error) {
    memset(out, 0, sizeof(*out));
    unsigned char *captured = NULL;
    size_t length = 0u;
    int status = 0;
    char *symbolic_argv[] = {
        (char *)git_executable, "--git-dir", (char *)repository_path,
        "symbolic-ref", "-q", "HEAD", NULL};
    maelys_git_result_t result = mg_process_capture_status(
        git_executable, symbolic_argv, &captured, &length,
        MAELYS_GIT_MAX_REF - 1u, &status, error);
    if (result != MAELYS_GIT_OK) return result;
    if (status == 0) {
        mg_trim_line_endings(captured, &length);
        out->symbolic = 1;
        int copied = length > 0u && length < sizeof(out->value) &&
                     mg_copy_string(out->value, sizeof(out->value), (char *)captured);
        free(captured);
        if (!copied || !maelys_git_ref_name_is_valid(out->value)) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                         "repository HEAD is not a valid symbolic reference");
            return MAELYS_GIT_ERR_PROTOCOL;
        }
        return MAELYS_GIT_OK;
    }
    free(captured);
    captured = NULL;
    length = 0u;
    char *detached_argv[] = {
        (char *)git_executable, "--git-dir", (char *)repository_path,
        "rev-parse", "--verify", "HEAD", NULL};
    result = mg_process_capture_status(git_executable, detached_argv, &captured,
                                       &length, 65u, &status, error);
    if (result != MAELYS_GIT_OK) return result;
    if (status != 0) {
        free(captured);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "repository HEAD is neither symbolic nor a valid object");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    mg_trim_line_endings(captured, &length);
    int copied = mg_is_oid((char *)captured) &&
                 mg_copy_string(out->value, sizeof(out->value), (char *)captured);
    free(captured);
    if (!copied) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     "repository has an invalid detached HEAD");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    return MAELYS_GIT_OK;
}

static maelys_git_result_t mirror_fingerprint(const char *git_executable,
                                              const char *repository_path,
                                              char out[65],
                                              mirror_head_t *out_head,
                                              maelys_git_error_t *error) {
    unsigned char *refs = NULL;
    size_t refs_length = 0u;
    char *argv[] = {
        (char *)git_executable, "--git-dir", (char *)repository_path,
        "for-each-ref", "--format=%(refname)%00%(objectname)%00%(symref)%00", NULL};
    maelys_git_result_t result = mg_process_capture(
        git_executable, argv, &refs, &refs_length, MG_MIRROR_MAX_REFS_BYTES, error);
    if (result != MAELYS_GIT_OK) return result;
    mirror_head_t head;
    result = mirror_head(git_executable, repository_path, &head, error);
    if (result != MAELYS_GIT_OK) {
        free(refs);
        return result;
    }
    const char *kind = head.symbolic ? "symbolic:" : "detached:";
    size_t kind_length = strlen(kind);
    size_t head_length = strlen(head.value);
    if (refs_length > SIZE_MAX - kind_length - head_length - 1u) {
        free(refs);
        return MAELYS_GIT_ERR_LIMIT;
    }
    size_t total = refs_length + kind_length + head_length + 1u;
    unsigned char *input = malloc(total);
    if (!input) {
        free(refs);
        return MAELYS_GIT_ERR_IO;
    }
    memcpy(input, refs, refs_length);
    memcpy(input + refs_length, kind, kind_length);
    memcpy(input + refs_length + kind_length, head.value, head_length);
    input[total - 1u] = '\n';
    free(refs);
    maelys_cli_sha256_hex(input, total, out);
    free(input);
    if (out_head) *out_head = head;
    return MAELYS_GIT_OK;
}

static int require_mirror_precondition(const char *name,
                                       const char *expected,
                                       const char *actual,
                                       maelys_git_error_t *error) {
    if (!expected || !*expected) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0,
                     "mirror apply requires expected %s from plan", name);
        return 0;
    }
    if (strcmp(expected, actual) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "mirror %s changed; run a new plan", name);
        return 0;
    }
    return 1;
}

static maelys_git_result_t synchronize_head(const char *git_executable,
                                            const char *target_path,
                                            const mirror_head_t *head,
                                            maelys_git_error_t *error) {
    char *symbolic_argv[] = {
        (char *)git_executable, "--git-dir", (char *)target_path,
        "symbolic-ref", "HEAD", (char *)head->value, NULL};
    char *detached_argv[] = {
        (char *)git_executable, "--git-dir", (char *)target_path,
        "update-ref", "--no-deref", "HEAD", (char *)head->value, NULL};
    return mg_process_run(git_executable,
                          head->symbolic ? symbolic_argv : detached_argv,
                          NULL, error);
}

maelys_git_result_t maelys_git_repository_mirror(
    const char *git_executable,
    const char *source_root,
    const char *source_repository,
    const char *target_root,
    const char *target_repository,
    const char *expected_source_identity,
    const char *expected_target_identity,
    const char *expected_source_fingerprint,
    const char *expected_target_fingerprint,
    int apply,
    maelys_git_repository_mirror_result_t *out_result,
    maelys_git_error_t *error) {
    static const char absent_fingerprint[] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    maelys_git_error_clear(error);
    if (!git_executable || !source_root || !source_repository || !target_root ||
        !target_repository || !out_result ||
        !maelys_git_repository_name_is_valid(source_repository) ||
        !maelys_git_repository_name_is_valid(target_repository))
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_result, 0, sizeof(*out_result));

    char canonical_source_root[PATH_MAX], canonical_target_root[PATH_MAX];
    maelys_git_result_t result = mg_canonical_directory(source_root, canonical_source_root, "mirror root", error);
    if (result != MAELYS_GIT_OK) return result;
    result = mg_canonical_directory(target_root, canonical_target_root, "mirror root", error);
    if (result != MAELYS_GIT_OK) return result;
    result = maelys_git_resolve_repository(canonical_source_root, source_repository,
                                           out_result->source_path,
                                           sizeof(out_result->source_path), error);
    if (result != MAELYS_GIT_OK) return result;
    int target_length = snprintf(out_result->target_path, sizeof(out_result->target_path),
                                 "%s/%s", canonical_target_root, target_repository);
    if (target_length < 0 || (size_t)target_length >= sizeof(out_result->target_path))
        return MAELYS_GIT_ERR_LIMIT;
    if (!strcmp(out_result->source_path, out_result->target_path)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0,
                     "mirror source and target must differ");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    if (!mg_path_identity(out_result->source_path, out_result->source_identity, NULL)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, errno,
                     "mirror source is not a direct repository directory");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    mirror_head_t source_head;
    result = mirror_fingerprint(git_executable, out_result->source_path,
                                out_result->source_fingerprint, &source_head, error);
    if (result != MAELYS_GIT_OK) return result;

    struct stat target_status;
    if (lstat(out_result->target_path, &target_status) == 0) {
        char resolved_target[PATH_MAX];
        result = maelys_git_resolve_repository(canonical_target_root, target_repository,
                                               resolved_target, sizeof(resolved_target), error);
        if (result != MAELYS_GIT_OK) return result;
        if (strcmp(resolved_target, out_result->target_path) != 0 ||
            !mg_path_identity(resolved_target, out_result->target_identity, NULL)) {
            mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, 0,
                         "mirror target is not a direct repository directory");
            return MAELYS_GIT_ERR_INVALID_REPOSITORY;
        }
        out_result->target_exists = 1;
        result = mirror_fingerprint(git_executable, resolved_target,
                                    out_result->target_fingerprint, NULL, error);
        if (result != MAELYS_GIT_OK) return result;
    } else if (errno == ENOENT) {
        (void)mg_copy_string(out_result->target_identity,
                             sizeof(out_result->target_identity), "absent");
        (void)mg_copy_string(out_result->target_fingerprint,
                             sizeof(out_result->target_fingerprint), absent_fingerprint);
    } else {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno,
                     "cannot inspect mirror target: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    (void)mg_copy_string(out_result->source_repository,
                         sizeof(out_result->source_repository), source_repository);
    (void)mg_copy_string(out_result->target_repository,
                         sizeof(out_result->target_repository), target_repository);
    out_result->changed = !out_result->target_exists ||
        strcmp(out_result->source_fingerprint, out_result->target_fingerprint) != 0;
    if (!apply) return MAELYS_GIT_OK;

    if (!require_mirror_precondition("source identity", expected_source_identity,
                                     out_result->source_identity, error) ||
        !require_mirror_precondition("target identity", expected_target_identity,
                                     out_result->target_identity, error) ||
        !require_mirror_precondition("source fingerprint", expected_source_fingerprint,
                                     out_result->source_fingerprint, error) ||
        !require_mirror_precondition("target fingerprint", expected_target_fingerprint,
                                     out_result->target_fingerprint, error))
        return error->code;
    if (!out_result->changed) return MAELYS_GIT_OK;

    if (!out_result->target_exists) {
        result = mg_repository_ensure_parent_directories(
            canonical_target_root, out_result->target_path, error);
        if (result != MAELYS_GIT_OK) return result;
        char *clone_argv[] = {
            (char *)git_executable, "clone", "--quiet", "--mirror", "--no-local", "--",
            out_result->source_path, out_result->target_path, NULL};
        result = mg_process_run(git_executable, clone_argv, NULL, error);
        if (result != MAELYS_GIT_OK) {
            (void)mg_remove_tree(out_result->target_path);
            return result;
        }
    } else {
        char *push_argv[] = {
            (char *)git_executable, "--git-dir", out_result->source_path,
            "push", "--quiet", "--atomic", "--mirror", "--",
            out_result->target_path, NULL};
        result = mg_process_run(git_executable, push_argv, NULL, error);
        if (result != MAELYS_GIT_OK) return result;
    }
    result = synchronize_head(git_executable, out_result->target_path, &source_head, error);
    if (result != MAELYS_GIT_OK) return result;
    char final_fingerprint[65];
    result = mirror_fingerprint(git_executable, out_result->target_path,
                                final_fingerprint, NULL, error);
    if (result != MAELYS_GIT_OK) return result;
    if (strcmp(final_fingerprint, out_result->source_fingerprint) != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "mirror verification failed after synchronization");
        return MAELYS_GIT_ERR_PROCESS;
    }
    return MAELYS_GIT_OK;
}
