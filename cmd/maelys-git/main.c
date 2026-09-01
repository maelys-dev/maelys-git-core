#include "maelys_git_cli.h"

#include <errno.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int emit_version(const maelys_cli_invocation_t *invocation) {
    json_t *data = json_pack("{s:s,s:s,s:s}", "product", "Maelys Git Core",
                             "version", MAELYS_GIT_VERSION, "contract", MAELYS_CLI_CONTRACT);
    char human[128];
    (void)snprintf(human, sizeof(human), "maelys-git %s", MAELYS_GIT_VERSION);
    int result = maelys_cli_emit_success(invocation, data, human, 0);
    json_decref(data);
    return result;
}

static int command_validate(const maelys_cli_invocation_t *invocation) {
    const char *manifest = maelys_cli_operand(invocation, 0u);
    maelys_git_error_t error = {0};
    maelys_git_policy_t *policy = NULL;
    maelys_git_result_t result = maelys_git_policy_open(manifest, &policy, &error);
    maelys_git_policy_close(policy);
    if (result != MAELYS_GIT_OK && result != MAELYS_GIT_ERR_POLICY)
        return maelys_cli_emit_maelys_error(invocation, result, &error);
    int valid = result == MAELYS_GIT_OK;
    json_t *diagnostics = json_array();
    if (!valid) json_array_append_new(diagnostics,
        json_pack("{s:s,s:s,s:s}", "code", "POLICY_INVALID", "path", manifest,
                  "message", error.message));
    json_t *data = json_pack("{s:b,s:s,s:o}", "valid", valid,
                             "manifest", manifest, "diagnostics", diagnostics);
    int exit_code = valid ? 0 : 2;
    int emitted = maelys_cli_emit_success(invocation, data,
        valid ? "Policy manifest is valid." : "Policy manifest has violations.", exit_code);
    json_decref(data);
    return emitted;
}

static int command_authorize(const maelys_cli_invocation_t *invocation) {
    maelys_git_error_t error = {0};
    maelys_git_policy_t *policy = NULL;
    maelys_git_result_t result = maelys_git_policy_open(
        maelys_cli_operand(invocation, 0u), &policy, &error);
    if (result != MAELYS_GIT_OK) return maelys_cli_emit_maelys_error(invocation, result, &error);
    const char *ref_name = maelys_cli_operand(invocation, 4u);
    if (ref_name && !strcmp(ref_name, "-")) ref_name = NULL;
    const char *paths[MAELYS_GIT_MAX_CHANGED_PATHS];
    size_t path_count = invocation->operand_count > 5u ? invocation->operand_count - 5u : 0u;
    if (path_count > MAELYS_GIT_MAX_CHANGED_PATHS) {
        maelys_git_policy_close(policy);
        maelys_cli_error_t cli_error = {"VALIDATION_FAILED", "Too many PATH operands.",
            "Pass no more than 64 paths in one authorization request."};
        return maelys_cli_emit_error(invocation, &cli_error, 1);
    }
    for (size_t i = 0u; i < path_count; ++i) paths[i] = invocation->operands[i + 5u];
    maelys_git_policy_request_t request = {
        .request_id = "cli",
        .principal = maelys_cli_operand(invocation, 1u),
        .repository = maelys_cli_operand(invocation, 2u),
        .operation = maelys_cli_operand(invocation, 3u),
        .ref_name = ref_name,
        .paths = path_count ? paths : NULL,
        .path_count = path_count,
    };
    maelys_git_policy_decision_t decision;
    result = maelys_git_policy_authorize(policy, &request, &decision, &error);
    maelys_git_policy_close(policy);
    if (result != MAELYS_GIT_OK) return maelys_cli_emit_maelys_error(invocation, result, &error);
    json_t *data = json_pack("{s:b,s:b,s:I,s:s}",
        "allowed", decision.allowed, "explicitDeny", decision.explicit_deny,
        "matchedPolicy", (json_int_t)decision.matched_policy, "reason", decision.reason);
    int emitted = maelys_cli_emit_success(invocation, data,
        decision.allowed ? "Authorization allowed." : "Authorization denied.", 0);
    json_decref(data);
    return emitted;
}

static int command_parse_ssh(const maelys_cli_invocation_t *invocation) {
    maelys_git_error_t error = {0};
    maelys_git_ssh_command_t parsed;
    maelys_git_result_t result = maelys_git_parse_ssh_command(
        maelys_cli_operand(invocation, 0u), &parsed, &error);
    if (result != MAELYS_GIT_OK) return maelys_cli_emit_maelys_error(invocation, result, &error);
    const char *service = parsed.service == MAELYS_GIT_SERVICE_UPLOAD_PACK ?
                          "upload-pack" : "receive-pack";
    json_t *data = json_pack("{s:s,s:s}", "service", service,
                             "repository", parsed.repository);
    int emitted = maelys_cli_emit_success(invocation, data, NULL, 0);
    json_decref(data);
    return emitted;
}

static const char *git_executable(const maelys_cli_invocation_t *invocation) {
    const char *git = maelys_cli_option(invocation, "git");
    return git ? git : "/usr/bin/git";
}

static int command_repo_init(const maelys_cli_invocation_t *invocation) {
    const char *root = maelys_cli_operand(invocation, 0u);
    const char *repository = maelys_cli_operand(invocation, 1u);
    if (!maelys_git_repository_name_is_valid(repository)) {
        maelys_git_error_t error = {.code = MAELYS_GIT_ERR_INVALID_REPOSITORY};
        (void)snprintf(error.message, sizeof(error.message), "invalid repository name");
        return maelys_cli_emit_maelys_error(invocation, error.code, &error);
    }
    char canonical_root[4096];
    if (!realpath(root, canonical_root)) {
        maelys_git_error_t error = {.code = MAELYS_GIT_ERR_NOT_FOUND, .system_error = errno};
        (void)snprintf(error.message, sizeof(error.message), "cannot resolve repository root: %s", strerror(errno));
        return maelys_cli_emit_maelys_error(invocation, error.code, &error);
    }
    char target[4096];
    int target_length = snprintf(target, sizeof(target), "%s/%s", canonical_root, repository);
    struct stat target_status;
    if (target_length < 0 || (size_t)target_length >= sizeof(target)) {
        maelys_git_error_t error = {.code = MAELYS_GIT_ERR_LIMIT};
        (void)snprintf(error.message, sizeof(error.message), "repository target path is too long");
        return maelys_cli_emit_maelys_error(invocation, error.code, &error);
    }
    if (lstat(target, &target_status) == 0 || errno != ENOENT) {
        maelys_cli_error_t error = {"PRECONDITION_FAILED",
            "Repository creation requires an absent target.",
            "Choose a new repository name or inspect the existing target before retrying."};
        return maelys_cli_emit_error(invocation, &error, 1);
    }
    int apply = maelys_cli_flag(invocation, "apply");
    maelys_git_error_t error = {0};
    maelys_git_result_t result = MAELYS_GIT_OK;
    if (apply) result = maelys_git_repository_init_bare(
        git_executable(invocation), canonical_root, repository, &error);
    if (result != MAELYS_GIT_OK) return maelys_cli_emit_maelys_error(invocation, result, &error);
    json_t *data = json_pack("{s:s,s:b,s:s,s:s,s:s,s:o}",
        "mode", apply ? "apply" : "plan", "changed", apply,
        "root", canonical_root, "repository", repository,
        "git", git_executable(invocation), "precondition",
        json_pack("{s:b}", "targetAbsent", 1));
    int emitted = maelys_cli_emit_success(invocation, data,
        apply ? "Bare repository created." : "Plan only; add --apply to create the repository.", 0);
    json_decref(data);
    return emitted;
}

static int resolve_repository(const maelys_cli_invocation_t *invocation,
                              char path[4096],
                              maelys_git_error_t *error) {
    maelys_git_result_t result = maelys_git_resolve_repository(
        maelys_cli_operand(invocation, 0u), maelys_cli_operand(invocation, 1u),
        path, 4096u, error);
    return result == MAELYS_GIT_OK ? 0 : maelys_cli_emit_maelys_error(invocation, result, error);
}

static int command_repo_diff(const maelys_cli_invocation_t *invocation) {
    maelys_git_error_t error = {0};
    char path[4096];
    int resolve_result = resolve_repository(invocation, path, &error);
    if (resolve_result) return resolve_result;
    maelys_git_path_list_t paths;
    maelys_git_result_t result = maelys_git_repository_changed_paths(
        git_executable(invocation), path, maelys_cli_operand(invocation, 2u),
        maelys_cli_operand(invocation, 3u), &paths, &error);
    if (result != MAELYS_GIT_OK) return maelys_cli_emit_maelys_error(invocation, result, &error);
    json_t *items = json_array();
    for (size_t i = 0u; i < paths.count; ++i) json_array_append_new(items, json_string(paths.items[i]));
    json_t *data = json_pack("{s:s,s:o,s:I}", "repository",
        maelys_cli_operand(invocation, 1u), "paths", items,
        "pathCount", (json_int_t)paths.count);
    maelys_git_path_list_clear(&paths);
    int emitted = maelys_cli_emit_success(invocation, data, NULL, 0);
    json_decref(data);
    return emitted;
}

static int command_repo_update(const maelys_cli_invocation_t *invocation) {
    maelys_git_error_t error = {0};
    char path[4096];
    int resolve_result = resolve_repository(invocation, path, &error);
    if (resolve_result) return resolve_result;
    const char *ref = maelys_cli_operand(invocation, 2u);
    const char *new_oid = maelys_cli_operand(invocation, 3u);
    const char *old_oid = maelys_cli_operand(invocation, 4u);
    if (!maelys_git_ref_name_is_valid(ref)) {
        error.code = MAELYS_GIT_ERR_INVALID_ARGUMENT;
        (void)snprintf(error.message, sizeof(error.message), "invalid full Git reference");
        return maelys_cli_emit_maelys_error(invocation, error.code, &error);
    }
    int apply = maelys_cli_flag(invocation, "apply");
    maelys_git_result_t result = MAELYS_GIT_OK;
    if (apply) result = maelys_git_repository_update_ref(
        git_executable(invocation), path, ref, new_oid, old_oid, &error);
    else {
        size_t old_length = strlen(old_oid);
        size_t new_length = strlen(new_oid);
        int valid_oids = (old_length == 40u || old_length == 64u) &&
                         (new_length == 40u || new_length == 64u);
        for (const char *p = old_oid; valid_oids && *p; ++p)
            if (!isxdigit((unsigned char)*p)) valid_oids = 0;
        for (const char *p = new_oid; valid_oids && *p; ++p)
            if (!isxdigit((unsigned char)*p)) valid_oids = 0;
        if (!valid_oids) {
        result = MAELYS_GIT_ERR_INVALID_ARGUMENT;
        (void)snprintf(error.message, sizeof(error.message), "object IDs must contain 40 or 64 hexadecimal characters");
        }
    }
    if (result != MAELYS_GIT_OK) return maelys_cli_emit_maelys_error(invocation, result, &error);
    json_t *data = json_pack("{s:s,s:b,s:s,s:s,s:s,s:s,s:o}",
        "mode", apply ? "apply" : "plan", "changed", apply,
        "repository", maelys_cli_operand(invocation, 1u), "ref", ref,
        "newOid", new_oid, "git", git_executable(invocation),
        "precondition", json_pack("{s:s}", "currentOid", old_oid));
    int emitted = maelys_cli_emit_success(invocation, data,
        apply ? "Reference updated." : "Plan only; add --apply to update the reference.", 0);
    json_decref(data);
    return emitted;
}

static maelys_git_merge_style_t merge_style(const char *value) {
    if (!value || !strcmp(value, "ff")) return MAELYS_GIT_MERGE_FAST_FORWARD;
    if (!strcmp(value, "merge")) return MAELYS_GIT_MERGE_COMMIT;
    if (!strcmp(value, "squash")) return MAELYS_GIT_MERGE_SQUASH;
    return 0;
}

static int emit_pr_result(const maelys_cli_invocation_t *invocation,
                          const char *mode,
                          int changed,
                          maelys_git_merge_style_t style,
                          maelys_git_pr_check_result_t *result) {
    const char *style_name = style == MAELYS_GIT_MERGE_FAST_FORWARD ? "ff" :
                             style == MAELYS_GIT_MERGE_COMMIT ? "merge" : "squash";
    json_t *conflicts = json_array();
    for (size_t i = 0u; i < result->conflict_paths.count; ++i)
        json_array_append_new(conflicts, json_string(result->conflict_paths.items[i]));
    json_t *summary = json_pack("{s:I,s:I,s:I,s:I,s:I,s:I,s:b}",
        "changed", (json_int_t)result->changes.changed_count,
        "added", (json_int_t)result->changes.added_count,
        "modified", (json_int_t)result->changes.modified_count,
        "deleted", (json_int_t)result->changes.deleted_count,
        "renamed", (json_int_t)result->changes.renamed_count,
        "maxNewBlobSize", (json_int_t)result->changes.max_new_blob_size,
        "hasBinary", result->changes.has_binary);
    json_t *data = json_pack("{s:s,s:b,s:s,s:s,s:b,s:b,s:s,s:s,s:s,s:s,s:o,s:o}",
        "mode", mode, "changed", changed,
        "repository", maelys_cli_operand(invocation, 1u), "style", style_name,
        "mergeable", result->mergeable, "empty", result->empty,
        "mergeBaseOid", result->merge_base_oid, "mergeTreeOid", result->merge_tree_oid,
        "preparedOid", result->prepared_oid,
        "policyFingerprint", result->policy_fingerprint, "conflicts", conflicts,
        "changeSummary", summary);
    int emitted = maelys_cli_emit_success(invocation, data, NULL, 0);
    json_decref(data);
    maelys_git_pr_check_result_clear(result);
    return emitted;
}

static int command_keys_compile(const maelys_cli_invocation_t *invocation) {
    int apply = maelys_cli_flag(invocation, "apply");
    size_t key_count = 0u;
    maelys_git_error_t error = {0};
    maelys_git_result_t result = maelys_git_compile_authorized_keys(
        maelys_cli_operand(invocation, 0u), maelys_cli_operand(invocation, 1u),
        maelys_cli_operand(invocation, 2u), maelys_cli_operand(invocation, 3u),
        maelys_cli_operand(invocation, 4u), apply, &key_count, &error);
    if (result != MAELYS_GIT_OK) return maelys_cli_emit_maelys_error(invocation, result, &error);
    json_t *data = json_pack("{s:s,s:b,s:s,s:s,s:I}",
        "mode", apply ? "apply" : "plan", "changed", apply,
        "keyDirectory", maelys_cli_operand(invocation, 0u),
        "output", maelys_cli_operand(invocation, 1u),
        "keyCount", (json_int_t)key_count);
    int emitted = maelys_cli_emit_success(invocation, data,
        apply ? "authorized_keys replaced atomically." : "Plan only; add --apply to replace authorized_keys.", 0);
    json_decref(data);
    return emitted;
}

static int command_pr_check(const maelys_cli_invocation_t *invocation) {
    maelys_git_error_t error = {0};
    char repository_path[4096];
    int resolved = resolve_repository(invocation, repository_path, &error);
    if (resolved) return resolved;
    maelys_git_merge_style_t style = merge_style(maelys_cli_option(invocation, "style"));
    if (!style) {
        maelys_cli_error_t cli_error = {"VALIDATION_FAILED", "Invalid --style value.",
                                         "Use ff, merge, or squash."};
        return maelys_cli_emit_error(invocation, &cli_error, 1);
    }
    maelys_git_pr_check_result_t check;
    maelys_git_result_t result = maelys_git_pr_check(
        git_executable(invocation), repository_path,
        maelys_cli_operand(invocation, 2u), maelys_cli_operand(invocation, 3u),
        style, maelys_cli_option(invocation, "message"), &check, &error);
    if (result != MAELYS_GIT_OK) return maelys_cli_emit_maelys_error(invocation, result, &error);
    return emit_pr_result(invocation, "check", 0, style, &check);
}

static int parse_count_option(const maelys_cli_invocation_t *invocation,
                              const char *name,
                              size_t *out) {
    const char *value = maelys_cli_option(invocation, name);
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value ? value : "", &end, 10);
    if (errno || !value || end == value || *end || parsed > SIZE_MAX) return 0;
    *out = (size_t)parsed;
    return 1;
}

static int command_pr_merge(const maelys_cli_invocation_t *invocation) {
    maelys_git_error_t error = {0};
    char repository_path[4096];
    int resolved = resolve_repository(invocation, repository_path, &error);
    if (resolved) return resolved;
    maelys_git_merge_style_t style = merge_style(maelys_cli_option(invocation, "style"));
    maelys_git_pr_gates_t gates = {
        .status_checks_passed = maelys_cli_flag(invocation, "status-checks-passed"),
        .blocking_review = maelys_cli_flag(invocation, "blocking-review"),
    };
    if (!style || !parse_count_option(invocation, "approvals", &gates.approvals) ||
        !parse_count_option(invocation, "required-approvals", &gates.required_approvals)) {
        maelys_cli_error_t cli_error = {"VALIDATION_FAILED", "Invalid PR merge options.",
                                         "Use a supported style and non-negative gate counts."};
        return maelys_cli_emit_error(invocation, &cli_error, 1);
    }
    maelys_git_policy_t *policy = NULL;
    maelys_git_result_t result = maelys_git_policy_open(
        maelys_cli_operand(invocation, 5u), &policy, &error);
    if (result != MAELYS_GIT_OK) return maelys_cli_emit_maelys_error(invocation, result, &error);
    int apply = maelys_cli_flag(invocation, "apply");
    const char *expected_prepared_oid =
        maelys_cli_option(invocation, "expected-prepared-oid");
    const char *expected_policy_fingerprint =
        maelys_cli_option(invocation, "expected-policy-fingerprint");
    if (apply && (!expected_prepared_oid || !expected_policy_fingerprint)) {
        maelys_git_policy_close(policy);
        maelys_cli_error_t cli_error = {
            "VALIDATION_FAILED",
            "Apply requires the reviewed plan preconditions.",
            "Pass --expected-prepared-oid and --expected-policy-fingerprint from the plan output."};
        return maelys_cli_emit_error(invocation, &cli_error, 1);
    }
    maelys_git_pr_check_result_t check;
    result = maelys_git_pr_merge(
        git_executable(invocation), repository_path, maelys_cli_operand(invocation, 1u),
        maelys_cli_operand(invocation, 2u), maelys_cli_operand(invocation, 3u),
        maelys_cli_operand(invocation, 4u), style, maelys_cli_option(invocation, "message"),
        maelys_cli_operand(invocation, 6u), &gates, policy,
        expected_prepared_oid, expected_policy_fingerprint, apply, &check, &error);
    maelys_git_policy_close(policy);
    if (result != MAELYS_GIT_OK) return maelys_cli_emit_maelys_error(invocation, result, &error);
    return emit_pr_result(invocation, apply ? "apply" : "plan", apply, style, &check);
}

int main(int argc, char **argv) {
    maelys_cli_invocation_t invocation;
    maelys_cli_error_t parse_error;
    if (!maelys_cli_parse("maelys-git", argc - 1, argv + 1, &invocation, &parse_error))
        return maelys_cli_emit_error(&invocation, &parse_error, 1);
    const char *command = invocation.command->id;
    if (!strcmp(command, "help")) return maelys_cli_emit_help(&invocation);
    if (!strcmp(command, "version")) return emit_version(&invocation);
    if (!strcmp(command, "describe")) return maelys_cli_emit_describe(&invocation);
    if (!strcmp(command, "validate")) return command_validate(&invocation);
    if (!strcmp(command, "authorize")) return command_authorize(&invocation);
    if (!strcmp(command, "parse-ssh")) return command_parse_ssh(&invocation);
    if (!strcmp(command, "repo.init")) return command_repo_init(&invocation);
    if (!strcmp(command, "repo.diff")) return command_repo_diff(&invocation);
    if (!strcmp(command, "repo.update-ref")) return command_repo_update(&invocation);
    if (!strcmp(command, "keys.compile")) return command_keys_compile(&invocation);
    if (!strcmp(command, "pr.check")) return command_pr_check(&invocation);
    if (!strcmp(command, "pr.merge")) return command_pr_merge(&invocation);
    return 1;
}
