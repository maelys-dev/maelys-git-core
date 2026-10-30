/* maelys-git: policy validation, authorization and repository administration.
 * Every command is one catalog entry, one handler and one embedded schema. */
#include "cli/json_support.h"
#include "maelys_git_receipt.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PATH_CAPACITY MAELYS_GIT_CLI_PATH_MAX

/* ---- operands ---------------------------------------------------------------- */

static const maelys_cli_operand_t validate_operands[] = {
    {MAELYS_CLI_OPERAND("MANIFEST", "Versioned Maelys Datalog manifest.")},
};
static const maelys_cli_operand_t authorize_operands[] = {
    {MAELYS_CLI_OPERAND("MANIFEST", "Versioned Maelys Datalog manifest.")},
    {MAELYS_CLI_OPERAND("PRINCIPAL", "Authenticated principal.")},
    {MAELYS_CLI_OPERAND("REPOSITORY", "Repository name below the configured root.")},
    {MAELYS_CLI_OPERAND("OPERATION", "Datalog operation atom.")},
    {MAELYS_CLI_OPERAND_OPTIONAL("REF", "Optional full Git reference, or '-' when omitted.")},
    {MAELYS_CLI_OPERAND_REST("PATH", "Zero or more changed paths.")},
};
static const maelys_cli_option_t validate_options[] = {
    MAELYS_GIT_CLI_GRANTS_OPTION,
};
/* The names maelys_git_update_kind_name() gives, in enumeration order. */
static const char *const update_kinds[] = {"create", "fast_forward", "force", "delete", NULL};
static const maelys_cli_option_t authorize_options[] = {
    {MAELYS_CLI_FLAG("explain",
     "Attach the engine's explanation document of the decision; write it before --.")},
    {MAELYS_CLI_CHOICE("update-kind",
     "Kind of ref update a push or merge request makes; a rule that names one, as a "
     "Gitolite ref grant does, never allows without it.", update_kinds)},
    MAELYS_GIT_CLI_GRANTS_OPTION,
};
static const maelys_cli_operand_t parse_ssh_operands[] = {
    {MAELYS_CLI_OPERAND("COMMAND", "Complete SSH_ORIGINAL_COMMAND value.")},
};
static const maelys_cli_operand_t repo_operands[] = {
    {MAELYS_CLI_OPERAND("ROOT", "Absolute repository root.")},
    {MAELYS_CLI_OPERAND("REPOSITORY", "Repository name below ROOT.")},
};
static const maelys_cli_operand_t repo_list_operands[] = {
    {MAELYS_CLI_OPERAND("ROOT", "Absolute repository root.")},
};
static const maelys_cli_operand_t repo_rename_operands[] = {
    {MAELYS_CLI_OPERAND("ROOT", "Absolute repository root.")},
    {MAELYS_CLI_OPERAND("SOURCE", "Existing active repository name.")},
    {MAELYS_CLI_OPERAND("TARGET", "Absent target repository name.")},
};
static const maelys_cli_operand_t repo_store_operands[] = {
    {MAELYS_CLI_OPERAND("ROOT", "Absolute repository root.")},
    {MAELYS_CLI_OPERAND("REPOSITORY", "Existing active repository name.")},
    {MAELYS_CLI_OPERAND("STORAGE_ID", "Stable archive or deletion identifier.")},
};
static const maelys_cli_operand_t repo_restore_operands[] = {
    {MAELYS_CLI_OPERAND("ROOT", "Absolute repository root.")},
    {MAELYS_CLI_OPERAND("STORAGE_ID", "Existing archive or deletion identifier.")},
};
static const maelys_cli_operand_t repo_mirror_operands[] = {
    {MAELYS_CLI_OPERAND("SOURCE_ROOT", "Absolute root containing the source repository.")},
    {MAELYS_CLI_OPERAND("REPOSITORY", "Existing source repository name.")},
    {MAELYS_CLI_OPERAND("TARGET_ROOT", "Absolute root that will contain the mirror.")},
};
static const maelys_cli_operand_t repo_diff_operands[] = {
    {MAELYS_CLI_OPERAND("ROOT", "Absolute repository root.")},
    {MAELYS_CLI_OPERAND("REPOSITORY", "Repository name below ROOT.")},
    MAELYS_GIT_CLI_OID_OPERAND("OLD_OID", "Expected old object identifier."),
    MAELYS_GIT_CLI_OID_OPERAND("NEW_OID", "New object identifier."),
};
static const maelys_cli_operand_t repo_update_ref_operands[] = {
    {MAELYS_CLI_OPERAND("ROOT", "Absolute repository root.")},
    {MAELYS_CLI_OPERAND("REPOSITORY", "Repository name below ROOT.")},
    {MAELYS_CLI_OPERAND("REF", "Full Git reference.")},
    MAELYS_GIT_CLI_OID_OPERAND("NEW_OID", "New object identifier."),
    MAELYS_GIT_CLI_OID_OPERAND("OLD_OID", "Expected current object identifier."),
};
static const maelys_cli_operand_t keys_compile_operands[] = {
    {MAELYS_CLI_OPERAND("KEY_DIRECTORY", "Directory containing PRINCIPAL.pub public keys.")},
    {MAELYS_CLI_OPERAND("OUTPUT", "authorized_keys file to replace atomically.")},
    MAELYS_GIT_CLI_ABSOLUTE_OPERAND("SHELL", "Absolute maelys-git-shell executable path."),
    MAELYS_GIT_CLI_ABSOLUTE_OPERAND("ROOT", "Absolute repository root."),
    MAELYS_GIT_CLI_ABSOLUTE_OPERAND("MANIFEST", "Absolute Datalog policy manifest path."),
};
static const maelys_cli_operand_t migrate_gitolite_operands[] = {
    {MAELYS_CLI_OPERAND("INPUT", "Gitolite conf file to analyze.")},
    {MAELYS_CLI_OPERAND("OUTPUT", "New directory for generated Datalog policy and manifest.")},
};
static const maelys_cli_operand_t pr_check_operands[] = {
    {MAELYS_CLI_OPERAND("ROOT", "Absolute repository root.")},
    {MAELYS_CLI_OPERAND("REPOSITORY", "Repository name below ROOT.")},
    MAELYS_GIT_CLI_OID_OPERAND("BASE_OID", "Current target commit."),
    MAELYS_GIT_CLI_OID_OPERAND("HEAD_OID", "Pull request head commit."),
};
static const maelys_cli_operand_t pr_merge_operands[] = {
    {MAELYS_CLI_OPERAND("ROOT", "Absolute repository root.")},
    {MAELYS_CLI_OPERAND("REPOSITORY", "Repository name below ROOT.")},
    {MAELYS_CLI_OPERAND("BASE_REF", "Target branch reference.")},
    MAELYS_GIT_CLI_OID_OPERAND("BASE_OID", "Expected target commit for CAS."),
    MAELYS_GIT_CLI_OID_OPERAND("HEAD_OID", "Pull request head commit."),
    {MAELYS_CLI_OPERAND("MANIFEST", "Datalog manifest used for final authorization.")},
    {MAELYS_CLI_OPERAND("PRINCIPAL", "Authenticated merge principal.")},
};

/* ---- options ----------------------------------------------------------------- */

static const char *const merge_styles[] = {"ff", "merge", "squash", NULL};
static const char *const storage_areas[] = {"archive", "trash", NULL};

/* Every reviewed precondition of a transaction travels with --apply: the
 * "apply" group is all-or-none, so a plan never carries a precondition and an
 * apply never lacks one. */
#define APPLY_GROUP "apply"
#define EXPECTED_SOURCE_IDENTITY_OPTION(summary_) \
    {MAELYS_CLI_STRING("expected-source-identity", "IDENTITY", summary_), \
     .group = APPLY_GROUP}

static const maelys_cli_option_t git_option[] = {
    MAELYS_GIT_CLI_GIT_OPTION,
};
static const maelys_cli_option_t git_apply_options[] = {
    MAELYS_GIT_CLI_GIT_OPTION,
    MAELYS_CLI_APPLY_OPTION,
};
static const maelys_cli_option_t apply_option[] = {
    MAELYS_CLI_APPLY_OPTION,
};
static const maelys_cli_option_t repo_list_options[] = {
    {MAELYS_CLI_FLAG("include-stored",
     "Include repositories held in archive and recoverable trash.")},
};
static const maelys_cli_option_t lifecycle_options[] = {
    EXPECTED_SOURCE_IDENTITY_OPTION(
        "Source device/inode identity returned by the reviewed plan."),
    {MAELYS_CLI_FLAG("apply", "Apply the reviewed repository transition."),
     .group = APPLY_GROUP},
};
static const maelys_cli_option_t restore_options[] = {
    {MAELYS_CLI_CHOICE("from", "Storage area containing the repository.", storage_areas),
     .required = 1},
    {MAELYS_CLI_STRING("as", "REPOSITORY",
     "Optional new active name; defaults to the stored original name.")},
    EXPECTED_SOURCE_IDENTITY_OPTION(
        "Stored repository device/inode identity returned by the reviewed plan."),
    {MAELYS_CLI_FLAG("apply", "Apply the reviewed repository restoration."),
     .group = APPLY_GROUP},
};
static const maelys_cli_option_t mirror_options[] = {
    {MAELYS_CLI_STRING("as", "REPOSITORY",
     "Optional mirror repository name; defaults to the source name.")},
    MAELYS_GIT_CLI_GIT_OPTION,
    EXPECTED_SOURCE_IDENTITY_OPTION(
        "Source device/inode identity returned by the reviewed plan."),
    {MAELYS_CLI_STRING("expected-target-identity", "IDENTITY|absent",
     "Target identity or absent marker returned by the reviewed plan."),
     .group = APPLY_GROUP},
    {MAELYS_CLI_HEX("expected-source-fingerprint", "SHA256",
     "Source refs and HEAD fingerprint returned by the reviewed plan.", 64u),
     .group = APPLY_GROUP},
    {MAELYS_CLI_HEX("expected-target-fingerprint", "SHA256",
     "Target refs and HEAD fingerprint returned by the reviewed plan.", 64u),
     .group = APPLY_GROUP},
    {MAELYS_CLI_FLAG("apply", "Synchronize the mirror using the reviewed preconditions."),
     .group = APPLY_GROUP},
};

#define PR_SOURCE_OPTIONS \
    {MAELYS_CLI_STRING("source-repository", "REPOSITORY", \
     "Optional fork repository below ROOT."), .depends_on = "source-ref"}, \
    {MAELYS_CLI_STRING("source-ref", "REF", \
     "Full branch ref whose commit must equal HEAD_OID."), \
     .depends_on = "source-repository"}, \
    {MAELYS_CLI_UNSIGNED("max-source-objects", "COUNT", \
     "Maximum objects reachable from a quarantined fork head.", 1u, \
     (uint64_t)INT64_MAX), .depends_on = "source-repository", \
     MAELYS_CLI_DEFAULT_OF(MAELYS_GIT_PR_DEFAULT_MAX_SOURCE_OBJECTS)}, \
    {MAELYS_CLI_SIZE("max-source-bytes", "BYTES", \
     "Maximum on-disk bytes reachable from a quarantined fork head.", 1u, \
     (uint64_t)INT64_MAX), .depends_on = "source-repository", \
     MAELYS_CLI_DEFAULT_OF(MAELYS_GIT_PR_DEFAULT_MAX_SOURCE_BYTES)}

static const maelys_cli_option_t pr_check_options[] = {
    MAELYS_GIT_CLI_GIT_OPTION,
    {MAELYS_CLI_CHOICE("style", "Merge strategy to evaluate.", merge_styles),
     .required = 1},
    {MAELYS_CLI_STRING("message", "TEXT", "Prepared merge commit message.")},
    PR_SOURCE_OPTIONS,
};
static const maelys_cli_option_t pr_merge_options[] = {
    MAELYS_GIT_CLI_GIT_OPTION,
    MAELYS_GIT_CLI_GRANTS_OPTION,
    {MAELYS_CLI_HEX("expected-grants-fingerprint", "SHA256",
     "Grants fingerprint returned by the reviewed plan; required to apply with --grants.", 64u),
     .depends_on = "grants"},
    {MAELYS_CLI_CHOICE("style", "Merge strategy to execute.", merge_styles),
     .required = 1},
    {MAELYS_CLI_STRING("message", "TEXT", "Prepared merge commit message.")},
    {MAELYS_CLI_UNSIGNED("approvals", "COUNT",
     "Verified approval count supplied by the forge.", 0u, (uint64_t)SIZE_MAX),
     .required = 1},
    {MAELYS_CLI_UNSIGNED("required-approvals", "COUNT",
     "Required approval count supplied by the forge.", 0u, (uint64_t)SIZE_MAX),
     .required = 1},
    {MAELYS_CLI_FLAG("status-checks-passed", "Assert that required status checks passed.")},
    {MAELYS_CLI_FLAG("blocking-review", "Assert that a blocking review exists.")},
    {MAELYS_CLI_STRING("pr-id", "ID",
     "Stable forge PR identifier used for internal head and merged refs.")},
    PR_SOURCE_OPTIONS,
    {MAELYS_CLI_STRING("expected-source-identity", "IDENTITY",
     "Fork device/inode identity returned by plan; required for cross-repository apply."),
     .depends_on = "source-repository"},
    {MAELYS_CLI_STRING("expected-target-identity", "IDENTITY",
     "Target device/inode identity returned by the reviewed plan."),
     .group = APPLY_GROUP},
    {MAELYS_CLI_HEX_OR("expected-prepared-oid", "OID",
     "Prepared OID returned by the reviewed plan.", 40u, 64u),
     .group = APPLY_GROUP},
    {MAELYS_CLI_HEX("expected-policy-fingerprint", "SHA256",
     "Policy-set fingerprint returned by the reviewed plan.", 64u),
     .group = APPLY_GROUP},
    {MAELYS_CLI_FLAG("apply", "Reauthorize and update the target ref with CAS."),
     .group = APPLY_GROUP},
};

/* ---- helpers ----------------------------------------------------------------- */

static const char *mode_name(int apply) { return apply ? "apply" : "plan"; }

static int fail_with_result(maelys_cli_context_t *context, maelys_git_result_t code,
                            const char *message) {
    maelys_git_error_t error = {.code = code};
    (void)snprintf(error.message, sizeof(error.message), "%s", message);
    return maelys_git_cli_fail_result(context, code, &error);
}

/* ---- validate / authorize / parse-ssh ----------------------------------------- */

static int command_validate(maelys_cli_context_t *context) {
    const char *manifest = maelys_cli_operand(context, 0u);
    maelys_git_error_t error = {0};
    const char *grants = maelys_cli_option(context, "grants");
    maelys_git_policy_t *policy = NULL;
    maelys_git_result_t result = grants ? maelys_git_policy_open_grants(manifest, grants, &policy, &error)
                                        : maelys_git_policy_open(manifest, &policy, &error);
    maelys_git_policy_close(policy);
    if (result != MAELYS_GIT_OK && result != MAELYS_GIT_ERR_POLICY)
        return maelys_git_cli_fail_result(context, result, &error);
    int valid = result == MAELYS_GIT_OK;
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_boolean(&data, "valid", valid);
    mg_json_string(&data, "manifest", manifest);
    mg_json_array(&data, "diagnostics");
    if (!valid) {
        /* The detail's members beside the diagnostic's own, as validate.json says. */
        mg_json_object(&data, NULL);
        mg_json_string(&data, "code", "POLICY_INVALID");
        mg_json_string(&data, "path", manifest);
        mg_json_string(&data, "message", error.message);
        mg_json_failure_detail(&data, &error.detail);
        mg_json_end_object(&data);
    }
    mg_json_end_array(&data);
    mg_json_end_object(&data);
    return maelys_git_cli_succeed_document(context, &data,
        valid ? "Policy manifest is valid." : "Policy manifest has violations.",
        valid ? MAELYS_CLI_EXIT_OK : MAELYS_CLI_EXIT_VIOLATIONS);
}

static int command_authorize(maelys_cli_context_t *context) {
    maelys_git_policy_t *policy = NULL;
    int failed = maelys_git_cli_open_policy(context, maelys_cli_operand(context, 0u),
                                            maelys_cli_option(context, "grants"), &policy);
    if (failed) return failed;
    const char *ref_name = maelys_cli_operand(context, 4u);
    if (ref_name && !strcmp(ref_name, "-")) ref_name = NULL;
    size_t operand_count = maelys_cli_operand_count(context);
    size_t path_count = operand_count > 5u ? operand_count - 5u : 0u;
    if (path_count > MAELYS_GIT_MAX_CHANGED_PATHS) {
        maelys_git_policy_close(policy);
        return maelys_cli_fail(context, MAELYS_CLI_CODE_VALIDATION_FAILED,
            "Pass no more than 64 paths in one authorization request.",
            "Too many PATH operands.");
    }
    const char *paths[MAELYS_GIT_MAX_CHANGED_PATHS];
    for (size_t i = 0u; i < path_count; ++i) paths[i] = maelys_cli_operand(context, i + 5u);
    maelys_git_policy_request_t request = {
        .request_id = "cli",
        .principal = maelys_cli_operand(context, 1u),
        .repository = maelys_cli_operand(context, 2u),
        .operation = maelys_cli_operand(context, 3u),
        .ref_name = ref_name,
        .update_kind = maelys_cli_option(context, "update-kind"),
        .paths = path_count ? paths : NULL,
        .path_count = path_count,
    };
    int explain = maelys_cli_flag(context, "explain");
    /* The document is exposed up to 32 KiB; beyond, the receipt keeps its
     * size and digest and explanationText is absent. */
    static char text[MAELYS_GIT_RECEIPT_MAX_EXPLANATION_TEXT + 1u];
    maelys_git_policy_decision_t decision;
    maelys_git_receipt_t receipt;
    maelys_git_error_t error = {0};
    maelys_git_result_t result = maelys_git_policy_authorize_receipt(
        policy, &request, explain ? MAELYS_GIT_EXPLAIN_ALWAYS : MAELYS_GIT_EXPLAIN_NEVER,
        explain ? text : NULL, explain ? sizeof(text) : 0u, &decision, &receipt, &error);
    maelys_git_policy_close(policy);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    char *bytes = NULL;
    size_t size = 0u;
    char sha256[65];
    result = maelys_git_receipt_serialize(&receipt, &bytes, &size, sha256, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    /* The receipt object is copied from its canonical bytes, read back; its
     * digest is that of those bytes, computed before it enters the data. */
    maelys_json_document_t *document = NULL;
    const maelys_json_limits_t receipt_limits = {
        .maximum_bytes = MAELYS_GIT_RECEIPT_MAX_BYTES, .maximum_depth = 4u, .maximum_tokens = 512u};
    maelys_json_result_t parsed = maelys_json_document_parse(
        bytes, size, MAELYS_JSON_PROFILE_RFC8259, &receipt_limits, &document, NULL);
    free(bytes);
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    if (parsed != MAELYS_JSON_OK) data.status = parsed;
    mg_json_object(&data, NULL);
    mg_json_boolean(&data, "allowed", decision.allowed);
    mg_json_boolean(&data, "explicitDeny", decision.explicit_deny);
    /* SIZE_MAX marks "no policy matched"; the contract exposes it as null. */
    if (decision.matched_policy == SIZE_MAX) mg_json_null(&data, "matchedPolicy");
    else mg_json_i64(&data, "matchedPolicy", (int64_t)decision.matched_policy);
    mg_json_string(&data, "reason", decision.reason);
    if (document) mg_json_copy(&data, "receipt", document, maelys_json_document_root(document));
    mg_json_string(&data, "receiptSha256", sha256);
    if (explain && receipt.explanation.has_text && text[0])
        mg_json_string(&data, "explanationText", text);
    mg_json_end_object(&data);
    maelys_json_document_release(document);
    return maelys_git_cli_succeed_document(context, &data,
        decision.allowed ? "Authorization allowed." : "Authorization denied.",
        MAELYS_CLI_EXIT_OK);
}

static int command_parse_ssh(maelys_cli_context_t *context) {
    maelys_git_error_t error = {0};
    maelys_git_ssh_command_t parsed;
    maelys_git_result_t result = maelys_git_parse_ssh_command(
        maelys_cli_operand(context, 0u), &parsed, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_string(&data, "service",
        parsed.service == MAELYS_GIT_SERVICE_UPLOAD_PACK ? "upload-pack" : "receive-pack");
    mg_json_string(&data, "repository", parsed.repository);
    mg_json_end_object(&data);
    return maelys_git_cli_succeed_document(context, &data, NULL, MAELYS_CLI_EXIT_OK);
}

/* ---- repo ---------------------------------------------------------------------- */

static int command_repo_init(maelys_cli_context_t *context) {
    const char *root = maelys_cli_operand(context, 0u);
    const char *repository = maelys_cli_operand(context, 1u);
    if (!maelys_git_repository_name_is_valid(repository))
        return fail_with_result(context, MAELYS_GIT_ERR_INVALID_REPOSITORY,
                                "invalid repository name");
    char canonical_root[PATH_CAPACITY];
    if (!realpath(root, canonical_root))
        return maelys_cli_fail_errno(context, MAELYS_CLI_CODE_NOT_FOUND, errno,
                                     "cannot resolve repository root");
    char target[PATH_CAPACITY];
    int length = snprintf(target, sizeof(target), "%s/%s", canonical_root, repository);
    if (length < 0 || (size_t)length >= sizeof(target))
        return fail_with_result(context, MAELYS_GIT_ERR_LIMIT,
                                "repository target path is too long");
    struct stat target_status;
    if (lstat(target, &target_status) == 0 || errno != ENOENT) {
        return maelys_cli_fail(context, MAELYS_CLI_CODE_PRECONDITION_FAILED,
            "Choose a new repository name or inspect the existing target before retrying.",
            "Repository creation requires an absent target.");
    }
    int apply = maelys_cli_flag(context, "apply");
    maelys_git_error_t error = {0};
    maelys_git_result_t result = MAELYS_GIT_OK;
    if (apply)
        result = maelys_git_repository_init_bare(
            maelys_git_cli_git(context), canonical_root, repository, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_string(&data, "mode", mode_name(apply));
    mg_json_boolean(&data, "changed", apply);
    mg_json_string(&data, "root", canonical_root);
    mg_json_string(&data, "repository", repository);
    mg_json_string(&data, "git", maelys_git_cli_git(context));
    mg_json_object(&data, "precondition");
    mg_json_boolean(&data, "targetAbsent", 1);
    mg_json_end_object(&data);
    mg_json_end_object(&data);
    return maelys_git_cli_succeed_document(context, &data,
        apply ? "Bare repository created." : "Plan only; add --apply to create the repository.",
        MAELYS_CLI_EXIT_OK);
}

static int command_repo_list(maelys_cli_context_t *context) {
    const char *root_operand = maelys_cli_operand(context, 0u);
    char root[PATH_CAPACITY];
    if (!realpath(root_operand, root))
        return maelys_cli_fail_errno(context, MAELYS_CLI_CODE_NOT_FOUND, errno,
                                     "cannot resolve repository root");
    maelys_git_error_t error = {0};
    maelys_git_repository_list_t repositories;
    maelys_git_result_t result = maelys_git_repository_list(
        root_operand, maelys_cli_flag(context, "include-stored"), &repositories, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_string(&data, "root", root);
    mg_json_i64(&data, "count", (int64_t)repositories.count);
    mg_json_array(&data, "repositories");
    for (size_t i = 0u; i < repositories.count; ++i) {
        const maelys_git_repository_entry_t *entry = &repositories.entries[i];
        mg_json_object(&data, NULL);
        mg_json_string(&data, "name", entry->repository);
        mg_json_string(&data, "state", maelys_git_repository_state_name(entry->state));
        mg_json_string(&data, "storageId", entry->storage_id);
        mg_json_end_object(&data);
    }
    mg_json_end_array(&data);
    mg_json_end_object(&data);
    maelys_git_repository_list_clear(&repositories);
    return maelys_git_cli_succeed_document(context, &data, NULL, MAELYS_CLI_EXIT_OK);
}

static int command_repo_inspect(maelys_cli_context_t *context) {
    maelys_git_error_t error = {0};
    maelys_git_repository_info_t info;
    maelys_git_result_t result = maelys_git_repository_inspect(
        maelys_git_cli_git(context), maelys_cli_operand(context, 0u),
        maelys_cli_operand(context, 1u), &info, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_string(&data, "repository", info.repository);
    mg_json_string(&data, "path", info.path);
    mg_json_string(&data, "identity", info.identity);
    mg_json_string(&data, "headRef", info.head_ref);
    mg_json_string(&data, "headOid", info.head_oid);
    mg_json_i64(&data, "refCount", (int64_t)info.ref_count);
    mg_json_i64(&data, "objectCount", (int64_t)info.object_count);
    mg_json_i64(&data, "objectBytes", (int64_t)info.object_bytes);
    mg_json_end_object(&data);
    return maelys_git_cli_succeed_document(context, &data, NULL, MAELYS_CLI_EXIT_OK);
}

static int emit_repository_transition(maelys_cli_context_t *context,
                                      const char *action,
                                      const char *event_type,
                                      int apply,
                                      const maelys_git_repository_transition_t *transition) {
    const char *source_state = maelys_git_repository_state_name(transition->source_state);
    const char *target_state = maelys_git_repository_state_name(transition->target_state);
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_string(&data, "mode", mode_name(apply));
    mg_json_boolean(&data, "changed", apply);
    mg_json_string(&data, "action", action);
    mg_json_string(&data, "sourceRepository", transition->source_repository);
    mg_json_string(&data, "targetRepository", transition->target_repository);
    mg_json_string(&data, "sourceState", source_state);
    mg_json_string(&data, "targetState", target_state);
    mg_json_string(&data, "storageId", transition->storage_id);
    mg_json_string(&data, "sourcePath", transition->source_path);
    mg_json_string(&data, "targetPath", transition->target_path);
    mg_json_object(&data, "precondition");
    mg_json_string(&data, "sourceIdentity", transition->source_identity);
    mg_json_boolean(&data, "targetAbsent", 1);
    mg_json_end_object(&data);
    mg_json_object(&data, "event");
    mg_json_string(&data, "version", "1");
    mg_json_string(&data, "type", event_type);
    mg_json_string(&data, "sourceRepository", transition->source_repository);
    mg_json_string(&data, "targetRepository", transition->target_repository);
    mg_json_string(&data, "storageId", transition->storage_id);
    mg_json_string(&data, "sourceIdentity", transition->source_identity);
    mg_json_string(&data, "sourceState", source_state);
    mg_json_string(&data, "targetState", target_state);
    mg_json_end_object(&data);
    mg_json_end_object(&data);
    return maelys_git_cli_succeed_document(context, &data, NULL, MAELYS_CLI_EXIT_OK);
}

static int command_repo_rename(maelys_cli_context_t *context) {
    int apply = maelys_cli_flag(context, "apply");
    maelys_git_error_t error = {0};
    maelys_git_repository_transition_t transition;
    maelys_git_result_t result = maelys_git_repository_rename(
        maelys_cli_operand(context, 0u), maelys_cli_operand(context, 1u),
        maelys_cli_operand(context, 2u),
        maelys_cli_option(context, "expected-source-identity"), apply,
        &transition, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    return emit_repository_transition(context, "rename",
        apply ? "repository_renamed" : "repository_rename_planned", apply, &transition);
}

static int repo_store(maelys_cli_context_t *context,
                      maelys_git_repository_state_t state,
                      const char *action,
                      const char *applied_event,
                      const char *planned_event) {
    int apply = maelys_cli_flag(context, "apply");
    maelys_git_error_t error = {0};
    maelys_git_repository_transition_t transition;
    maelys_git_result_t result = maelys_git_repository_store(
        maelys_cli_operand(context, 0u), maelys_cli_operand(context, 1u), state,
        maelys_cli_operand(context, 2u),
        maelys_cli_option(context, "expected-source-identity"), apply,
        &transition, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    return emit_repository_transition(context, action,
        apply ? applied_event : planned_event, apply, &transition);
}

static int command_repo_archive(maelys_cli_context_t *context) {
    return repo_store(context, MAELYS_GIT_REPOSITORY_ARCHIVE, "archive",
                      "repository_archived", "repository_archive_planned");
}

static int command_repo_delete(maelys_cli_context_t *context) {
    return repo_store(context, MAELYS_GIT_REPOSITORY_TRASH, "delete",
                      "repository_trashed", "repository_delete_planned");
}

static int command_repo_restore(maelys_cli_context_t *context) {
    size_t area = 0u;
    (void)maelys_cli_option_choice(context, "from", &area);
    maelys_git_repository_state_t state = area == 0u ?
        MAELYS_GIT_REPOSITORY_ARCHIVE : MAELYS_GIT_REPOSITORY_TRASH;
    int apply = maelys_cli_flag(context, "apply");
    maelys_git_error_t error = {0};
    maelys_git_repository_transition_t transition;
    maelys_git_result_t result = maelys_git_repository_restore(
        maelys_cli_operand(context, 0u), state, maelys_cli_operand(context, 1u),
        maelys_cli_option(context, "as"),
        maelys_cli_option(context, "expected-source-identity"), apply,
        &transition, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    return emit_repository_transition(context, "restore",
        apply ? "repository_restored" : "repository_restore_planned", apply, &transition);
}

static int command_repo_mirror(maelys_cli_context_t *context) {
    const char *source_repository = maelys_cli_operand(context, 1u);
    const char *target_repository = maelys_cli_option_or(context, "as", source_repository);
    int apply = maelys_cli_flag(context, "apply");
    maelys_git_error_t error = {0};
    maelys_git_repository_mirror_result_t mirror;
    maelys_git_result_t result = maelys_git_repository_mirror(
        maelys_git_cli_git(context),
        maelys_cli_operand(context, 0u), source_repository,
        maelys_cli_operand(context, 2u), target_repository,
        maelys_cli_option(context, "expected-source-identity"),
        maelys_cli_option(context, "expected-target-identity"),
        maelys_cli_option(context, "expected-source-fingerprint"),
        maelys_cli_option(context, "expected-target-fingerprint"),
        apply, &mirror, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    const char *event_type = apply && mirror.changed ? "repository_mirrored" :
                             apply ? "repository_mirror_unchanged" :
                             "repository_mirror_planned";
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_string(&data, "mode", mode_name(apply));
    mg_json_boolean(&data, "changed", apply && mirror.changed);
    mg_json_boolean(&data, "synchronizationRequired", mirror.changed);
    mg_json_string(&data, "sourceRepository", mirror.source_repository);
    mg_json_string(&data, "targetRepository", mirror.target_repository);
    mg_json_string(&data, "sourcePath", mirror.source_path);
    mg_json_string(&data, "targetPath", mirror.target_path);
    mg_json_boolean(&data, "targetExists", mirror.target_exists);
    mg_json_object(&data, "precondition");
    mg_json_string(&data, "sourceIdentity", mirror.source_identity);
    mg_json_string(&data, "targetIdentity", mirror.target_identity);
    mg_json_string(&data, "sourceFingerprint", mirror.source_fingerprint);
    mg_json_string(&data, "targetFingerprint", mirror.target_fingerprint);
    mg_json_end_object(&data);
    mg_json_object(&data, "event");
    mg_json_string(&data, "version", "1");
    mg_json_string(&data, "type", event_type);
    mg_json_string(&data, "sourceRepository", mirror.source_repository);
    mg_json_string(&data, "targetRepository", mirror.target_repository);
    mg_json_string(&data, "sourceFingerprint", mirror.source_fingerprint);
    mg_json_end_object(&data);
    mg_json_end_object(&data);
    return maelys_git_cli_succeed_document(context, &data,
        apply ? (mirror.changed ? "Repository mirror synchronized and verified." :
                                  "Repository mirror already synchronized.") :
                "Mirror plan complete; apply with all returned preconditions.",
        MAELYS_CLI_EXIT_OK);
}

static int command_repo_diff(maelys_cli_context_t *context) {
    const char *old_oid = maelys_cli_operand(context, 2u);
    const char *new_oid = maelys_cli_operand(context, 3u);
    char path[PATH_CAPACITY];
    int failed = maelys_git_cli_resolve_repository(context, maelys_cli_operand(context, 0u),
                                                   maelys_cli_operand(context, 1u),
                                                   path, sizeof(path));
    if (failed) return failed;
    maelys_git_error_t error = {0};
    maelys_git_path_list_t paths;
    maelys_git_result_t result = maelys_git_repository_changed_paths(
        maelys_git_cli_git(context), path, old_oid, new_oid, &paths, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_string(&data, "repository", maelys_cli_operand(context, 1u));
    mg_json_array(&data, "paths");
    for (size_t i = 0u; i < paths.count; ++i) mg_json_string(&data, NULL, paths.items[i]);
    mg_json_end_array(&data);
    mg_json_i64(&data, "pathCount", (int64_t)paths.count);
    mg_json_end_object(&data);
    maelys_git_path_list_clear(&paths);
    return maelys_git_cli_succeed_document(context, &data, NULL, MAELYS_CLI_EXIT_OK);
}

static int command_repo_update_ref(maelys_cli_context_t *context) {
    const char *ref = maelys_cli_operand(context, 2u);
    const char *new_oid = maelys_cli_operand(context, 3u);
    const char *old_oid = maelys_cli_operand(context, 4u);
    if (!maelys_git_ref_name_is_valid(ref))
        return fail_with_result(context, MAELYS_GIT_ERR_INVALID_ARGUMENT,
                                "invalid full Git reference");
    char path[PATH_CAPACITY];
    int failed = maelys_git_cli_resolve_repository(context, maelys_cli_operand(context, 0u),
                                                   maelys_cli_operand(context, 1u),
                                                   path, sizeof(path));
    if (failed) return failed;
    int apply = maelys_cli_flag(context, "apply");
    maelys_git_error_t error = {0};
    maelys_git_result_t result = MAELYS_GIT_OK;
    if (apply)
        result = maelys_git_repository_update_ref(
            maelys_git_cli_git(context), path, ref, new_oid, old_oid, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_string(&data, "mode", mode_name(apply));
    mg_json_boolean(&data, "changed", apply);
    mg_json_string(&data, "repository", maelys_cli_operand(context, 1u));
    mg_json_string(&data, "ref", ref);
    mg_json_string(&data, "newOid", new_oid);
    mg_json_string(&data, "git", maelys_git_cli_git(context));
    mg_json_object(&data, "precondition");
    mg_json_string(&data, "currentOid", old_oid);
    mg_json_end_object(&data);
    mg_json_end_object(&data);
    return maelys_git_cli_succeed_document(context, &data,
        apply ? "Reference updated." : "Plan only; add --apply to update the reference.",
        MAELYS_CLI_EXIT_OK);
}

/* ---- keys / migrate ------------------------------------------------------------ */

static int command_keys_compile(maelys_cli_context_t *context) {
    int apply = maelys_cli_flag(context, "apply");
    size_t key_count = 0u;
    maelys_git_error_t error = {0};
    maelys_git_result_t result = maelys_git_compile_authorized_keys(
        maelys_cli_operand(context, 0u), maelys_cli_operand(context, 1u),
        maelys_cli_operand(context, 2u), maelys_cli_operand(context, 3u),
        maelys_cli_operand(context, 4u), apply, &key_count, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_string(&data, "mode", mode_name(apply));
    mg_json_boolean(&data, "changed", apply);
    mg_json_string(&data, "keyDirectory", maelys_cli_operand(context, 0u));
    mg_json_string(&data, "output", maelys_cli_operand(context, 1u));
    mg_json_i64(&data, "keyCount", (int64_t)key_count);
    mg_json_end_object(&data);
    return maelys_git_cli_succeed_document(context, &data,
        apply ? "authorized_keys replaced atomically." :
                "Plan only; add --apply to replace authorized_keys.",
        MAELYS_CLI_EXIT_OK);
}

/* The budget of a generated policy, as member `budget`: the engine's counts,
 * null when it refused the policy, the bounds, the generator's worst cases of
 * execution, and the failure, in the shape of a validate diagnostic, or null. */
static void budget_json(mg_json_t *data, const maelys_git_policy_budget_t *budget) {
    mg_json_object(data, "budget");
    mg_json_boolean(data, "compiled", budget->compiled);
    if (budget->compiled) {
        mg_json_i64(data, "rules", (int64_t)budget->rules);
        mg_json_i64(data, "facts", (int64_t)budget->facts);
        mg_json_i64(data, "predicates", (int64_t)budget->predicates);
    } else {
        mg_json_null(data, "rules");
        mg_json_null(data, "facts");
        mg_json_null(data, "predicates");
    }
    mg_json_i64(data, "ruleLimit", (int64_t)budget->rule_limit);
    mg_json_i64(data, "factLimit", (int64_t)budget->fact_limit);
    mg_json_i64(data, "predicateLimit", (int64_t)budget->predicate_limit);
    mg_json_i64(data, "derivedPerPredicate", (int64_t)budget->derived_per_predicate);
    mg_json_i64(data, "derivedPerPredicateLimit", (int64_t)budget->derived_per_predicate_limit);
    mg_json_i64(data, "derived", (int64_t)budget->derived);
    mg_json_i64(data, "derivedLimit", (int64_t)budget->derived_limit);
    if (budget->failure.kind == MAELYS_GIT_FAILURE_NONE) {
        mg_json_null(data, "failure");
    } else {
        mg_json_object(data, "failure");
        mg_json_failure_detail(data, &budget->failure);
        mg_json_end_object(data);
    }
    mg_json_end_object(data);
}

static int command_migrate_gitolite(maelys_cli_context_t *context) {
    int apply = maelys_cli_flag(context, "apply");
    maelys_git_error_t error = {0};
    maelys_git_gitolite_migration_result_t migration;
    maelys_git_result_t result = maelys_git_migrate_gitolite(
        maelys_cli_operand(context, 0u), maelys_cli_operand(context, 1u),
        apply, &migration, &error);
    if (result != MAELYS_GIT_OK) {
        maelys_git_gitolite_migration_result_clear(&migration);
        return maelys_git_cli_fail_result(context, result, &error);
    }
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_string(&data, "mode", mode_name(apply));
    mg_json_boolean(&data, "changed", apply);
    mg_json_string(&data, "input", maelys_cli_operand(context, 0u));
    mg_json_string(&data, "output", maelys_cli_operand(context, 1u));
    mg_json_i64(&data, "groupCount", (int64_t)migration.group_count);
    mg_json_i64(&data, "repositoryCount", (int64_t)migration.repository_count);
    mg_json_i64(&data, "ruleCount", (int64_t)migration.rule_count);
    mg_json_i64(&data, "vrefCount", (int64_t)migration.vref_count);
    mg_json_array(&data, "unsupported");
    for (size_t i = 0u; i < migration.unsupported_count; ++i)
        mg_json_string(&data, NULL, migration.unsupported[i]);
    mg_json_end_array(&data);
    mg_json_string(&data, "grantsFormat", migration.grants_format);
    mg_json_array(&data, "remarks");
    for (size_t i = 0u; i < migration.remark_count; ++i)
        mg_json_string(&data, NULL, migration.remarks[i]);
    mg_json_end_array(&data);
    budget_json(&data, &migration.budget);
    mg_json_boolean(&data, "canApply", migration.unsupported_count == 0u);
    mg_json_end_object(&data);
    maelys_git_gitolite_migration_result_clear(&migration);
    return maelys_git_cli_succeed_document(context, &data,
        apply ? "Gitolite policy migration written atomically." :
                "Migration plan complete; review unsupported entries before apply.",
        MAELYS_CLI_EXIT_OK);
}

/* ---- pull requests ------------------------------------------------------------- */

static maelys_git_merge_style_t merge_style(const maelys_cli_context_t *context) {
    size_t index = 0u;
    (void)maelys_cli_option_choice(context, "style", &index);
    switch (index) {
        case 1u: return MAELYS_GIT_MERGE_COMMIT;
        case 2u: return MAELYS_GIT_MERGE_SQUASH;
        default: return MAELYS_GIT_MERGE_FAST_FORWARD;
    }
}

static int emit_pr_result(maelys_cli_context_t *context,
                          const char *mode,
                          int changed,
                          maelys_git_pr_check_result_t *result) {
    size_t style = 0u;
    (void)maelys_cli_option_choice(context, "style", &style);
    const char *event_type = !strcmp(mode, "apply") ? "pr_merged" :
                             !strcmp(mode, "plan") ? "pr_planned" : "pr_checked";
    mg_json_t data;
    mg_json_begin(&data, MG_JSON_DATA);
    mg_json_object(&data, NULL);
    mg_json_string(&data, "mode", mode);
    mg_json_boolean(&data, "changed", changed);
    mg_json_string(&data, "repository", maelys_cli_operand(context, 1u));
    mg_json_string(&data, "style", merge_styles[style]);
    mg_json_boolean(&data, "mergeable", result->mergeable);
    mg_json_boolean(&data, "empty", result->empty);
    mg_json_boolean(&data, "crossRepository", result->cross_repository);
    mg_json_string(&data, "sourceRepository", result->source_repository);
    mg_json_string(&data, "sourceRef", result->source_ref);
    mg_json_string(&data, "sourceOid", result->source_oid);
    mg_json_string(&data, "sourceIdentity", result->source_identity);
    mg_json_i64(&data, "sourceObjectCount", (int64_t)result->source_object_count);
    mg_json_i64(&data, "sourceObjectBytes", (int64_t)result->source_object_bytes);
    mg_json_string(&data, "targetIdentity", result->target_identity);
    mg_json_string(&data, "mergeBaseOid", result->merge_base_oid);
    mg_json_string(&data, "mergeTreeOid", result->merge_tree_oid);
    mg_json_string(&data, "preparedOid", result->prepared_oid);
    mg_json_string(&data, "policyFingerprint", result->policy_fingerprint);
    mg_json_string(&data, "grantsFingerprint", result->grants_fingerprint);
    mg_json_string(&data, "prId", result->pr_id);
    mg_json_string(&data, "prHeadRef", result->pr_head_ref);
    mg_json_string(&data, "prMergedRef", result->pr_merged_ref);
    mg_json_array(&data, "conflicts");
    for (size_t i = 0u; i < result->conflict_paths.count; ++i)
        mg_json_string(&data, NULL, result->conflict_paths.items[i]);
    mg_json_end_array(&data);
    maelys_git_cli_change_summary(&data, "changeSummary", &result->changes);
    if (result->has_applied_changes)
        maelys_git_cli_change_summary(&data, "appliedChangeSummary", &result->applied_changes);
    else
        mg_json_null(&data, "appliedChangeSummary");
    mg_json_object(&data, "event");
    mg_json_string(&data, "version", "1");
    mg_json_string(&data, "type", event_type);
    mg_json_string(&data, "prId", result->pr_id);
    mg_json_string(&data, "preparedOid", result->prepared_oid);
    mg_json_string(&data, "policyFingerprint", result->policy_fingerprint);
    mg_json_string(&data, "targetIdentity", result->target_identity);
    mg_json_boolean(&data, "crossRepository", result->cross_repository);
    mg_json_string(&data, "sourceRepository", result->source_repository);
    mg_json_string(&data, "sourceRef", result->source_ref);
    mg_json_string(&data, "sourceOid", result->source_oid);
    mg_json_end_object(&data);
    mg_json_end_object(&data);
    maelys_git_pr_check_result_clear(result);
    return maelys_git_cli_succeed_document(context, &data, NULL, MAELYS_CLI_EXIT_OK);
}

/* Builds the optional fork source from --source-repository and friends. The
 * catalog already enforces the option dependencies; the handler resolves the
 * repository and converts the typed quotas. */
static int pr_source_options(maelys_cli_context_t *context,
                             char source_path[PATH_CAPACITY],
                             maelys_git_pr_source_t *source,
                             const maelys_git_pr_source_t **out_source) {
    const char *repository = maelys_cli_option(context, "source-repository");
    const char *ref = maelys_cli_option(context, "source-ref");
    *out_source = NULL;
    memset(source, 0, sizeof(*source));
    if (!repository || !ref) return 0;
    int failed = maelys_git_cli_resolve_repository(
        context, maelys_cli_operand(context, 0u), repository, source_path, PATH_CAPACITY);
    if (failed) return failed;
    /* The typed accessors deliver the catalog defaults when absent. */
    uint64_t max_objects = 0u;
    uint64_t max_bytes = 0u;
    (void)maelys_cli_option_unsigned(context, "max-source-objects", &max_objects);
    (void)maelys_cli_option_unsigned(context, "max-source-bytes", &max_bytes);
#if SIZE_MAX < UINT64_MAX
    if (max_objects > SIZE_MAX)
        return maelys_cli_fail(context, MAELYS_CLI_CODE_VALIDATION_FAILED,
            "Lower --max-source-objects to a host-sized value.",
            "--max-source-objects exceeds this host's address space.");
#endif
    source->repository_path = source_path;
    source->repository_name = repository;
    source->ref_name = ref;
    source->expected_identity = maelys_cli_option(context, "expected-source-identity");
    source->max_objects = (size_t)max_objects;
    source->max_bytes = max_bytes;
    *out_source = source;
    return 0;
}

static int command_pr_check(maelys_cli_context_t *context) {
    char repository_path[PATH_CAPACITY];
    int failed = maelys_git_cli_resolve_repository(
        context, maelys_cli_operand(context, 0u), maelys_cli_operand(context, 1u),
        repository_path, sizeof(repository_path));
    char source_path[PATH_CAPACITY];
    maelys_git_pr_source_t source_storage;
    const maelys_git_pr_source_t *source = NULL;
    if (!failed) failed = pr_source_options(context, source_path, &source_storage, &source);
    if (failed) return failed;
    maelys_git_error_t error = {0};
    maelys_git_pr_check_result_t check;
    maelys_git_result_t result = maelys_git_pr_check_with_source(
        maelys_git_cli_git(context), repository_path,
        maelys_cli_operand(context, 2u), maelys_cli_operand(context, 3u),
        merge_style(context), maelys_cli_option(context, "message"), source, &check, &error);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    return emit_pr_result(context, "check", 0, &check);
}

static int command_pr_merge(maelys_cli_context_t *context) {
    char repository_path[PATH_CAPACITY];
    int failed = maelys_git_cli_resolve_repository(
        context, maelys_cli_operand(context, 0u), maelys_cli_operand(context, 1u),
        repository_path, sizeof(repository_path));
    char source_path[PATH_CAPACITY];
    maelys_git_pr_source_t source_storage;
    const maelys_git_pr_source_t *source = NULL;
    if (!failed) failed = pr_source_options(context, source_path, &source_storage, &source);
    if (failed) return failed;
    uint64_t approvals = 0u;
    uint64_t required_approvals = 0u;
    (void)maelys_cli_option_unsigned(context, "approvals", &approvals);
    (void)maelys_cli_option_unsigned(context, "required-approvals", &required_approvals);
    maelys_git_pr_gates_t gates = {
        .approvals = (size_t)approvals,
        .required_approvals = (size_t)required_approvals,
        .status_checks_passed = maelys_cli_flag(context, "status-checks-passed"),
        .blocking_review = maelys_cli_flag(context, "blocking-review"),
    };
    int apply = maelys_cli_flag(context, "apply");
    const char *expected_prepared_oid = maelys_cli_option(context, "expected-prepared-oid");
    const char *expected_policy_fingerprint =
        maelys_cli_option(context, "expected-policy-fingerprint");
    const char *expected_target_identity =
        maelys_cli_option(context, "expected-target-identity");
    maelys_git_policy_t *policy = NULL;
    failed = maelys_git_cli_open_policy(context, maelys_cli_operand(context, 5u),
                                        maelys_cli_option(context, "grants"), &policy);
    if (failed) return failed;
    maelys_git_error_t error = {0};
    maelys_git_pr_check_result_t check;
    maelys_git_result_t result = maelys_git_pr_merge_grants(
        maelys_git_cli_git(context), repository_path, maelys_cli_operand(context, 1u),
        maelys_cli_operand(context, 2u), maelys_cli_operand(context, 3u),
        maelys_cli_operand(context, 4u), merge_style(context),
        maelys_cli_option(context, "message"), maelys_cli_operand(context, 6u),
        &gates, policy, maelys_cli_option(context, "pr-id"), source,
        expected_target_identity, expected_prepared_oid, expected_policy_fingerprint,
        maelys_cli_option(context, "expected-grants-fingerprint"), apply, &check, &error);
    maelys_git_policy_close(policy);
    if (result != MAELYS_GIT_OK) return maelys_git_cli_fail_result(context, result, &error);
    return emit_pr_result(context, mode_name(apply), apply, &check);
}

/* ---- catalog ------------------------------------------------------------------- */

static const maelys_cli_command_t commands[] = {
    {MAELYS_CLI_READ("validate", "validate", "Validate a Datalog policy manifest.",
     command_validate),
     MAELYS_CLI_OPERANDS(validate_operands), MAELYS_CLI_OPTIONS(validate_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_validate)},
    {MAELYS_CLI_READ("authorize", "authorize", "Evaluate one authorization request.",
     command_authorize),
     MAELYS_CLI_OPERANDS(authorize_operands), MAELYS_CLI_OPTIONS(authorize_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_authorize)},
    {MAELYS_CLI_READ("parse-ssh", "parse-ssh", "Parse a forced SSH Git command.",
     command_parse_ssh),
     MAELYS_CLI_OPERANDS(parse_ssh_operands),
     MAELYS_CLI_SCHEMA(maelys_git_schema_parse_ssh)},
    {MAELYS_CLI_TRANSACTION("repo.init", "repo init", "Plan or create a bare repository.",
     command_repo_init),
     MAELYS_CLI_OPERANDS(repo_operands), MAELYS_CLI_OPTIONS(git_apply_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_repo_init)},
    {MAELYS_CLI_READ("repo.list", "repo list",
     "Inventory active repositories and optionally recoverable stored repositories.",
     command_repo_list),
     MAELYS_CLI_OPERANDS(repo_list_operands), MAELYS_CLI_OPTIONS(repo_list_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_repo_list)},
    {MAELYS_CLI_READ("repo.inspect", "repo inspect",
     "Inspect the identity, HEAD, refs and object storage of an active repository.",
     command_repo_inspect),
     MAELYS_CLI_OPERANDS(repo_operands), MAELYS_CLI_OPTIONS(git_option),
     MAELYS_CLI_SCHEMA(maelys_git_schema_repo_inspect)},
    {MAELYS_CLI_TRANSACTION("repo.rename", "repo rename",
     "Plan or atomically rename an active repository.", command_repo_rename),
     MAELYS_CLI_OPERANDS(repo_rename_operands), MAELYS_CLI_OPTIONS(lifecycle_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_repo_transition)},
    {MAELYS_CLI_TRANSACTION("repo.archive", "repo archive",
     "Plan or move a repository into recoverable archive storage.", command_repo_archive),
     MAELYS_CLI_OPERANDS(repo_store_operands), MAELYS_CLI_OPTIONS(lifecycle_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_repo_transition)},
    {MAELYS_CLI_TRANSACTION("repo.delete", "repo delete",
     "Plan or move a repository into recoverable trash without erasing objects.",
     command_repo_delete),
     MAELYS_CLI_OPERANDS(repo_store_operands), MAELYS_CLI_OPTIONS(lifecycle_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_repo_transition)},
    {MAELYS_CLI_TRANSACTION("repo.restore", "repo restore",
     "Plan or restore an archived or deleted repository.", command_repo_restore),
     MAELYS_CLI_OPERANDS(repo_restore_operands), MAELYS_CLI_OPTIONS(restore_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_repo_transition)},
    {MAELYS_CLI_TRANSACTION("repo.mirror", "repo mirror",
     "Plan or idempotently synchronize a complete local bare mirror.", command_repo_mirror),
     MAELYS_CLI_OPERANDS(repo_mirror_operands), MAELYS_CLI_OPTIONS(mirror_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_repo_mirror)},
    {MAELYS_CLI_READ("repo.diff", "repo diff", "List changed paths between Git objects.",
     command_repo_diff),
     MAELYS_CLI_OPERANDS(repo_diff_operands), MAELYS_CLI_OPTIONS(git_option),
     MAELYS_CLI_SCHEMA(maelys_git_schema_repo_diff)},
    {MAELYS_CLI_TRANSACTION("repo.update-ref", "repo update-ref",
     "Plan or compare-and-swap a Git reference.", command_repo_update_ref),
     MAELYS_CLI_OPERANDS(repo_update_ref_operands), MAELYS_CLI_OPTIONS(git_apply_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_repo_update_ref)},
    {MAELYS_CLI_TRANSACTION("keys.compile", "keys compile",
     "Plan or atomically compile forced-command SSH keys.", command_keys_compile),
     MAELYS_CLI_OPERANDS(keys_compile_operands), MAELYS_CLI_OPTIONS(apply_option),
     MAELYS_CLI_SCHEMA(maelys_git_schema_keys_compile)},
    {MAELYS_CLI_TRANSACTION("migrate.gitolite", "migrate gitolite",
     "Compile the safe Gitolite ACL subset and report every incompatible entry.",
     command_migrate_gitolite),
     MAELYS_CLI_OPERANDS(migrate_gitolite_operands), MAELYS_CLI_OPTIONS(apply_option),
     MAELYS_CLI_SCHEMA(maelys_git_schema_migrate_gitolite)},
    {MAELYS_CLI_READ("pr.check", "pr check",
     "Compute merge-base, conflicts, emptiness and a prepared result in an isolated quarantine.",
     command_pr_check),
     MAELYS_CLI_OPERANDS(pr_check_operands), MAELYS_CLI_OPTIONS(pr_check_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_pr)},
    {MAELYS_CLI_TRANSACTION("pr.merge", "pr merge",
     "Plan or execute a gated, reauthorized pull request merge with reviewed repository "
     "identities and compare-and-swap.", command_pr_merge),
     MAELYS_CLI_OPERANDS(pr_merge_operands), MAELYS_CLI_OPTIONS(pr_merge_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_pr)},
};

const maelys_cli_app_t maelys_git_cli_admin_app = {
    .program = "maelys-git",
    .product = "Maelys Git Core",
    .version = MAELYS_GIT_VERSION,
    .summary = "policy-aware Git administration for humans and agents",
    .commands = commands,
    .command_count = MAELYS_CLI_COUNT(commands),
};
