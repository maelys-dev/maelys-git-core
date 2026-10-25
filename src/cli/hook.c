/* maelys-git-hook: Git receive hooks. `pre-receive` authorizes a bounded
 * transaction read from stdin; `post-receive` converts updates into JSONL
 * events. Both are protocol streams: stdout never carries a CLI envelope. */
#include "cli/support.h"
#include "internal.h"
#include "receipt/receipt_internal.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define HOOK_LIMIT_MAX ((uint64_t)SIZE_MAX)

static const maelys_cli_option_t pre_receive_options[] = {
    {MAELYS_CLI_STRING("repository", "NAME", "Repository name."), .required = 1},
    {MAELYS_CLI_PATH("manifest", "FILE", "Datalog manifest path."), .required = 1},
    MAELYS_GIT_CLI_GRANTS_OPTION,
    {MAELYS_CLI_STRING("user", "PRINCIPAL",
     "Authenticated principal; defaults to MAELYS_GIT_PRINCIPAL.")},
    MAELYS_GIT_CLI_GIT_OPTION,
    {MAELYS_CLI_PATH("git-dir", "DIR", "Bare Git directory; defaults to GIT_DIR.")},
    /* Defaults have one source: the library constants. */
    {MAELYS_CLI_UNSIGNED("max-commits", "COUNT",
     "Maximum commits inspected across the receive transaction.", 1u, HOOK_LIMIT_MAX),
     MAELYS_CLI_DEFAULT_OF(MAELYS_GIT_DEFAULT_MAX_COMMITS)},
    {MAELYS_CLI_UNSIGNED("max-changes", "COUNT",
     "Maximum changed paths across the receive transaction.", 1u, HOOK_LIMIT_MAX),
     MAELYS_CLI_DEFAULT_OF(MAELYS_GIT_DEFAULT_MAX_CHANGES)},
    {MAELYS_CLI_SIZE("max-total-blob-bytes", "BYTES",
     "Maximum total size of new blobs across the receive transaction.", 1u, 0u),
     MAELYS_CLI_DEFAULT_OF(MAELYS_GIT_DEFAULT_MAX_TOTAL_NEW_BLOB_BYTES)},
    {MAELYS_CLI_SIZE("max-inspected-blob-bytes", "BYTES",
     "Maximum blob content consumed across the receive transaction.", 1u, HOOK_LIMIT_MAX),
     MAELYS_CLI_DEFAULT_OF(MAELYS_GIT_DEFAULT_MAX_INSPECTED_BLOB_BYTES)},
    {MAELYS_CLI_PATH("receipts", "FILE",
     "Append one receipt line per push: the first denial with its explanation, "
     "or the final authorization of an accepted push.")},
};

static const maelys_cli_option_t post_receive_options[] = {
    {MAELYS_CLI_STRING("repository", "NAME", "Repository name."), .required = 1},
    {MAELYS_CLI_STRING("user", "PRINCIPAL",
     "Authenticated principal; defaults to MAELYS_GIT_PRINCIPAL.")},
    {MAELYS_CLI_PATH("events", "FILE", "Append-only JSONL event file; stdout when omitted.")},
};

static const char *principal(const maelys_cli_context_t *context) {
    const char *user = maelys_cli_option(context, "user");
    return user ? user : getenv("MAELYS_GIT_PRINCIPAL");
}

static int missing_principal(maelys_cli_context_t *context, const char *operation) {
    maelys_git_error_t error = {.code = MAELYS_GIT_ERR_INVALID_ARGUMENT};
    (void)snprintf(error.message, sizeof(error.message),
                   "principal is missing; pass --user or MAELYS_GIT_PRINCIPAL");
    return maelys_git_cli_stream_error(context, operation, error.code, &error);
}

/* The typed accessors always deliver a value: the invocation's or the
 * catalog default, declared from the library constant. */
static void read_limit(const maelys_cli_context_t *context, const char *name, size_t *out) {
    uint64_t value = 0u;
    if (maelys_cli_option_unsigned(context, name, &value)) *out = (size_t)value;
}

static int command_pre_receive(maelys_cli_context_t *context) {
    const char *user = principal(context);
    if (!user || !*user) return missing_principal(context, "pre-receive");
    const char *git_dir = maelys_cli_option(context, "git-dir");
    if (!git_dir) {
        git_dir = getenv("GIT_DIR");
        if (!git_dir || !*git_dir) git_dir = ".";
    }
    maelys_git_inspection_limits_t limits;
    maelys_git_inspection_limits_default(&limits);
    read_limit(context, "max-commits", &limits.max_commits);
    read_limit(context, "max-changes", &limits.max_changes);
    read_limit(context, "max-inspected-blob-bytes", &limits.max_inspected_blob_bytes);
    uint64_t total = 0u;
    if (maelys_cli_option_unsigned(context, "max-total-blob-bytes", &total))
        limits.max_total_new_blob_size = total;
    maelys_git_error_t error = {0};
    /* With --receipts, the file is opened before anything is decided: a push
     * whose receipt cannot be written is refused. */
    const char *receipts_path = maelys_cli_option(context, "receipts");
    FILE *receipts = receipts_path ? fopen(receipts_path, "a") : NULL;
    if (receipts_path && !receipts) {
        error.code = MAELYS_GIT_ERR_IO;
        error.system_error = errno;
        (void)snprintf(error.message, sizeof(error.message),
                       "cannot open receipt output: %s", strerror(errno));
        return maelys_git_cli_stream_error(context, "pre-receive", error.code, &error);
    }
    static char text[MAELYS_GIT_RECEIPT_MAX_EXPLANATION_TEXT + 1u];
    mg_receive_receipt_t receipt = {.mode = MAELYS_GIT_EXPLAIN_ON_DENIAL, .text = text,
                                    .text_capacity = sizeof(text)};
    /* One snapshot of grants for the whole push: every ref decides on the
     * generation read here. */
    const char *manifest = maelys_cli_option(context, "manifest");
    const char *grants = maelys_cli_option(context, "grants");
    maelys_git_policy_t *policy = NULL;
    maelys_git_result_t result = grants ? maelys_git_policy_open_grants(manifest, grants, &policy, &error)
                                        : maelys_git_policy_open(manifest, &policy, &error);
    if (result == MAELYS_GIT_OK) result = mg_receive_objects_begin(git_dir, &error);
    if (result == MAELYS_GIT_OK)
        result = mg_receive_authorize(
            policy, maelys_git_cli_git(context), git_dir,
            maelys_cli_option(context, "repository"), user, &limits, NULL, 0u,
            stdin, context->err, NULL, NULL, receipts ? &receipt : NULL, &error);
    mg_receive_objects_end();
    maelys_git_policy_close(policy);
    if (receipts) {
        maelys_git_error_t write_error = {0};
        const maelys_git_receipt_explanation_t *explanation = &receipt.receipt.explanation;
        maelys_git_result_t written = !receipt.decided ? MAELYS_GIT_OK :
            mg_receipt_write_line(receipts, &receipt.receipt,
                                  explanation->has_text && text[0] ? text : NULL, &write_error);
        if (fclose(receipts) != 0 && written == MAELYS_GIT_OK) {
            write_error.code = written = MAELYS_GIT_ERR_IO;
            write_error.system_error = errno;
            (void)snprintf(write_error.message, sizeof(write_error.message),
                           "cannot close receipt output: %s", strerror(errno));
        }
        if (written != MAELYS_GIT_OK && result == MAELYS_GIT_OK) {
            result = written;
            error = write_error;
        }
    }
    return result == MAELYS_GIT_OK ? MAELYS_CLI_EXIT_OK :
        maelys_git_cli_stream_error(context, "pre-receive", result, &error);
}

static int command_post_receive(maelys_cli_context_t *context) {
    const char *user = principal(context);
    if (!user || !*user) return missing_principal(context, "post-receive");
    const char *events_path = maelys_cli_option(context, "events");
    FILE *events = events_path ? fopen(events_path, "a") : context->out;
    if (!events) {
        maelys_git_error_t error = {.code = MAELYS_GIT_ERR_IO, .system_error = errno};
        (void)snprintf(error.message, sizeof(error.message),
                       "cannot open event output: %s", strerror(errno));
        return maelys_git_cli_stream_error(context, "post-receive", error.code, &error);
    }
    maelys_git_error_t error = {0};
    maelys_git_result_t result = maelys_git_post_receive(
        maelys_cli_option(context, "repository"), user, stdin, events, &error);
    if (events_path && fclose(events) != 0 && result == MAELYS_GIT_OK) {
        error.code = MAELYS_GIT_ERR_IO;
        error.system_error = errno;
        (void)snprintf(error.message, sizeof(error.message),
                       "cannot close event output: %s", strerror(errno));
        result = error.code;
    }
    return result == MAELYS_GIT_OK ? MAELYS_CLI_EXIT_OK :
        maelys_git_cli_stream_error(context, "post-receive", result, &error);
}

static const maelys_cli_command_t commands[] = {
    {MAELYS_CLI_PROTOCOL_STREAM("pre-receive", "pre-receive",
     "Authorize a quota-bounded Git receive transaction from stdin.",
     command_pre_receive, "git-hook"),
     MAELYS_CLI_OPTIONS(pre_receive_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_protocol_stream)},
    {MAELYS_CLI_PROTOCOL_STREAM("post-receive", "post-receive",
     "Convert received refs into JSONL events.",
     command_post_receive, "maelys-git-events/1"),
     MAELYS_CLI_OPTIONS(post_receive_options),
     MAELYS_CLI_SCHEMA(maelys_git_schema_protocol_stream)},
};

const maelys_cli_app_t maelys_git_cli_hook_app = {
    .program = "maelys-git-hook",
    .product = "Maelys Git Hook",
    .version = MAELYS_GIT_VERSION,
    .summary = "policy-checked Git receive hooks",
    .commands = commands,
    .command_count = MAELYS_CLI_COUNT(commands),
};
