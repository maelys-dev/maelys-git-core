/* Authorization receipts as bytes. maelys-json is their only writer and
 * reader: the writer produces Maelys Canonical JSON v1, and verification
 * demands that form back, with the closed shape of version 1. */
#include "receipt/receipt_internal.h"
#include "internal.h"

#include <maelys/cli/digest.h>

#include <stdlib.h>
#include <string.h>

#define RECEIPT_VERSION 1u
#define RECEIPT_DEPTH 4u
#define RECEIPT_TOKENS 512u

static const maelys_json_limits_t k_limits = {
    .maximum_bytes = MAELYS_GIT_RECEIPT_MAX_BYTES,
    .maximum_depth = RECEIPT_DEPTH,
    .maximum_tokens = RECEIPT_TOKENS,
};

static const char *const k_decisions[] = {"allow", "deny_explicit", "deny_default", "deny_error"};
static const char *const k_kinds[] = {"none", "why_true", "why_false"};
static const char *const k_statuses[] = {"not_requested", "complete", "truncated", "not_applicable",
                                         "unknown"};
static const char *const k_error_kinds[] = {"capacity", "syntax", "semantics", "manifest", "value",
                                            "engine"};
/* In the order of the MAELYS_GIT_RECEIPT_LIMIT_ bits. */
static const char *const k_limits_hit[] = {"candidate-rules", "substitutions", "depth", "diagnostics",
                                           "filter-cost"};
#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

static maelys_git_result_t writer_failure(maelys_json_result_t status, const char *operation,
                                        maelys_git_error_t *error) {
    maelys_git_result_t code = status == MAELYS_JSON_ERR_LIMIT ? MAELYS_GIT_ERR_LIMIT :
                               status == MAELYS_JSON_ERR_MEMORY ? MAELYS_GIT_ERR_IO :
                                                                  MAELYS_GIT_ERR_PROTOCOL;
    mg_error_set(error, code, 0, "%s: %s", operation, maelys_json_result_string(status));
    return code;
}

/* ---- writing --------------------------------------------------------------- */

static maelys_json_result_t key_string(maelys_json_writer_t *writer, const char *key, const char *value) {
    maelys_json_result_t status = maelys_json_writer_key_cstr(writer, key);
    return status == MAELYS_JSON_OK ? maelys_json_writer_string_cstr(writer, value) : status;
}

/* An empty string is null. */
static maelys_json_result_t key_optional(maelys_json_writer_t *writer, const char *key, const char *value) {
    if (value[0]) return key_string(writer, key, value);
    maelys_json_result_t status = maelys_json_writer_key_cstr(writer, key);
    return status == MAELYS_JSON_OK ? maelys_json_writer_null(writer) : status;
}

static maelys_json_result_t key_u64(maelys_json_writer_t *writer, const char *key, uint64_t value) {
    maelys_json_result_t status = maelys_json_writer_key_cstr(writer, key);
    return status == MAELYS_JSON_OK ? maelys_json_writer_u64(writer, value) : status;
}

static maelys_json_result_t key_u64_if(maelys_json_writer_t *writer, const char *key, int present,
                                       uint64_t value) {
    if (present) return key_u64(writer, key, value);
    maelys_json_result_t status = maelys_json_writer_key_cstr(writer, key);
    return status == MAELYS_JSON_OK ? maelys_json_writer_null(writer) : status;
}

static maelys_json_result_t key_null(maelys_json_writer_t *writer, const char *key) {
    maelys_json_result_t status = maelys_json_writer_key_cstr(writer, key);
    return status == MAELYS_JSON_OK ? maelys_json_writer_null(writer) : status;
}

static maelys_json_result_t write_explanation(maelys_json_writer_t *writer,
                                              const maelys_git_receipt_t *receipt) {
    const maelys_git_receipt_explanation_t *explanation = &receipt->explanation;
    int none = explanation->kind == MAELYS_GIT_EXPLANATION_NONE;
    maelys_json_result_t status = maelys_json_writer_key_cstr(writer, "explanation");
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_begin(writer);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_key_cstr(writer, "counts");
    if (status == MAELYS_JSON_OK && (none || !explanation->has_counts))
        status = maelys_json_writer_null(writer);
    else if (status == MAELYS_JSON_OK) {
        status = maelys_json_writer_object_begin(writer);
        if (status == MAELYS_JSON_OK) status = key_u64(writer, "candidateRules", explanation->candidate_rules);
        if (status == MAELYS_JSON_OK) status = key_u64(writer, "diagnostics", explanation->diagnostics);
        if (status == MAELYS_JSON_OK) status = key_u64(writer, "filterCostUnits", explanation->filter_cost_units);
        if (status == MAELYS_JSON_OK) status = key_u64(writer, "substitutions", explanation->substitutions);
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_end(writer);
    }
    if (status == MAELYS_JSON_OK)
        status = key_string(writer, "kind", k_kinds[none ? 0 : explanation->kind]);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_key_cstr(writer, "limitHits");
    if (status == MAELYS_JSON_OK && (none || !explanation->has_counts))
        status = maelys_json_writer_null(writer);
    else if (status == MAELYS_JSON_OK) {
        status = maelys_json_writer_array_begin(writer);
        for (size_t i = 0u; status == MAELYS_JSON_OK && i < COUNT(k_limits_hit); ++i)
            if (explanation->limit_hits & (1u << i))
                status = maelys_json_writer_string_cstr(writer, k_limits_hit[i]);
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_array_end(writer);
    }
    if (status == MAELYS_JSON_OK)
        status = key_u64_if(writer, "policyIndex", !none, explanation->policy_index);
    if (status == MAELYS_JSON_OK)
        status = key_u64_if(writer, "premiseCount", !none && explanation->has_rule, explanation->premise_count);
    if (status == MAELYS_JSON_OK)
        status = none ? key_null(writer, "query") : key_string(writer, "query", explanation->query);
    if (status == MAELYS_JSON_OK)
        status = key_u64_if(writer, "ruleId", !none && explanation->has_rule, explanation->rule_id);
    if (status == MAELYS_JSON_OK)
        status = key_string(writer, "status", k_statuses[none ? 0 : explanation->status]);
    if (status == MAELYS_JSON_OK)
        status = key_u64_if(writer, "stepCount", !none && explanation->has_rule, explanation->step_count);
    if (status == MAELYS_JSON_OK)
        status = key_u64_if(writer, "textBytes", !none && explanation->has_text, explanation->text_bytes);
    if (status == MAELYS_JSON_OK)
        status = !none && explanation->has_text ? key_string(writer, "textSha256", explanation->text_sha256)
                                                : key_null(writer, "textSha256");
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_end(writer);
    return status;
}

static maelys_json_result_t write_receipt(maelys_json_writer_t *writer, const maelys_git_receipt_t *receipt) {
    maelys_json_result_t status = maelys_json_writer_object_begin(writer);
    if (status == MAELYS_JSON_OK) status = key_string(writer, "decision", k_decisions[receipt->decision - 1]);
    if (status == MAELYS_JSON_OK) status = key_optional(writer, "errorBudget", receipt->error_budget);
    if (status == MAELYS_JSON_OK) status = key_optional(writer, "errorCode", receipt->error_code);
    if (status == MAELYS_JSON_OK) status = key_optional(writer, "errorKind", receipt->error_kind);
    if (status == MAELYS_JSON_OK) status = write_explanation(writer, receipt);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_key_cstr(writer, "matched");
    if (status == MAELYS_JSON_OK && !receipt->matched) status = maelys_json_writer_null(writer);
    else if (status == MAELYS_JSON_OK) {
        status = maelys_json_writer_object_begin(writer);
        if (status == MAELYS_JSON_OK) status = key_string(writer, "policyId", receipt->matched_policy_id);
        if (status == MAELYS_JSON_OK) status = key_u64(writer, "policyIndex", receipt->matched_policy_index);
        if (status == MAELYS_JSON_OK)
            status = key_string(writer, "sessionFingerprint", receipt->matched_session_fingerprint);
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_end(writer);
    }
    if (status == MAELYS_JSON_OK)
        status = key_string(writer, "policySetFingerprint", receipt->policy_set_fingerprint);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_key_cstr(writer, "request");
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_begin(writer);
    if (status == MAELYS_JSON_OK) status = key_string(writer, "id", receipt->request.id);
    if (status == MAELYS_JSON_OK) status = key_string(writer, "operation", receipt->request.operation);
    if (status == MAELYS_JSON_OK) status = key_u64(writer, "pathCount", receipt->request.path_count);
    if (status == MAELYS_JSON_OK) status = key_string(writer, "principal", receipt->request.principal);
    if (status == MAELYS_JSON_OK) status = key_optional(writer, "ref", receipt->request.ref);
    if (status == MAELYS_JSON_OK) status = key_string(writer, "repository", receipt->request.repository);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_end(writer);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_key_cstr(writer, "stats");
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_begin(writer);
    if (status == MAELYS_JSON_OK) status = key_u64(writer, "edbFacts", receipt->edb_facts);
    if (status == MAELYS_JSON_OK) status = key_u64(writer, "evaluatedPolicies", receipt->evaluated_policies);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_end(writer);
    if (status == MAELYS_JSON_OK) status = key_u64(writer, "version", RECEIPT_VERSION);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_end(writer);
    return status;
}

static int known_enums(const maelys_git_receipt_t *receipt) {
    return receipt->decision >= MAELYS_GIT_RECEIPT_ALLOW && receipt->decision <= MAELYS_GIT_RECEIPT_DENY_ERROR &&
           receipt->explanation.kind <= MAELYS_GIT_EXPLANATION_WHY_FALSE &&
           receipt->explanation.status <= MAELYS_GIT_RECEIPT_STATUS_UNKNOWN;
}

maelys_git_result_t mg_receipt_serialize_within(const maelys_git_receipt_t *receipt, size_t maximum_bytes,
                                                char **out_bytes, size_t *out_size, char out_sha256[65],
                                                maelys_git_error_t *error) {
    if (!receipt || !out_bytes || !out_size || !out_sha256 || !known_enums(receipt) ||
        maximum_bytes == 0u || maximum_bytes > MAELYS_GIT_RECEIPT_MAX_BYTES) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0, "a valid receipt and outputs are required");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    maelys_json_limits_t limits = k_limits;
    limits.maximum_bytes = maximum_bytes;
    maelys_json_writer_t *writer = NULL;
    maelys_json_result_t status = maelys_json_writer_create(MAELYS_JSON_PROFILE_RFC8259, &limits, 0u, &writer);
    if (status == MAELYS_JSON_OK) status = write_receipt(writer, receipt);
    char *bytes = NULL;
    size_t size = 0u;
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_finish(writer, &bytes, &size);
    maelys_json_writer_release(writer);
    if (status != MAELYS_JSON_OK) return writer_failure(status, "receipt serialization", error);
    maelys_cli_sha256_hex(bytes, size, out_sha256);
    *out_bytes = bytes;
    *out_size = size;
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_receipt_serialize(const maelys_git_receipt_t *receipt, char **out_bytes,
                                                 size_t *out_size, char out_sha256[65],
                                                 maelys_git_error_t *error) {
    return mg_receipt_serialize_within(receipt, MAELYS_GIT_RECEIPT_MAX_BYTES, out_bytes, out_size,
                                       out_sha256, error);
}

/* ---- verification ---------------------------------------------------------- */

typedef struct {
    const maelys_json_document_t *document;
    int ok;
} shape_t;

static maelys_json_value_t member(shape_t *shape, maelys_json_value_t object, const char *key) {
    maelys_json_value_t value = 0;
    if (shape->ok && maelys_json_object_get(shape->document, object, key, &value) != MAELYS_JSON_OK)
        shape->ok = 0;
    return value;
}

/* An object with exactly these keys. */
static void closed_object(shape_t *shape, maelys_json_value_t object, const char *const *keys, size_t count) {
    size_t size = 0u;
    if (!shape->ok || maelys_json_value_type(shape->document, object) != MAELYS_JSON_TYPE_OBJECT ||
        maelys_json_object_size(shape->document, object, &size) != MAELYS_JSON_OK || size != count) {
        shape->ok = 0;
        return;
    }
    for (size_t i = 0u; i < count; ++i) (void)member(shape, object, keys[i]);
}

static int is_null(shape_t *shape, maelys_json_value_t value) {
    return maelys_json_value_type(shape->document, value) == MAELYS_JSON_TYPE_NULL;
}

/* An unsigned integer: a fraction or an exponent is refused. */
static uint64_t unsigned_value(shape_t *shape, maelys_json_value_t value) {
    uint64_t number = 0u;
    if (shape->ok && maelys_json_value_u64(shape->document, value, &number) != MAELYS_JSON_OK) shape->ok = 0;
    return number;
}

static void unsigned_or_null(shape_t *shape, maelys_json_value_t value) {
    if (!is_null(shape, value)) (void)unsigned_value(shape, value);
}

static maelys_json_view_t string_value(shape_t *shape, maelys_json_value_t value) {
    maelys_json_view_t view = {"", 0u};
    if (shape->ok && maelys_json_value_string(shape->document, value, &view) != MAELYS_JSON_OK) shape->ok = 0;
    return view;
}

static size_t one_of(shape_t *shape, maelys_json_value_t value, const char *const *names, size_t count) {
    maelys_json_view_t view = string_value(shape, value);
    for (size_t i = 0u; shape->ok && i < count; ++i)
        if (view.size == strlen(names[i]) && !memcmp(view.data, names[i], view.size)) return i;
    shape->ok = 0;
    return 0u;
}

static void sha256_hex(shape_t *shape, maelys_json_value_t value) {
    maelys_json_view_t view = string_value(shape, value);
    if (view.size != 64u) shape->ok = 0;
    for (size_t i = 0u; shape->ok && i < view.size; ++i)
        if (!((view.data[i] >= '0' && view.data[i] <= '9') || (view.data[i] >= 'a' && view.data[i] <= 'f')))
            shape->ok = 0;
}

static void budget_name(shape_t *shape, maelys_json_value_t value) {
    maelys_json_view_t view = string_value(shape, value);
    if (view.size == 0u || !(view.data[0] >= 'A' && view.data[0] <= 'Z')) shape->ok = 0;
    for (size_t i = 0u; shape->ok && i < view.size; ++i)
        if (!((view.data[i] >= 'A' && view.data[i] <= 'Z') || (view.data[i] >= '0' && view.data[i] <= '9') ||
              view.data[i] == '_'))
            shape->ok = 0;
}

static void check_explanation(shape_t *shape, maelys_json_value_t explanation, mg_receipt_text_t *text) {
    static const char *const keys[] = {"counts", "kind", "limitHits", "policyIndex", "premiseCount", "query",
                                       "ruleId", "status", "stepCount", "textBytes", "textSha256"};
    closed_object(shape, explanation, keys, COUNT(keys));
    size_t kind = one_of(shape, member(shape, explanation, "kind"), k_kinds, COUNT(k_kinds));
    size_t status = one_of(shape, member(shape, explanation, "status"), k_statuses, COUNT(k_statuses));
    if (!shape->ok) return;
    if (kind == 0u) {
        /* Not rendered: every other member is null. */
        if (status != 0u) shape->ok = 0;
        for (size_t i = 0u; shape->ok && i < COUNT(keys); ++i)
            if (strcmp(keys[i], "kind") && strcmp(keys[i], "status") &&
                !is_null(shape, member(shape, explanation, keys[i])))
                shape->ok = 0;
        return;
    }
    if (status == 0u) shape->ok = 0;
    (void)unsigned_value(shape, member(shape, explanation, "policyIndex"));
    static const char *const queries[] = {"allow", "deny"};
    (void)one_of(shape, member(shape, explanation, "query"), queries, COUNT(queries));
    unsigned_or_null(shape, member(shape, explanation, "premiseCount"));
    unsigned_or_null(shape, member(shape, explanation, "ruleId"));
    unsigned_or_null(shape, member(shape, explanation, "stepCount"));
    maelys_json_value_t counts = member(shape, explanation, "counts");
    if (shape->ok && !is_null(shape, counts)) {
        static const char *const count_keys[] = {"candidateRules", "diagnostics", "filterCostUnits",
                                                 "substitutions"};
        closed_object(shape, counts, count_keys, COUNT(count_keys));
        for (size_t i = 0u; shape->ok && i < COUNT(count_keys); ++i)
            (void)unsigned_value(shape, member(shape, counts, count_keys[i]));
    }
    maelys_json_value_t hits = member(shape, explanation, "limitHits");
    if (shape->ok && !is_null(shape, hits)) {
        size_t size = 0u;
        if (maelys_json_array_size(shape->document, hits, &size) != MAELYS_JSON_OK) shape->ok = 0;
        for (size_t i = 0u; shape->ok && i < size; ++i) {
            maelys_json_value_t hit = 0;
            if (maelys_json_array_get(shape->document, hits, i, &hit) != MAELYS_JSON_OK) shape->ok = 0;
            else (void)one_of(shape, hit, k_limits_hit, COUNT(k_limits_hit));
        }
    }
    maelys_json_value_t bytes = member(shape, explanation, "textBytes");
    maelys_json_value_t digest = member(shape, explanation, "textSha256");
    if (!shape->ok) return;
    if (is_null(shape, bytes) != is_null(shape, digest)) {
        shape->ok = 0;
        return;
    }
    if (is_null(shape, bytes)) return;
    uint64_t size = unsigned_value(shape, bytes);
    sha256_hex(shape, digest);
    if (!shape->ok || !text) return;
    maelys_json_view_t view = string_value(shape, digest);
    text->has_text = 1;
    text->text_bytes = (size_t)size;
    memcpy(text->text_sha256, view.data, 64u);
    text->text_sha256[64] = '\0';
}

static int receipt_shape(const maelys_json_document_t *document, mg_receipt_text_t *text) {
    shape_t shape = {document, 1};
    maelys_json_value_t root = maelys_json_document_root(document);
    static const char *const keys[] = {"decision", "errorBudget", "errorCode", "errorKind", "explanation",
                                       "matched", "policySetFingerprint", "request", "stats", "version"};
    closed_object(&shape, root, keys, COUNT(keys));
    if (unsigned_value(&shape, member(&shape, root, "version")) != RECEIPT_VERSION) shape.ok = 0;
    size_t decision = one_of(&shape, member(&shape, root, "decision"), k_decisions, COUNT(k_decisions));
    maelys_json_value_t code = member(&shape, root, "errorCode");
    maelys_json_value_t kind = member(&shape, root, "errorKind");
    maelys_json_value_t budget = member(&shape, root, "errorBudget");
    if (shape.ok && decision == MAELYS_GIT_RECEIPT_DENY_ERROR - 1) {
        if (string_value(&shape, code).size == 0u) shape.ok = 0;
        if (!is_null(&shape, kind)) (void)one_of(&shape, kind, k_error_kinds, COUNT(k_error_kinds));
        if (!is_null(&shape, budget)) budget_name(&shape, budget);
    } else if (shape.ok && (!is_null(&shape, code) || !is_null(&shape, kind) || !is_null(&shape, budget))) {
        shape.ok = 0;
    }
    maelys_json_value_t matched = member(&shape, root, "matched");
    if (shape.ok && !is_null(&shape, matched)) {
        static const char *const matched_keys[] = {"policyId", "policyIndex", "sessionFingerprint"};
        closed_object(&shape, matched, matched_keys, COUNT(matched_keys));
        if (string_value(&shape, member(&shape, matched, "policyId")).size == 0u) shape.ok = 0;
        (void)unsigned_value(&shape, member(&shape, matched, "policyIndex"));
        sha256_hex(&shape, member(&shape, matched, "sessionFingerprint"));
    }
    sha256_hex(&shape, member(&shape, root, "policySetFingerprint"));
    maelys_json_value_t request = member(&shape, root, "request");
    static const char *const request_keys[] = {"id", "operation", "pathCount", "principal", "ref", "repository"};
    closed_object(&shape, request, request_keys, COUNT(request_keys));
    (void)string_value(&shape, member(&shape, request, "id"));
    (void)string_value(&shape, member(&shape, request, "operation"));
    (void)unsigned_value(&shape, member(&shape, request, "pathCount"));
    (void)string_value(&shape, member(&shape, request, "principal"));
    maelys_json_value_t ref = member(&shape, request, "ref");
    if (shape.ok && !is_null(&shape, ref)) (void)string_value(&shape, ref);
    (void)string_value(&shape, member(&shape, request, "repository"));
    maelys_json_value_t stats = member(&shape, root, "stats");
    static const char *const stats_keys[] = {"edbFacts", "evaluatedPolicies"};
    closed_object(&shape, stats, stats_keys, COUNT(stats_keys));
    (void)unsigned_value(&shape, member(&shape, stats, "edbFacts"));
    (void)unsigned_value(&shape, member(&shape, stats, "evaluatedPolicies"));
    check_explanation(&shape, member(&shape, root, "explanation"), text);
    return shape.ok;
}

static maelys_git_result_t verify_bytes(const void *bytes, size_t size, char out_sha256[65],
                                        mg_receipt_text_t *text, maelys_git_error_t *error) {
    if (!bytes || size == 0u) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "a receipt is required");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    maelys_json_document_t *document = NULL;
    maelys_json_result_t status = maelys_json_document_parse(bytes, size, MAELYS_JSON_PROFILE_RFC8259,
                                                             &k_limits, &document, NULL);
    if (status != MAELYS_JSON_OK) {
        /* Bytes that do not parse, or exceed the bounds, are not a receipt. */
        maelys_git_result_t code = status == MAELYS_JSON_ERR_MEMORY ? MAELYS_GIT_ERR_IO : MAELYS_GIT_ERR_PROTOCOL;
        mg_error_set(error, code, 0, "receipt: %s", maelys_json_result_string(status));
        return code;
    }
    int canonical = 0;
    status = maelys_json_document_is_canonical(document, 0u, &canonical);
    if (text) memset(text, 0, sizeof(*text));
    int shaped = status == MAELYS_JSON_OK && canonical && receipt_shape(document, text);
    maelys_json_document_release(document);
    if (status != MAELYS_JSON_OK) return writer_failure(status, "receipt canonical check", error);
    if (!canonical || !shaped) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                     canonical ? "receipt does not have the shape of version 1"
                               : "receipt is not in canonical form");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    if (out_sha256) maelys_cli_sha256_hex(bytes, size, out_sha256);
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_receipt_verify(const void *bytes, size_t size, char out_sha256[65],
                                              maelys_git_error_t *error) {
    return verify_bytes(bytes, size, out_sha256, NULL, error);
}

maelys_git_result_t mg_receipt_rewrite(const maelys_json_document_t *document, maelys_json_value_t value,
                                       char **out_bytes, size_t *out_size, char out_sha256[65],
                                       mg_receipt_text_t *out_text, maelys_git_error_t *error) {
    if (!document || !out_bytes || !out_size || !out_sha256 || !out_text) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    maelys_json_writer_t *writer = NULL;
    maelys_json_result_t status = maelys_json_writer_create(MAELYS_JSON_PROFILE_RFC8259, &k_limits, 0u, &writer);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_value(writer, document, value);
    char *bytes = NULL;
    size_t size = 0u;
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_finish(writer, &bytes, &size);
    maelys_json_writer_release(writer);
    if (status != MAELYS_JSON_OK) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "receipt rewrite: %s", maelys_json_result_string(status));
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    char digest[65];
    mg_receipt_text_t text;
    maelys_git_result_t result = verify_bytes(bytes, size, digest, &text, error);
    if (result != MAELYS_GIT_OK) {
        free(bytes);
        return result;
    }
    *out_bytes = bytes;
    *out_size = size;
    memcpy(out_sha256, digest, sizeof(digest));
    *out_text = text;
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_receipt_write_line(FILE *stream, const maelys_git_receipt_t *receipt, const char *text,
                                          maelys_git_error_t *error) {
    if (!stream || !receipt) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    char *bytes = NULL;
    size_t size = 0u;
    char sha256[65];
    maelys_git_result_t result = maelys_git_receipt_serialize(receipt, &bytes, &size, sha256, error);
    if (result != MAELYS_GIT_OK) return result;
    maelys_json_document_t *document = NULL;
    maelys_json_result_t status = maelys_json_document_parse(bytes, size, MAELYS_JSON_PROFILE_RFC8259,
                                                             &k_limits, &document, NULL);
    /* The text is bounded by MAELYS_GIT_RECEIPT_MAX_EXPLANATION_TEXT; escaping
     * may grow it sixfold. */
    const maelys_json_limits_t line_limits = {
        .maximum_bytes = MAELYS_GIT_RECEIPT_MAX_BYTES + 6u * MAELYS_GIT_RECEIPT_MAX_EXPLANATION_TEXT + 256u,
        .maximum_depth = RECEIPT_DEPTH + 1u,
        .maximum_tokens = RECEIPT_TOKENS + 8u,
    };
    maelys_json_writer_t *writer = NULL;
    if (status == MAELYS_JSON_OK)
        status = maelys_json_writer_create(MAELYS_JSON_PROFILE_RFC8259, &line_limits,
                                           MAELYS_JSON_WRITER_FINAL_NEWLINE, &writer);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_begin(writer);
    if (status == MAELYS_JSON_OK && text) status = key_string(writer, "explanationText", text);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_key_cstr(writer, "receipt");
    if (status == MAELYS_JSON_OK)
        status = maelys_json_writer_value(writer, document, maelys_json_document_root(document));
    if (status == MAELYS_JSON_OK) status = key_string(writer, "receiptSha256", sha256);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_end(writer);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_finish_file(writer, stream);
    maelys_json_writer_release(writer);
    maelys_json_document_release(document);
    free(bytes);
    return status == MAELYS_JSON_OK ? MAELYS_GIT_OK : writer_failure(status, "receipt line", error);
}
