#include "agent/agent_internal.h"
#include "test_json.h"
#include "test_support.h"

#include <stdarg.h>

/* A growing text, for JSON documents built by hand. */
typedef struct {
    char *data;
    size_t length, capacity;
} text_t;

static int append(text_t *text, const char *format, ...) MG_PRINTF(2, 3);

static int append(text_t *text, const char *format, ...) {
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int needed = vsnprintf(NULL, 0u, format, copy);
    va_end(copy);
    if (needed < 0) { va_end(args); return 0; }
    if (text->length + (size_t)needed + 1u > text->capacity) {
        size_t next = text->capacity ? text->capacity : 256u;
        while (next < text->length + (size_t)needed + 1u) next *= 2u;
        char *grown = realloc(text->data, next);
        if (!grown) { va_end(args); return 0; }
        text->data = grown;
        text->capacity = next;
    }
    (void)vsnprintf(text->data + text->length, text->capacity - text->length, format, args);
    va_end(args);
    text->length += (size_t)needed;
    return 1;
}

/* A health command `id` with `payload`, as JSON text the caller frees. */
static char *command_object(const char *id, const char *payload) {
    text_t text = {0};
    return append(&text, "{\"protocol\":\"" MAELYS_GIT_AGENT_PROTOCOL "\",\"message_id\":\"%s\","
                         "\"agent_id\":\"agent-1\",\"type\":\"command\",\"command\":\"health\","
                         "\"issued_at_ms\":1,\"expires_at_ms\":2,\"payload\":%s}", id, payload)
        ? text.data : NULL;
}

/* Parses `bytes` and frees it, overwritten first: the document owns its
 * bytes and decoded views after the parse. */
static int parse_object(char *bytes, mg_agent_message_t *message, maelys_git_result_t expected) {
    CHECK(bytes != NULL);
    maelys_git_error_t error = {0};
    maelys_git_result_t result = mg_protocol_parse(bytes, strlen(bytes), message, &error);
    memset(bytes, '!', strlen(bytes));
    free(bytes);
    CHECK(result == expected);
    if (result == MAELYS_GIT_OK) {
        CHECK(message->document != NULL && message->payload != MAELYS_JSON_VALUE_NONE);
    } else {
        CHECK(message->document == NULL && message->payload == MAELYS_JSON_VALUE_NONE);
    }
    return 1;
}

/* The parsed `value` is the JSON `reference`, structurally. */
static int same_value(const maelys_json_document_t *document, maelys_json_value_t value,
                      const char *reference) {
    maelys_json_document_t *expected = tj_parse(reference);
    int same = expected && tj_value_equal(document, value, expected, maelys_json_document_root(expected));
    tj_release(expected);
    return same;
}

static int test_owned_documents(void) {
    static const char payload[] =
        "{\"text\":\"caf\\u00e9 \\ud800\\udc00\",\"values\":[-9223372036854775808,"
        "9223372036854775807,0,true,false,null,{},[]]}";
    static const char second_payload[] =
        "{\"text\":\"second\",\"values\":[-9223372036854775808,"
        "9223372036854775807,0,true,false,null,{},[]]}";
    char *first = command_object("first", payload), *second = command_object("second", second_payload);
    CHECK(first != NULL && second != NULL);
    char *first_reference = strdup(first), *second_reference = strdup(second);
    CHECK(first_reference && second_reference);
    mg_agent_message_t a, b;
    CHECK(parse_object(first, &a, MAELYS_GIT_OK));
    CHECK(parse_object(second, &b, MAELYS_GIT_OK));
    CHECK(a.document != b.document);
    CHECK(same_value(a.document, maelys_json_document_root(a.document), first_reference));
    mg_protocol_message_clear(&a);
    CHECK(a.document == NULL && a.payload == MAELYS_JSON_VALUE_NONE);
    mg_protocol_message_clear(&a);
    CHECK(same_value(b.document, maelys_json_document_root(b.document), second_reference));
    free(first_reference);
    free(second_reference);
    maelys_json_view_t view;
    CHECK(maelys_json_object_get_string(b.document, b.payload, "text", &view) == MAELYS_JSON_OK);
    CHECK(!strcmp(view.data, "second"));
    mg_protocol_message_clear(&b);
    const char bad[] = "{\"payload\":{\"text\":\"a\\u0000b\"}}";
    CHECK(mg_protocol_parse(bad, strlen(bad), &a, NULL) == MAELYS_GIT_ERR_PROTOCOL);
    CHECK(a.document == NULL && a.payload == MAELYS_JSON_VALUE_NONE);
    mg_protocol_message_clear(&a);
    return 1;
}

/* `depth` - 2 arrays nested around 0: with its payload object and its
 * command object, a value `depth` containers deep. */
static char *nested_zero(size_t depth) {
    text_t text = {0};
    int ok = 1;
    for (size_t i = 2u; ok && i < depth; ++i) ok = append(&text, "[");
    ok = ok && append(&text, "0");
    for (size_t i = 2u; ok && i < depth; ++i) ok = append(&text, "]");
    return ok ? text.data : NULL;
}

static int test_structure_budgets(void) {
    text_t payload = {0};
    CHECK(append(&payload, "{\"values\":["));
    for (size_t i = 0u; i < 9000u; ++i) CHECK(append(&payload, i ? ",0" : "0"));
    CHECK(append(&payload, "]}"));
    mg_agent_message_t message;
    CHECK(parse_object(command_object("many-values", payload.data), &message, MAELYS_GIT_OK));
    CHECK(same_value(message.document, message.payload, payload.data));
    mg_protocol_message_clear(&message);
    free(payload.data);

    for (size_t depth = MG_PROTOCOL_MAX_DEPTH; depth <= MG_PROTOCOL_MAX_DEPTH + 1u; ++depth) {
        char *values = nested_zero(depth);
        text_t nested = {0};
        CHECK(values != NULL && append(&nested, "{\"nested\":%s}", values));
        CHECK(parse_object(command_object("depth", nested.data), &message,
            depth == MG_PROTOCOL_MAX_DEPTH ? MAELYS_GIT_OK : MAELYS_GIT_ERR_LIMIT));
        mg_protocol_message_clear(&message);
        free(values);
        free(nested.data);
    }
    return 1;
}

/* The deduplication forms of one command, as the journal stores them. v1 is
 * what the build of 1016d1b wrote: keys by UTF-8 bytes, escapes in upper
 * case. v2 is what maelys-json writes: keys by UTF-16 code units, escapes in
 * lower case. */
static const char k_v1[] =
    "{\"agent_id\":\"agent-1\",\"command\":\"health\",\"expires_at_ms\":2,\"issued_at_ms\":1,"
    "\"message_id\":\"durable-unicode\",\"payload\":{\"text\":\"caf\\u00E9\",\"\\uE000\":1,"
    "\"\\uD800\\uDC00\":2},\"protocol\":\"maelys-git-agent/1\",\"type\":\"command\"}";
static const char k_v2[] =
    "{\"agent_id\":\"agent-1\",\"command\":\"health\",\"expires_at_ms\":2,\"issued_at_ms\":1,"
    "\"message_id\":\"durable-unicode\",\"payload\":{\"text\":\"caf\\u00e9\",\"\\ud800\\udc00\":2,"
    "\"\\ue000\":1},\"protocol\":\"maelys-git-agent/1\",\"type\":\"command\"}";

static int test_deduplication_v2(void) {
    maelys_git_error_t error = {0};
    /* A v1 form, read back, is written in the v2 form. */
    char *form = mg_protocol_deduplication_form(k_v1, strlen(k_v1), &error);
    CHECK(form != NULL && strcmp(form, k_v2) == 0);
    free(form);
    /* A command received in a poll, raw UTF-8 here, takes the same v2 form. */
    static const char poll_body[] =
        "{\"cursor\":\"c\",\"commands\":[{\"type\":\"command\",\"protocol\":\"maelys-git-agent/1\","
        "\"message_id\":\"durable-unicode\",\"agent_id\":\"agent-1\",\"command\":\"health\","
        "\"issued_at_ms\":1,\"expires_at_ms\":2,"
        "\"payload\":{\"\xee\x80\x80\":1,\"\xf0\x90\x80\x80\":2,\"text\":\"caf\xc3\xa9\"}}]}";
    mg_agent_poll_t poll;
    CHECK(mg_protocol_poll_parse(poll_body, strlen(poll_body), &poll, &error) == MAELYS_GIT_OK);
    form = mg_protocol_poll_command_form(&poll, 0u, &error);
    CHECK(form != NULL && strcmp(form, k_v2) == 0);
    CHECK(mg_protocol_poll_command_form(&poll, 1u, &error) == NULL);
    mg_protocol_poll_clear(&poll);

    /* A new journal compares v2 forms byte for byte. */
    mg_agent_message_t message;
    CHECK(mg_protocol_parse(form, strlen(form), &message, NULL) == MAELYS_GIT_OK);
    char directory[] = "/tmp/maelys_protocol_journal_XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    char path[4096];
    (void)snprintf(path, sizeof(path), "%s/journal", directory);
    maelys_git_agent_store_t *store = NULL;
    CHECK(mg_store_open(path, &store, NULL) == MAELYS_GIT_OK);
    mg_store_command_state_t state;
    char *result = NULL;
    CHECK(mg_store_record_command(store, &message, form, &state, &result, NULL) == MAELYS_GIT_OK);
    CHECK(state == MG_STORE_COMMAND_NEW);
    CHECK(mg_store_mark_running(store, message.message_id, NULL) == MAELYS_GIT_OK);
    CHECK(mg_store_complete_command(store, message.message_id, 1, "{\"status\":\"ok\"}", NULL, 1, NULL) == MAELYS_GIT_OK);
    mg_store_close(store);
    CHECK(mg_store_open(path, &store, NULL) == MAELYS_GIT_OK);
    CHECK(mg_store_record_command(store, &message, form, &state, &result, NULL) == MAELYS_GIT_OK);
    CHECK(state == MG_STORE_COMMAND_COMPLETE && result != NULL);
    free(result);
    CHECK(mg_store_record_command(store, &message, k_v1, &state, &result, NULL) == MAELYS_GIT_ERR_PROTOCOL);
    mg_store_close(store);
    mg_protocol_message_clear(&message);
    free(form);
    CHECK(test_remove_tree(directory));
    return 1;
}

static int test_poll_reader(void) {
    const char *invalid[] = {
        "{}", "[]", "{\"cursor\":null,\"commands\":[]}",
        "{\"cursor\":\"\",\"commands\":{},\"extra\":1}",
        "{\"cursor\":\"a\\u0000b\",\"commands\":[]}",
        "{\"cursor\":\"\",\"cur\\u0073or\":\"\",\"commands\":[]}",
        "\xef\xbb\xbf{\"cursor\":\"\",\"commands\":[]}",
        "{\"cursor\":\"\xff\",\"commands\":[]}",
        "{\"cursor\":\"\\ud800\",\"commands\":[]}",
        "{\"cursor\":\"\",\"commands\":[]}{}"
    };
    mg_agent_poll_t poll;
    for (size_t i = 0u; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        CHECK(mg_protocol_poll_parse(invalid[i], strlen(invalid[i]), &poll, NULL) == MAELYS_GIT_ERR_PROTOCOL);
        CHECK(poll.document == NULL && poll.cursor.data == NULL);
        mg_protocol_poll_clear(&poll);
    }
    const char *numbers[] = {"-9223372036854775808", "9223372036854775807", "0",
        "9223372036854775808", "18446744073709551615", "18446744073709551616",
        "-9223372036854775809", "1.0", "1e0", "1e100000"};
    for (size_t i = 0u; i < sizeof(numbers) / sizeof(numbers[0]); ++i) {
        char bytes[200];
        (void)snprintf(bytes, sizeof(bytes), "{\"cursor\":\"\",\"commands\":[{\"nested\":[%s]}]}", numbers[i]);
        CHECK(mg_protocol_poll_parse(bytes, strlen(bytes), &poll, NULL) ==
              (i < 3u ? MAELYS_GIT_OK : MAELYS_GIT_ERR_PROTOCOL));
        if (i < 3u) {
            char expected[200];
            (void)snprintf(expected, sizeof(expected), "{\"nested\":[%s]}", numbers[i]);
            char *form = mg_protocol_poll_command_form(&poll, 0u, NULL);
            CHECK(form != NULL && strcmp(form, expected) == 0);
            free(form);
        }
        mg_protocol_poll_clear(&poll);
    }
    char *bytes = malloc(MAELYS_GIT_MAX_PROTOCOL_LINE + 2u);
    CHECK(bytes != NULL);
    const char *empty = "{\"cursor\":\"\",\"commands\":[]}";
    memset(bytes, ' ', MAELYS_GIT_MAX_PROTOCOL_LINE + 2u);
    memcpy(bytes, empty, strlen(empty));
    CHECK(mg_protocol_poll_parse(bytes, MAELYS_GIT_MAX_PROTOCOL_LINE, &poll, NULL) == MAELYS_GIT_OK);
    mg_protocol_poll_clear(&poll);
    CHECK(mg_protocol_poll_parse(bytes, MAELYS_GIT_MAX_PROTOCOL_LINE + 1u, &poll, NULL) == MAELYS_GIT_ERR_LIMIT);
    bytes[strlen(empty)] = '\0';
    CHECK(mg_protocol_poll_parse(bytes, strlen(empty) + 1u, &poll, NULL) == MAELYS_GIT_ERR_PROTOCOL);
    free(bytes);
    /* 32 commands of 300 values: 9 600 values in one poll. */
    text_t command = {0}, commands = {0};
    CHECK(append(&command, "{\"values\":["));
    for (size_t j = 0u; j < 300u; ++j) CHECK(append(&command, j ? ",0" : "0"));
    CHECK(append(&command, "]}"));
    CHECK(append(&commands, "["));
    for (size_t i = 0u; i < 32u; ++i) CHECK(append(&commands, "%s%s", i ? "," : "", command.data));
    text_t root = {0};
    CHECK(append(&root, "{\"cursor\":\"caf\xc3\xa9\",\"commands\":%s]}", commands.data));
    CHECK(root.length < MAELYS_GIT_MAX_PROTOCOL_LINE);
    bytes = strdup(root.data);
    CHECK(bytes != NULL);
    CHECK(mg_protocol_poll_parse(bytes, strlen(bytes), &poll, NULL) == MAELYS_GIT_OK);
    memset(bytes, '!', strlen(bytes)); free(bytes);
    CHECK(poll.command_count == 32u && !strcmp(poll.cursor.data, "caf\xc3\xa9"));
    CHECK(append(&commands, "]"));
    maelys_json_value_t parsed_commands;
    CHECK(maelys_json_object_get(poll.document, maelys_json_document_root(poll.document),
                                 "commands", &parsed_commands) == MAELYS_JSON_OK);
    CHECK(same_value(poll.document, parsed_commands, commands.data));
    for (size_t i = 0u; i < 32u; ++i) {
        char *form = mg_protocol_poll_command_form(&poll, i, NULL);
        CHECK(form != NULL && strcmp(form, command.data) == 0);
        free(form);
    }
    mg_protocol_poll_clear(&poll);
    /* A 33rd command is one too many. */
    root.length = 0u;
    commands.data[commands.length - 1u] = '\0';
    CHECK(append(&root, "{\"cursor\":\"caf\xc3\xa9\",\"commands\":%s,{}]}", commands.data));
    CHECK(mg_protocol_poll_parse(root.data, root.length, &poll, NULL) == MAELYS_GIT_ERR_PROTOCOL);
    free(command.data); free(commands.data); free(root.data);
    for (size_t depth = MG_POLL_MAX_DEPTH; depth <= MG_POLL_MAX_DEPTH + 1u; ++depth) {
        char *nested = nested_zero(depth);
        text_t deep = {0};
        CHECK(nested != NULL && append(&deep, "{\"cursor\":\"\",\"commands\":[%s]}", nested));
        CHECK(mg_protocol_poll_parse(deep.data, deep.length, &poll, NULL) ==
              (depth == MG_POLL_MAX_DEPTH ? MAELYS_GIT_OK : MAELYS_GIT_ERR_LIMIT));
        free(nested); free(deep.data); mg_protocol_poll_clear(&poll);
    }
    return 1;
}

/* A result of `command` with an empty payload. */
static char *empty_result(const mg_agent_message_t *command, const char *status) {
    mg_json_t json;
    mg_protocol_result_begin(&json, command, status);
    return mg_protocol_result_end(&json, NULL);
}

static int test_result_envelope(void) {
    mg_agent_message_t command = {.message_id = "result-1", .agent_id = "agent-1", .command = "health"};
    const char *statuses[] = {"ok", "denied", "failed", "pending", "", "OK"};
    int succeeded;
    for (size_t i = 0u; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char *encoded = empty_result(&command, statuses[i]);
        CHECK(encoded != NULL);
        succeeded = 1;
        CHECK(mg_protocol_validate_result(encoded, strlen(encoded), &command, &succeeded, NULL) ==
              (i < 3u ? MAELYS_GIT_OK : MAELYS_GIT_ERR_PROTOCOL));
        CHECK(succeeded == (i == 0u)); free(encoded);
    }
    char *root = empty_result(&command, "ok");
    CHECK(root != NULL);
    const char *fields[] = {"protocol", "message_id", "agent_id", "type", "command", "status", "payload"};
    for (size_t i = 0u; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        for (size_t variant = 0u; variant < 3u; ++variant) {
            /* Removed, a wrong string, or null. */
            char *encoded = tj_with(root, fields[i], variant == 0u ? NULL : variant == 1u ? "\"wrong\"" : "null");
            CHECK(encoded != NULL);
            succeeded = 1;
            CHECK(mg_protocol_validate_result(encoded, strlen(encoded), &command, &succeeded, NULL) == MAELYS_GIT_ERR_PROTOCOL);
            CHECK(succeeded == 0); free(encoded);
        }
    }
    char *encoded = tj_with(root, "extra", "true");
    CHECK(encoded != NULL);
    CHECK(mg_protocol_validate_result(encoded, strlen(encoded), &command, &succeeded, NULL) == MAELYS_GIT_ERR_PROTOCOL);
    free(encoded); free(root);
    return 1;
}

/* A result with one string member of `filler` bytes. */
static char *filled_result(const mg_agent_message_t *command, size_t filler, maelys_git_error_t *error) {
    char *text = malloc(filler + 1u);
    if (!text) return NULL;
    memset(text, 'x', filler);
    text[filler] = '\0';
    mg_json_t json;
    mg_protocol_result_begin(&json, command, "ok");
    mg_json_string(&json, "filler", text);
    free(text);
    return mg_protocol_result_end(&json, error);
}

/* A result line holds 65 536 bytes of JSON, the separator excluded: one of
 * exactly that size is written and read back; one byte more is never
 * written, and says why. */
static int test_result_line_limit(void) {
    mg_agent_message_t command = {.message_id = "line-1", .agent_id = "agent-1", .command = "diff"};
    maelys_git_error_t error = {0};
    char *probe = filled_result(&command, 0u, &error);
    CHECK(probe != NULL);
    size_t envelope = strlen(probe);
    free(probe);
    char *line = filled_result(&command, MAELYS_GIT_MAX_PROTOCOL_LINE - envelope, &error);
    CHECK(line != NULL && strlen(line) == MAELYS_GIT_MAX_PROTOCOL_LINE);
    int succeeded = 0;
    CHECK(mg_protocol_validate_result(line, strlen(line), &command, &succeeded, &error) == MAELYS_GIT_OK);
    CHECK(succeeded == 1);
    free(line);
    line = filled_result(&command, MAELYS_GIT_MAX_PROTOCOL_LINE - envelope + 1u, &error);
    CHECK(line == NULL && error.code == MAELYS_GIT_ERR_LIMIT);
    return 1;
}

/* The payload of each command in protocol/agent-v1.schema.json declares the
 * members the executor accepts, no more and no fewer, for the same commands:
 * the published shape cannot drift from what runs. */
static int test_schema_payloads(void) {
    static char text[65536];
    FILE *file = fopen(PROTOCOL_DIR "/agent-v1.schema.json", "rb");
    CHECK(file != NULL);
    size_t size = fread(text, 1u, sizeof(text) - 1u, file);
    (void)fclose(file);
    CHECK(size > 0u && size < sizeof(text) - 1u);
    text[size] = '\0';
    maelys_json_document_t *schema = tj_parse(text);
    CHECK(schema != NULL);
    size_t commands = 0u;
    while (mg_executor_payloads[commands].command) ++commands;
    CHECK(tj_size(schema, "oneOf") == commands);
    for (size_t i = 0u; i < commands; ++i) {
        char path[96];
        (void)snprintf(path, sizeof(path), "oneOf.%zu.properties.command.const", i);
        const char *command = tj_string(schema, path);
        CHECK(command != NULL);
        const mg_executor_payload_t *entry = mg_executor_payloads;
        while (entry->command && strcmp(entry->command, command) != 0) ++entry;
        CHECK(entry->command != NULL);
        size_t members = 0u;
        while (entry->members[members]) ++members;
        (void)snprintf(path, sizeof(path), "oneOf.%zu.properties.payload", i);
        maelys_json_value_t payload = tj_root_at(schema, path);
        maelys_json_value_t properties = tj_at(schema, payload, "properties");
        if (properties == MAELYS_JSON_VALUE_NONE) {
            (void)snprintf(path, sizeof(path), "oneOf.%zu.properties.payload.maxProperties", i);
            CHECK(members == 0u && tj_i64(schema, path, -1) == 0);
            continue;
        }
        (void)snprintf(path, sizeof(path), "oneOf.%zu.properties.payload.additionalProperties", i);
        CHECK(tj_boolean(schema, path) == 0);
        (void)snprintf(path, sizeof(path), "oneOf.%zu.properties.payload.properties", i);
        if (tj_size(schema, path) != members) {
            (void)fprintf(stderr, "%s: schema declares %zu members, the executor accepts %zu\n", command,
                          tj_size(schema, path), members);
            CHECK(0);
        }
        for (size_t m = 0u; m < members; ++m) {
            maelys_json_value_t member;
            if (maelys_json_object_get(schema, properties, entry->members[m], &member) != MAELYS_JSON_OK) {
                (void)fprintf(stderr, "%s: schema lacks %s\n", command, entry->members[m]);
                CHECK(0);
            }
        }
    }
    tj_release(schema);
    return 1;
}

int main(void) {
    int passed = test_owned_documents();
    passed += test_structure_budgets();
    passed += test_deduplication_v2();
    passed += test_poll_reader();
    passed += test_result_envelope();
    passed += test_result_line_limit();
    passed += test_schema_payloads();
    if (passed != 7) return 1;
    (void)printf("ok: %d protocol ownership and compatibility groups passed\n", passed);
    return 0;
}
