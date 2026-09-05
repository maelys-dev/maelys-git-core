#include "agent/agent_internal.h"
#include "test_support.h"

static json_t *command_object(const char *id, json_t *payload) {
    return json_pack("{s:s,s:s,s:s,s:s,s:s,s:I,s:I,s:O}",
        "protocol", MAELYS_GIT_AGENT_PROTOCOL, "message_id", id,
        "agent_id", "agent-1", "type", "command", "command", "health",
        "issued_at_ms", (json_int_t)1, "expires_at_ms", (json_int_t)2, "payload", payload);
}

static int parse_object(json_t *root, mg_agent_message_t *message,
                         maelys_git_result_t expected) {
    char *bytes = json_dumps(root, JSON_COMPACT | JSON_ENSURE_ASCII);
    CHECK(bytes != NULL);
    maelys_git_error_t error = {0};
    maelys_git_result_t result = mg_protocol_parse(bytes, strlen(bytes), message, &error);
    /* Prove the document owns its bytes and decoded views after parse. */
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

static int same_value(const maelys_json_document_t *document,
                       maelys_json_value_t value, json_t *reference) {
    switch (maelys_json_value_type(document, value)) {
    case MAELYS_JSON_TYPE_OBJECT: {
        size_t size;
        CHECK(json_is_object(reference));
        CHECK(maelys_json_object_size(document, value, &size) == MAELYS_JSON_OK);
        CHECK(size == json_object_size(reference));
        for (size_t i = 0u; i < size; ++i) {
            maelys_json_view_t key;
            maelys_json_value_t child;
            CHECK(maelys_json_object_member_at(document, value, i, &key, &child) == MAELYS_JSON_OK);
            CHECK(same_value(document, child, json_object_get(reference, key.data)));
        }
        return 1;
    }
    case MAELYS_JSON_TYPE_ARRAY: {
        size_t size;
        CHECK(json_is_array(reference));
        CHECK(maelys_json_array_size(document, value, &size) == MAELYS_JSON_OK);
        CHECK(size == json_array_size(reference));
        for (size_t i = 0u; i < size; ++i) {
            maelys_json_value_t child;
            CHECK(maelys_json_array_get(document, value, i, &child) == MAELYS_JSON_OK);
            CHECK(same_value(document, child, json_array_get(reference, i)));
        }
        return 1;
    }
    case MAELYS_JSON_TYPE_STRING: {
        maelys_json_view_t view;
        CHECK(json_is_string(reference));
        CHECK(maelys_json_value_string(document, value, &view) == MAELYS_JSON_OK);
        CHECK(view.size == json_string_length(reference));
        CHECK(memcmp(view.data, json_string_value(reference), view.size) == 0);
        return 1;
    }
    case MAELYS_JSON_TYPE_NUMBER: {
        int64_t number;
        CHECK(json_is_integer(reference));
        CHECK(maelys_json_value_i64(document, value, &number) == MAELYS_JSON_OK);
        CHECK(number == (int64_t)json_integer_value(reference));
        return 1;
    }
    case MAELYS_JSON_TYPE_BOOLEAN: {
        int boolean;
        CHECK(json_is_boolean(reference));
        CHECK(maelys_json_value_boolean(document, value, &boolean) == MAELYS_JSON_OK);
        CHECK(boolean == json_is_true(reference));
        return 1;
    }
    case MAELYS_JSON_TYPE_NULL: return json_is_null(reference);
    default: return 0;
    }
}

static int test_owned_documents(void) {
    json_error_t json_error;
    json_t *payload = json_loads(
        "{\"text\":\"caf\\u00e9 \\ud800\\udc00\",\"values\":[-9223372036854775808,"
        "9223372036854775807,0,true,false,null,{},[]]}", JSON_REJECT_DUPLICATES, &json_error);
    CHECK(payload != NULL);
    json_t *first = command_object("first", payload);
    CHECK(first != NULL);
    json_t *second = json_deep_copy(first);
    CHECK(second != NULL);
    CHECK(json_object_set_new(json_object_get(second, "payload"), "text", json_string("second")) == 0);
    CHECK(json_object_set_new(second, "message_id", json_string("second")) == 0);
    mg_agent_message_t a, b;
    CHECK(parse_object(first, &a, MAELYS_GIT_OK));
    CHECK(parse_object(second, &b, MAELYS_GIT_OK));
    CHECK(a.document != b.document);
    CHECK(same_value(a.document, maelys_json_document_root(a.document), first));
    mg_protocol_message_clear(&a);
    CHECK(a.document == NULL && a.payload == MAELYS_JSON_VALUE_NONE);
    mg_protocol_message_clear(&a);
    CHECK(same_value(b.document, maelys_json_document_root(b.document), second));
    json_decref(first);
    json_decref(second);
    json_decref(payload);
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

static int test_structure_budgets(void) {
    json_t *payload = json_object(), *values = json_array();
    CHECK(payload != NULL && values != NULL);
    for (size_t i = 0u; i < 9000u; ++i)
        CHECK(json_array_append_new(values, json_integer(0)) == 0);
    CHECK(json_object_set_new(payload, "values", values) == 0);
    json_t *root = command_object("many-values", payload);
    mg_agent_message_t message;
    CHECK(root != NULL && parse_object(root, &message, MAELYS_GIT_OK));
    CHECK(same_value(message.document, message.payload, payload));
    mg_protocol_message_clear(&message);
    json_decref(root);
    json_decref(payload);

    for (size_t depth = MG_PROTOCOL_MAX_DEPTH; depth <= MG_PROTOCOL_MAX_DEPTH + 1u; ++depth) {
        values = json_integer(0);
        for (size_t i = 2u; i < depth; ++i) {
            json_t *array = json_array();
            CHECK(array != NULL && json_array_append_new(array, values) == 0);
            values = array;
        }
        payload = json_pack("{s:o}", "nested", values);
        root = command_object("depth", payload);
        CHECK(payload != NULL && root != NULL);
        CHECK(parse_object(root, &message,
            depth == MG_PROTOCOL_MAX_DEPTH ? MAELYS_GIT_OK : MAELYS_GIT_ERR_LIMIT));
        mg_protocol_message_clear(&message);
        json_decref(root);
        json_decref(payload);
    }
    return 1;
}

static int test_deduplication_v1(void) {
    /* Regression vectors for Jansson's UTF-8 key order and ASCII escaping. */
    json_error_t json_error;
    json_t *payload = json_loads("{\"\\ue000\":1,\"\\ud800\\udc00\":2,\"text\":\"caf\\u00e9\"}",
                                JSON_REJECT_DUPLICATES, &json_error);
    json_t *root = command_object("durable-unicode", payload);
    CHECK(payload != NULL && root != NULL);
    char *v1 = json_dumps(root, JSON_COMPACT | JSON_ENSURE_ASCII | JSON_SORT_KEYS);
    CHECK(v1 != NULL);
    CHECK(strstr(v1, "caf\\u00E9") != NULL);
    CHECK(strstr(v1, "\\uE000") != NULL && strstr(v1, "\\uD800\\uDC00") != NULL);
    CHECK(strstr(v1, "\\uE000") < strstr(v1, "\\uD800\\uDC00"));
    mg_agent_message_t message;
    CHECK(mg_protocol_parse(v1, strlen(v1), &message, NULL) == MAELYS_GIT_OK);
    maelys_json_writer_t *writer = NULL;
    CHECK(maelys_json_writer_create(MAELYS_JSON_PROFILE_RFC8259, NULL, 0u, &writer) == MAELYS_JSON_OK);
    CHECK(maelys_json_writer_value(writer, message.document,
        maelys_json_document_root(message.document)) == MAELYS_JSON_OK);
    char *canonical = NULL;
    size_t size;
    CHECK(maelys_json_writer_finish(writer, &canonical, &size) == MAELYS_JSON_OK);
    maelys_json_writer_release(writer);
    CHECK(strcmp(canonical, v1) != 0);

    char directory[] = "/tmp/maelys_protocol_journal_XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    char path[4096];
    (void)snprintf(path, sizeof(path), "%s/journal", directory);
    maelys_git_agent_store_t *store = NULL;
    CHECK(mg_store_open(path, &store, NULL) == MAELYS_GIT_OK);
    mg_store_command_state_t state;
    char *result = NULL;
    CHECK(mg_store_record_command(store, &message, v1, &state, &result, NULL) == MAELYS_GIT_OK);
    CHECK(state == MG_STORE_COMMAND_NEW);
    CHECK(mg_store_mark_running(store, message.message_id, NULL) == MAELYS_GIT_OK);
    CHECK(mg_store_complete_command(store, message.message_id, 1, "{\"status\":\"ok\"}", 1, NULL) == MAELYS_GIT_OK);
    mg_store_close(store);
    CHECK(mg_store_open(path, &store, NULL) == MAELYS_GIT_OK);
    char *pretty = json_dumps(root, JSON_INDENT(2));
    CHECK(pretty != NULL);
    json_t *replayed = json_loads(pretty, JSON_REJECT_DUPLICATES, &json_error);
    char *replayed_v1 = json_dumps(replayed, JSON_COMPACT | JSON_ENSURE_ASCII | JSON_SORT_KEYS);
    CHECK(replayed_v1 != NULL && strcmp(replayed_v1, v1) == 0);
    CHECK(mg_store_record_command(store, &message, replayed_v1, &state, &result, NULL) == MAELYS_GIT_OK);
    CHECK(state == MG_STORE_COMMAND_COMPLETE && result != NULL);
    free(result);
    CHECK(mg_store_record_command(store, &message, canonical, &state, &result, NULL) == MAELYS_GIT_ERR_PROTOCOL);
    mg_store_close(store);
    mg_protocol_message_clear(&message);
    json_decref(replayed);
    json_decref(root);
    json_decref(payload);
    free(pretty);
    free(replayed_v1);
    free(canonical);
    free(v1);
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
        CHECK(poll.document == NULL && poll.deduplication_commands == NULL && poll.cursor.data == NULL);
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
            maelys_json_value_t commands;
            CHECK(maelys_json_object_get(poll.document, maelys_json_document_root(poll.document),
                                         "commands", &commands) == MAELYS_JSON_OK);
            CHECK(same_value(poll.document, commands, poll.deduplication_commands));
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
    json_t *commands = json_array();
    for (size_t i = 0u; i < 32u; ++i) {
        json_t *values = json_array();
        for (size_t j = 0u; j < 300u; ++j) CHECK(json_array_append_new(values, json_integer(0)) == 0);
        CHECK(json_array_append_new(commands, json_pack("{s:o}", "values", values)) == 0);
    }
    json_t *root = json_pack("{s:s,s:o}", "cursor", "caf\xc3\xa9", "commands", commands);
    bytes = json_dumps(root, JSON_COMPACT);
    CHECK(bytes != NULL && strlen(bytes) < MAELYS_GIT_MAX_PROTOCOL_LINE);
    CHECK(mg_protocol_poll_parse(bytes, strlen(bytes), &poll, NULL) == MAELYS_GIT_OK);
    memset(bytes, '!', strlen(bytes)); free(bytes);
    CHECK(poll.command_count == 32u && !strcmp(poll.cursor.data, "caf\xc3\xa9"));
    maelys_json_value_t parsed_commands;
    CHECK(maelys_json_object_get(poll.document, maelys_json_document_root(poll.document),
                                 "commands", &parsed_commands) == MAELYS_JSON_OK);
    CHECK(same_value(poll.document, parsed_commands, commands));
    CHECK(json_equal(poll.deduplication_commands, commands));
    mg_protocol_poll_clear(&poll);
    CHECK(json_array_append_new(commands, json_object()) == 0);
    bytes = json_dumps(root, JSON_COMPACT);
    CHECK(mg_protocol_poll_parse(bytes, strlen(bytes), &poll, NULL) == MAELYS_GIT_ERR_PROTOCOL);
    free(bytes); json_decref(root);
    for (size_t depth = MG_POLL_MAX_DEPTH; depth <= MG_POLL_MAX_DEPTH + 1u; ++depth) {
        json_t *nested = json_integer(0);
        for (size_t j = 2u; j < depth; ++j) {
            json_t *array = json_array();
            CHECK(json_array_append_new(array, nested) == 0); nested = array;
        }
        root = json_pack("{s:s,s:[o]}", "cursor", "", "commands", nested);
        bytes = json_dumps(root, JSON_COMPACT);
        CHECK(mg_protocol_poll_parse(bytes, strlen(bytes), &poll, NULL) ==
              (depth == MG_POLL_MAX_DEPTH ? MAELYS_GIT_OK : MAELYS_GIT_ERR_LIMIT));
        free(bytes); json_decref(root); mg_protocol_poll_clear(&poll);
    }
    return 1;
}

static int test_result_envelope(void) {
    mg_agent_message_t command = {.message_id = "result-1", .agent_id = "agent-1", .command = "health"};
    json_t *payload = json_object();
    const char *statuses[] = {"ok", "denied", "failed", "pending", "", "OK"};
    int succeeded;
    for (size_t i = 0u; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char *encoded = mg_protocol_encode_result(&command, statuses[i], payload, NULL);
        CHECK(encoded != NULL);
        succeeded = 1;
        CHECK(mg_protocol_validate_result(encoded, strlen(encoded), &command, &succeeded, NULL) ==
              (i < 3u ? MAELYS_GIT_OK : MAELYS_GIT_ERR_PROTOCOL));
        CHECK(succeeded == (i == 0u)); free(encoded);
    }
    char *encoded = mg_protocol_encode_result(&command, "ok", payload, NULL);
    json_t *root = json_loads(encoded, 0u, NULL);
    CHECK(root != NULL); free(encoded); json_decref(payload);
    const char *fields[] = {"protocol", "message_id", "agent_id", "type", "command", "status", "payload"};
    for (size_t i = 0u; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        for (size_t variant = 0u; variant < 3u; ++variant) {
            json_t *wrong = json_deep_copy(root);
            if (variant == 0u) CHECK(json_object_del(wrong, fields[i]) == 0);
            else CHECK(json_object_set_new(wrong, fields[i],
                variant == 1u ? json_string("wrong") : json_null()) == 0);
            encoded = json_dumps(wrong, JSON_COMPACT);
            succeeded = 1;
            CHECK(mg_protocol_validate_result(encoded, strlen(encoded), &command, &succeeded, NULL) == MAELYS_GIT_ERR_PROTOCOL);
            CHECK(succeeded == 0); free(encoded); json_decref(wrong);
        }
    }
    CHECK(json_object_set_new(root, "extra", json_true()) == 0);
    encoded = json_dumps(root, JSON_COMPACT);
    CHECK(mg_protocol_validate_result(encoded, strlen(encoded), &command, &succeeded, NULL) == MAELYS_GIT_ERR_PROTOCOL);
    free(encoded); json_decref(root);
    return 1;
}

int main(void) {
    int passed = test_owned_documents();
    passed += test_structure_budgets();
    passed += test_deduplication_v1();
    passed += test_poll_reader();
    passed += test_result_envelope();
    if (passed != 5) return 1;
    (void)printf("ok: %d protocol ownership and compatibility groups passed\n", passed);
    return 0;
}
