#include "agent/agent_internal.h"
#include "test_json.h"
#include "test_support.h"

#include <fcntl.h>

typedef struct {
    char directory[4096];
    char config[4096];
    char *base; /* the configuration provision wrote */
} fixture_t;

static int write_bytes(const char *path, const void *bytes, size_t size, mode_t mode) {
    FILE *file = fopen(path, "wb");
    if (!file) return 0;
    int ok = fwrite(bytes, 1u, size, file) == size;
    if (fclose(file) != 0) ok = 0;
    return chmod(path, mode) == 0 && ok;
}

static int fixture_init(fixture_t *fixture) {
    strcpy(fixture->directory, "/tmp/maelys_config_reader_XXXXXX");
    CHECK(mkdtemp(fixture->directory) != NULL);
    char token[4096], ca[4096], manifest[4096], database[4096];
    (void)snprintf(token, sizeof(token), "%s/token", fixture->directory);
    (void)snprintf(ca, sizeof(ca), "%s/ca", fixture->directory);
    (void)snprintf(manifest, sizeof(manifest), "%s/manifest", fixture->directory);
    (void)snprintf(database, sizeof(database), "%s/database", fixture->directory);
    (void)snprintf(fixture->config, sizeof(fixture->config), "%s/config", fixture->directory);
    CHECK(write_bytes(token, "secret\n", 7u, 0600));
    CHECK(write_bytes(ca, "ca\n", 3u, 0644));
    CHECK(write_bytes(manifest, "{}", 2u, 0644));
    maelys_git_error_t error = {0};
    CHECK(maelys_git_agent_provision(fixture->config, "agent-1", "forge.example.test",
        ca, token, database, manifest, fixture->directory, "/usr/bin/true", &error) == MAELYS_GIT_OK);
    FILE *file = fopen(fixture->config, "rb");
    CHECK(file != NULL);
    fixture->base = calloc(1u, MG_CONFIG_MAX_BYTES + 1u);
    size_t size = fixture->base ? fread(fixture->base, 1u, MG_CONFIG_MAX_BYTES, file) : 0u;
    (void)fclose(file);
    maelys_json_document_t *parsed = size > 0u ? tj_parse(fixture->base) : NULL;
    tj_release(parsed);
    CHECK(parsed != NULL);
    return 1;
}

static int expect_path(const char *path, maelys_git_result_t expected) {
    maelys_git_agent_config_t sentinel = {0};
    maelys_git_agent_config_t *loaded = &sentinel;
    maelys_git_error_t error = {0};
    maelys_git_result_t result = mg_config_load(path, &loaded, &error);
    if (result != expected) {
        (void)fprintf(stderr, "config result %s, expected %s: %s\n",
            maelys_git_result_name(result), maelys_git_result_name(expected), error.message);
    }
    if (result == MAELYS_GIT_OK) {
        CHECK(loaded != NULL && loaded != &sentinel);
        mg_config_free(loaded);
    } else {
        CHECK(loaded == NULL);
        CHECK(error.code == result && error.message[0] != '\0');
    }
    CHECK(result == expected);
    return 1;
}

static int expect_bytes(const fixture_t *fixture, const void *bytes, size_t size,
                        maelys_git_result_t expected) {
    CHECK(write_bytes(fixture->config, bytes, size, 0600));
    return expect_path(fixture->config, expected);
}

/* Writes `text`, compact and printable ASCII, and loads it. Frees `text`. */
static int expect_object(const fixture_t *fixture, char *text, maelys_git_result_t expected) {
    CHECK(text != NULL);
    char *bytes = tj_rewrite(text, NULL, NULL, MAELYS_JSON_WRITER_ASCII);
    free(text);
    CHECK(bytes != NULL);
    int ok = expect_bytes(fixture, bytes, strlen(bytes), expected);
    free(bytes);
    return ok;
}

/* The base configuration with `field` set to the string `value`. */
static char *with_string(const fixture_t *fixture, const char *field, const char *value) {
    char *quoted = tj_quote(value);
    char *text = quoted ? tj_with(fixture->base, field, quoted) : NULL;
    free(quoted);
    return text;
}

static int test_valid_config(const fixture_t *fixture) {
    CHECK(expect_object(fixture, tj_with(fixture->base, NULL, NULL), MAELYS_GIT_OK));
    const char *unicode_path = "/tmp/\xc3\xa9\xf0\x9f\x98\x80";
    char *root = with_string(fixture, "database_path", unicode_path);
    CHECK(root != NULL);
    CHECK(expect_object(fixture, tj_with(root, NULL, NULL), MAELYS_GIT_OK));
    maelys_git_agent_config_t *loaded = NULL;
    CHECK(mg_config_load(fixture->config, &loaded, NULL) == MAELYS_GIT_OK);
    /* The parsed document is already gone: all strings belong to config. */
    CHECK(!strcmp(loaded->database_path, unicode_path));
    CHECK(!strcmp(loaded->agent_id, "agent-1"));
    CHECK(loaded->poll_timeout_ms == 30000u && loaded->request_timeout_ms == 30000u);
    mg_config_free(loaded);
    char *utf8 = tj_rewrite(root, NULL, NULL, MAELYS_JSON_WRITER_INDENT);
    CHECK(utf8 != NULL && strstr(utf8, "\xc3\xa9") != NULL);
    CHECK(expect_bytes(fixture, utf8, strlen(utf8), MAELYS_GIT_OK));
    free(utf8);
    free(root);
    return 1;
}

static int test_syntax_and_limits(const fixture_t *fixture) {
    static const char *const rejected[] = {
        "", "{}", "[]", "null", "{\"version\":1,}",
        "{\"version\":1,\"ver\\u0073ion\":1}",
        "{\"agent_id\":\"a\\u0000b\"}",
        "{\"agent_id\":\"\\ud800\"}",
        "{\"agent_id\":\"\xff\"}", "\xef\xbb\xbf{}", "{} {}"
    };
    for (size_t i = 0u; i < sizeof(rejected) / sizeof(rejected[0]); ++i)
        CHECK(expect_bytes(fixture, rejected[i], strlen(rejected[i]), MAELYS_GIT_ERR_PROTOCOL));

    const char *nested = "{\"version\":{}}";
    CHECK(expect_bytes(fixture, nested, strlen(nested), MAELYS_GIT_ERR_LIMIT));
    CHECK(expect_object(fixture, tj_with(fixture->base, "extra", "0"), MAELYS_GIT_ERR_LIMIT));

    char *base = tj_with(fixture->base, NULL, NULL);
    CHECK(base != NULL);
    size_t base_size = strlen(base);
    char *padded = malloc(MG_CONFIG_MAX_BYTES + 1u);
    CHECK(padded != NULL && base_size < MG_CONFIG_MAX_BYTES);
    memcpy(padded, base, base_size);
    memset(padded + base_size, ' ', MG_CONFIG_MAX_BYTES + 1u - base_size);
    CHECK(expect_bytes(fixture, padded, MG_CONFIG_MAX_BYTES - 1u, MAELYS_GIT_OK));
    CHECK(expect_bytes(fixture, padded, MG_CONFIG_MAX_BYTES, MAELYS_GIT_OK));
    CHECK(expect_bytes(fixture, padded, MG_CONFIG_MAX_BYTES + 1u, MAELYS_GIT_ERR_LIMIT));
    padded[base_size] = '\0';
    CHECK(expect_bytes(fixture, padded, base_size + 1u, MAELYS_GIT_ERR_PROTOCOL));
    memcpy(padded + base_size + 1u, "{}", 2u);
    CHECK(expect_bytes(fixture, padded, base_size + 3u, MAELYS_GIT_ERR_PROTOCOL));
    free(padded);
    free(base);

    /* A syntax error retains the byte position from maelys-json. */
    const char syntax_error[] = "{\n\"version\":?}";
    CHECK(write_bytes(fixture->config, syntax_error, sizeof(syntax_error) - 1u, 0600));
    maelys_git_agent_config_t *loaded = NULL;
    maelys_git_error_t error = {0};
    CHECK(mg_config_load(fixture->config, &loaded, &error) == MAELYS_GIT_ERR_PROTOCOL);
    CHECK(loaded == NULL && strstr(error.message, "line 2, column 11 (offset 12)") != NULL);
    return 1;
}

static int expect_number(const fixture_t *fixture, const char *field,
                         const char *lexeme, maelys_git_result_t expected) {
    char *encoded = with_string(fixture, field, "NUMBER_MARKER");
    CHECK(encoded != NULL);
    const char marker[] = "\"NUMBER_MARKER\"";
    char *found = strstr(encoded, marker);
    CHECK(found != NULL);
    size_t prefix = (size_t)(found - encoded);
    const char *suffix = found + strlen(marker);
    size_t size = prefix + strlen(lexeme) + strlen(suffix);
    char *bytes = malloc(size + 1u);
    CHECK(bytes != NULL);
    memcpy(bytes, encoded, prefix);
    memcpy(bytes + prefix, lexeme, strlen(lexeme));
    memcpy(bytes + prefix + strlen(lexeme), suffix, strlen(suffix) + 1u);
    int ok = expect_bytes(fixture, bytes, size, expected);
    free(bytes);
    free(encoded);
    return ok;
}

static int test_numeric_contract(const fixture_t *fixture) {
    static const char *const fields[] = {"version", "poll_timeout_ms", "request_timeout_ms"};
    static const char *const invalid[] = {
        "-1", "-0", "0", "-9223372036854775808", "-9223372036854775809",
        "9223372036854775807", "9223372036854775808", "18446744073709551615",
        "18446744073709551616", "true", "null", "\"1000\""
    };
    for (size_t f = 0u; f < sizeof(fields) / sizeof(fields[0]); ++f) {
        for (size_t i = 0u; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
            CHECK(expect_number(fixture, fields[f], invalid[i], MAELYS_GIT_ERR_PROTOCOL));
        CHECK(expect_number(fixture, fields[f], f == 0u ? "1.0" : "1000.0", MAELYS_GIT_ERR_PROTOCOL));
        CHECK(expect_number(fixture, fields[f], f == 0u ? "1e0" : "1e3", MAELYS_GIT_ERR_PROTOCOL));
    }
    CHECK(expect_number(fixture, "version", "1", MAELYS_GIT_OK));
    CHECK(expect_number(fixture, "version", "2", MAELYS_GIT_ERR_PROTOCOL));
    for (size_t f = 1u; f < sizeof(fields) / sizeof(fields[0]); ++f) {
        CHECK(expect_number(fixture, fields[f], "999", MAELYS_GIT_ERR_PROTOCOL));
        CHECK(expect_number(fixture, fields[f], "1000", MAELYS_GIT_OK));
        CHECK(expect_number(fixture, fields[f], "120000", MAELYS_GIT_OK));
        CHECK(expect_number(fixture, fields[f], "120001", MAELYS_GIT_ERR_PROTOCOL));
    }
    return 1;
}

static int test_schema_and_strings(const fixture_t *fixture) {
    maelys_json_document_t *base = tj_parse(fixture->base);
    CHECK(base != NULL && tj_size(base, "") == 14u);
    for (size_t i = 0u; i < 14u; ++i) {
        maelys_json_view_t field;
        maelys_json_value_t value;
        CHECK(maelys_json_object_member_at(base, maelys_json_document_root(base), i, &field, &value) ==
              MAELYS_JSON_OK);
        char *missing = tj_with(fixture->base, field.data, NULL);
        CHECK(missing != NULL);
        CHECK(expect_object(fixture, tj_with(missing, NULL, NULL), MAELYS_GIT_ERR_PROTOCOL));
        /* Same member count, but one required field replaced by an unknown. */
        CHECK(expect_object(fixture, tj_with(missing, "unknown", "0"), MAELYS_GIT_ERR_PROTOCOL));
        free(missing);
        if (maelys_json_value_type(base, value) != MAELYS_JSON_TYPE_STRING) continue;
        CHECK(expect_object(fixture, tj_with(fixture->base, field.data, "false"), MAELYS_GIT_ERR_PROTOCOL));
        CHECK(expect_object(fixture, tj_with(fixture->base, field.data, "\"\""), MAELYS_GIT_ERR_PROTOCOL));
    }
    tj_release(base);
    char identifier[MG_AGENT_ID_MAX + 1u];
    memset(identifier, 'a', sizeof(identifier));
    identifier[MG_AGENT_ID_MAX - 1u] = '\0';
    CHECK(expect_object(fixture, with_string(fixture, "agent_id", identifier), MAELYS_GIT_OK));
    identifier[MG_AGENT_ID_MAX - 1u] = 'a';
    identifier[MG_AGENT_ID_MAX] = '\0';
    CHECK(expect_object(fixture, with_string(fixture, "agent_id", identifier), MAELYS_GIT_ERR_PROTOCOL));
    static const struct { const char *field; const char *value; } bad[] = {
        {"agent_id", "agent/1"}, {"authority", "https://forge.example.test"},
        {"database_path", "relative"}, {"repository_root", "relative"},
        {"command_target", "//other-host/path"}, {"event_target", "/path#fragment"}
    };
    for (size_t i = 0u; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        CHECK(expect_object(fixture, with_string(fixture, bad[i].field, bad[i].value),
                            MAELYS_GIT_ERR_PROTOCOL));
    }
    return 1;
}

static int test_file_security(const fixture_t *fixture) {
    CHECK(expect_object(fixture, tj_with(fixture->base, NULL, NULL), MAELYS_GIT_OK));
    CHECK(chmod(fixture->config, 0644) == 0);
    CHECK(expect_path(fixture->config, MAELYS_GIT_OK));
    CHECK(chmod(fixture->config, 0620) == 0);
    CHECK(expect_path(fixture->config, MAELYS_GIT_ERR_DENIED));
    CHECK(chmod(fixture->config, 0602) == 0);
    CHECK(expect_path(fixture->config, MAELYS_GIT_ERR_DENIED));
    CHECK(chmod(fixture->config, 0600) == 0);
    if (geteuid() == 0u) {
        CHECK(chown(fixture->config, 65534u, (gid_t)-1) == 0);
        CHECK(expect_path(fixture->config, MAELYS_GIT_ERR_DENIED));
        CHECK(chown(fixture->config, 0u, (gid_t)-1) == 0);
    }
    char other[4096];
    (void)snprintf(other, sizeof(other), "%s/link", fixture->directory);
    CHECK(symlink(fixture->config, other) == 0);
    CHECK(expect_path(other, MAELYS_GIT_ERR_DENIED));
    CHECK(unlink(other) == 0 && symlink("absent", other) == 0);
    CHECK(expect_path(other, MAELYS_GIT_ERR_DENIED));
    CHECK(unlink(other) == 0);
    CHECK(expect_path(other, MAELYS_GIT_ERR_NOT_FOUND));
    CHECK(expect_path(fixture->directory, MAELYS_GIT_ERR_DENIED));
    CHECK(mkfifo(other, 0600) == 0);
    CHECK(expect_path(other, MAELYS_GIT_ERR_DENIED));
    CHECK(unlink(other) == 0);
    int before = open("/dev/null", O_RDONLY | O_CLOEXEC);
    CHECK(before >= 0 && close(before) == 0);
    for (size_t i = 0u; i < 64u; ++i) {
        CHECK(expect_bytes(fixture, "{", 1u, MAELYS_GIT_ERR_PROTOCOL));
        CHECK(expect_path(fixture->directory, MAELYS_GIT_ERR_DENIED));
    }
    int after = open("/dev/null", O_RDONLY | O_CLOEXEC);
    CHECK(after >= 0 && close(after) == 0 && after == before);
    return 1;
}

int main(void) {
    fixture_t fixture = {0};
    if (!fixture_init(&fixture)) return 1;
    int passed = test_valid_config(&fixture);
    passed += test_syntax_and_limits(&fixture);
    passed += test_numeric_contract(&fixture);
    passed += test_schema_and_strings(&fixture);
    passed += test_file_security(&fixture);
    free(fixture.base);
    if (!test_remove_tree(fixture.directory) || passed != 5) return 1;
    (void)printf("ok: %d configuration reader test groups passed\n", passed);
    return 0;
}
