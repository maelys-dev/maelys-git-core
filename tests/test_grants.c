/* The snapshot of Gitolite grants, maelys-git-grants/1: its closed form, its
 * order, its bounds, and the trusted read of its file. */
#include "internal.h"
#include "policy/grants.h"
#include "test_support.h"

#include <maelys/cli/digest.h>

#include <errno.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[256];

/* A snapshot with the given sections; NULL leaves a section empty. */
#define SNAPSHOT_FORMAT \
    "{\"format\":\"maelys-git-grants/1\",\"members\":[%s],\"nested\":[%s],\"access\":[%s]," \
    "\"refs\":[%s],\"namespace_creators\":[%s],\"owner_access\":[%s],\"vref_names\":[%s]," \
    "\"vref_limits\":[%s]}"
#define OR_EMPTY(x) ((x) ? (x) : "")

static char *snapshot(const char *members, const char *nested, const char *access, const char *refs,
                      const char *creators, const char *owners, const char *names, const char *limits) {
    int size = snprintf(NULL, 0u, SNAPSHOT_FORMAT, OR_EMPTY(members), OR_EMPTY(nested), OR_EMPTY(access),
                        OR_EMPTY(refs), OR_EMPTY(creators), OR_EMPTY(owners), OR_EMPTY(names),
                        OR_EMPTY(limits));
    char *text = size < 0 ? NULL : malloc((size_t)size + 1u);
    if (text)
        (void)snprintf(text, (size_t)size + 1u, SNAPSHOT_FORMAT, OR_EMPTY(members), OR_EMPTY(nested),
                       OR_EMPTY(access), OR_EMPTY(refs), OR_EMPTY(creators), OR_EMPTY(owners),
                       OR_EMPTY(names), OR_EMPTY(limits));
    return text;
}

static maelys_git_result_t parse(const char *text, mg_grants_t **out, maelys_git_error_t *error) {
    return mg_grants_parse(text, strlen(text), out, error);
}

/* TEXT is refused with CODE and a message holding REASON. */
static int refused(const char *text, maelys_git_result_t code, const char *reason) {
    mg_grants_t *grants = NULL;
    maelys_git_error_t error = {0};
    maelys_git_result_t result = parse(text, &grants, &error);
    if (result != code || grants || !strstr(error.message, reason))
        (void)fprintf(stderr, "expected %d \"%s\", got %d \"%s\"\n", code, reason, result, error.message);
    return result == code && !grants && strstr(error.message, reason) != NULL;
}

static int test_accepted(void) {
    char *empty = snapshot(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    mg_grants_t *grants = NULL;
    maelys_git_error_t error = {0};
    CHECK(empty && parse(empty, &grants, &error) == MAELYS_GIT_OK);
    char digest[MAELYS_CLI_SHA256_HEX_SIZE];
    maelys_cli_sha256_hex(empty, strlen(empty), digest);
    CHECK(!strcmp(mg_grants_sha256(grants), digest));
    mg_grants_view_t view;
    mg_grants_view(grants, &view);
    CHECK(view.member_count == 0u && view.access_count == 0u && view.group_count == 0u);
    mg_grants_free(grants);
    free(empty);

    char *full = snapshot(
        "[\"alice\",\"devs\"],[\"bob\",\"devs\"]",
        "[\"devs\",\"eng\"]",
        "[\"group\",\"devs\",\"app.git\",\"RW\"],[\"user\",\"alice\",\"app.git\",\"RW+\"]",
        "[\"group\",\"devs\",\"app.git\",\"prefix\",\"refs/heads/rel/\",\"RW\"],"
        "[\"user\",\"bob\",\"app.git\",\"exact\",\"refs/heads/main\",\"-\"],"
        "[\"user\",\"bob\",\"app.git\",\"prefix\",\"refs/heads/main\",\"-\"]",
        "[\"group\",\"eng\",\"team\"]",
        "[\"team\",\"RW+\"]",
        "[\"group\",\"devs\",\"app.git\",\"docs/secret.txt\"]",
        "[\"group\",\"devs\",\"app.git\",\"count\",100],[\"user\",\"alice\",\"app.git\",\"max_new_binary\",0]");
    CHECK(full && parse(full, &grants, &error) == MAELYS_GIT_OK);
    mg_grants_view(grants, &view);
    CHECK(view.member_count == 2u && view.nested_count == 1u && view.access_count == 2u &&
          view.ref_count == 3u && view.creator_count == 1u && view.owner_count == 1u &&
          view.vref_name_count == 1u && view.vref_limit_count == 2u);
    CHECK(view.group_count == 2u);  /* devs, eng */
    CHECK(view.refs[0].prefix == 1 && !strcmp(view.refs[0].pattern, "refs/heads/rel/"));
    CHECK(view.access[1].kind == MG_SUBJECT_USER && !strcmp(view.access[1].level, "RW+"));
    CHECK(view.vref_limits[0].value == 100 && view.index_bytes > 0u);
    mg_grants_free(grants);
    free(full);
    return 1;
}

static int test_refused_shapes(void) {
    char *text;
    CHECK(refused("[]", MAELYS_GIT_ERR_INVALID_ARGUMENT, "an object of nine members"));
    CHECK(refused("{\"format\":\"maelys-git-grants/1\"}", MAELYS_GIT_ERR_INVALID_ARGUMENT, "nine members"));
    text = snapshot(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    char *other = malloc(strlen(text) + 32u);
    (void)snprintf(other, strlen(text) + 32u, "%.*s,\"surprise\":1}", (int)strlen(text) - 1, text);
    CHECK(refused(other, MAELYS_GIT_ERR_INVALID_ARGUMENT, "nine members"));
    free(other);
    char *renamed = strdup(text);
    memcpy(strstr(renamed, "\"nested\""), "\"nestex\"", 8u);
    CHECK(refused(renamed, MAELYS_GIT_ERR_INVALID_ARGUMENT, "an unknown member"));
    free(renamed);
    char *format = strdup(text);
    memcpy(strstr(format, "grants/1"), "grants/2", 8u);
    CHECK(refused(format, MAELYS_GIT_ERR_INVALID_ARGUMENT, "format is not maelys-git-grants/1"));
    free(format);
    free(text);
    CHECK(refused("{\"a\":", MAELYS_GIT_ERR_INVALID_ARGUMENT, "not valid JSON"));

    static const struct {
        const char *access, *refs, *names, *limits, *reason;
    } cases[] = {
        {"[\"user\",\"alice\",\"app.git\"]", NULL, NULL, NULL, "wrong number of elements"},
        {"[\"robot\",\"alice\",\"app.git\",\"R\"]", NULL, NULL, NULL, "kind is"},
        {"[\"user\",\"al ice\",\"app.git\",\"R\"]", NULL, NULL, NULL, "name is invalid"},
        {"[\"user\",\"alice\",\"../app.git\",\"R\"]", NULL, NULL, NULL, "repository name is invalid"},
        {"[\"user\",\"alice\",\"app.git\",\"W\"]", NULL, NULL, NULL, "level is"},
        {"[\"user\",\"alice\",\"app.git\",1]", NULL, NULL, NULL, "a string is expected"},
        {NULL, "[\"user\",\"a\",\"app.git\",\"prefix\",\"refs/heads/rel\",\"RW\"]", NULL, NULL, "ref pattern"},
        /* A deny's bare literal is a prefix; a grant's is not. */
        {NULL, "[\"user\",\"a\",\"app.git\",\"prefix\",\"refs/heads/main\",\"RW+\"]", NULL, NULL, "ref pattern"},
        {NULL, "[\"user\",\"a\",\"app.git\",\"prefix\",\"refs/heads/../\",\"RW\"]", NULL, NULL, "ref pattern"},
        {NULL, "[\"user\",\"a\",\"app.git\",\"prefix\",\"heads/rel/\",\"RW\"]", NULL, NULL, "ref pattern"},
        {NULL, "[\"user\",\"a\",\"app.git\",\"exact\",\"refs/heads/a b\",\"RW\"]", NULL, NULL, "ref pattern"},
        {NULL, "[\"user\",\"a\",\"app.git\",\"glob\",\"refs/heads/\",\"RW\"]", NULL, NULL, "form is"},
        {NULL, "[\"user\",\"a\",\"app.git\",\"exact\",\"refs/heads/main\",\"R\"]", NULL, NULL, "level is"},
        {NULL, NULL, "[\"user\",\"a\",\"app.git\",\"/etc/passwd\"]", NULL, "VREF path"},
        {NULL, NULL, "[\"user\",\"a\",\"app.git\",\"docs/../x\"]", NULL, "VREF path"},
        {NULL, NULL, NULL, "[\"user\",\"a\",\"app.git\",\"count\",-1]", "value is an integer"},
        {NULL, NULL, NULL, "[\"user\",\"a\",\"app.git\",\"count\",1.0]", "value is an integer"},
        {NULL, NULL, NULL, "[\"user\",\"a\",\"app.git\",\"size\",1]", "limit is"},
        /* Order: strictly increasing, so neither unsorted nor repeated. */
        {"[\"user\",\"bob\",\"app.git\",\"R\"],[\"user\",\"alice\",\"app.git\",\"R\"]", NULL, NULL, NULL,
         "strictly increasing"},
        {"[\"user\",\"alice\",\"app.git\",\"R\"],[\"user\",\"alice\",\"app.git\",\"R\"]", NULL, NULL, NULL,
         "strictly increasing"},
        {NULL, NULL, NULL, "[\"user\",\"a\",\"app.git\",\"count\",10],[\"user\",\"a\",\"app.git\",\"count\",9]",
         "strictly increasing"},
    };
    for (size_t i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        text = snapshot(NULL, NULL, cases[i].access, cases[i].refs, NULL, NULL, cases[i].names, cases[i].limits);
        CHECK(text && refused(text, MAELYS_GIT_ERR_INVALID_ARGUMENT, cases[i].reason));
        free(text);
    }
    return 1;
}

/* A growing text, for the snapshots of the bounds. */
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
    while (text->length + (size_t)needed + 1u > text->capacity) {
        size_t next = text->capacity ? text->capacity * 2u : 4096u;
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

/* COUNT access grants to users u00000... on one repository, or to groups
 * g0000... when GROUPS is set. */
static char *many_access(size_t count, int groups) {
    text_t text = {0};
    for (size_t i = 0u; i < count; ++i)
        if (!append(&text, "%s[\"%s\",\"%c%05zu\",\"app.git\",\"R\"]", i ? "," : "",
                    groups ? "group" : "user", groups ? 'g' : 'u', i))
            return NULL;
    char *full = snapshot(NULL, NULL, text.data ? text.data : "", NULL, NULL, NULL, NULL, NULL);
    free(text.data);
    return full;
}

static int accepted(const char *text) {
    mg_grants_t *grants = NULL;
    maelys_git_error_t error = {0};
    maelys_git_result_t result = parse(text, &grants, &error);
    if (result != MAELYS_GIT_OK) (void)fprintf(stderr, "refused: %s\n", error.message);
    mg_grants_free(grants);
    return result == MAELYS_GIT_OK;
}

static int test_bounds(void) {
    /* 65 536 grants, then one more. */
    char *text = many_access(MG_GRANTS_MAX_TUPLES, 0);
    CHECK(text && accepted(text));
    free(text);
    text = many_access(MG_GRANTS_MAX_TUPLES + 1u, 0);
    CHECK(text && refused(text, MAELYS_GIT_ERR_LIMIT, "more than 65536 grants"));
    free(text);
    /* 4 096 groups, then one more. */
    text = many_access(MG_GRANTS_MAX_GROUPS, 1);
    CHECK(text && accepted(text));
    free(text);
    text = many_access(MG_GRANTS_MAX_GROUPS + 1u, 1);
    CHECK(text && refused(text, MAELYS_GIT_ERR_LIMIT, "more than 4096 groups"));
    free(text);
    /* 64 direct groups of one member, then 65. */
    for (size_t count = MG_GRANTS_MAX_DIRECT_GROUPS; count <= MG_GRANTS_MAX_DIRECT_GROUPS + 1u; ++count) {
        text_t members = {0};
        for (size_t i = 0u; i < count; ++i)
            CHECK(append(&members, "%s[\"alice\",\"g%03zu\"]", i ? "," : "", i));
        text = snapshot(members.data, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        free(members.data);
        CHECK(text && (count == MG_GRANTS_MAX_DIRECT_GROUPS
                           ? accepted(text)
                           : refused(text, MAELYS_GIT_ERR_LIMIT, "more than 64 groups")));
        free(text);
    }
    /* A string of 1 023 bytes, then 1 024 (a VREF path of one component). */
    for (size_t length = MG_GRANTS_MAX_STRING; length <= MG_GRANTS_MAX_STRING + 1u; ++length) {
        char path[MG_GRANTS_MAX_STRING + 2u], tuple[MG_GRANTS_MAX_STRING + 64u];
        memset(path, 'p', length);
        path[length] = '\0';
        (void)snprintf(tuple, sizeof(tuple), "[\"user\",\"a\",\"app.git\",\"%s\"]", path);
        text = snapshot(NULL, NULL, NULL, NULL, NULL, NULL, tuple, NULL);
        CHECK(text && (length == MG_GRANTS_MAX_STRING
                           ? accepted(text)
                           : refused(text, MAELYS_GIT_ERR_LIMIT, "longer than 1023 bytes")));
        free(text);
    }
    /* 16 MiB of text, the last bytes whitespace, then one byte more. */
    char *base = snapshot(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    CHECK(base);
    char *big = malloc(MG_GRANTS_MAX_BYTES + 2u);
    CHECK(big);
    memset(big, ' ', MG_GRANTS_MAX_BYTES + 1u);
    memcpy(big, base, strlen(base));
    big[MG_GRANTS_MAX_BYTES] = '\0';
    CHECK(accepted(big));
    big[MG_GRANTS_MAX_BYTES] = ' ';
    big[MG_GRANTS_MAX_BYTES + 1u] = '\0';
    CHECK(refused(big, MAELYS_GIT_ERR_LIMIT, "exceeds 16777216 bytes"));
    free(big);
    /* Depth 4: a tuple holding an array. */
    text = snapshot(NULL, NULL, "[\"user\",\"alice\",\"app.git\",[\"R\"]]", NULL, NULL, NULL, NULL, NULL);
    CHECK(text && refused(text, MAELYS_GIT_ERR_LIMIT, "not valid JSON within its limits"));
    free(text);
    free(base);
    return 1;
}

static int write_file(const char *path, const char *text, mode_t mode) {
    FILE *file = fopen(path, "w");
    if (!file) return 0;
    int ok = fputs(text, file) >= 0;
    if (fclose(file) != 0) ok = 0;
    return ok && chmod(path, mode) == 0;
}

static maelys_git_result_t load(const char *path, maelys_git_error_t *error) {
    mg_grants_t *grants = NULL;
    maelys_git_result_t result = mg_grants_load(path, &grants, error);
    mg_grants_free(grants);
    return result;
}

/* The trusted read: owned by the caller, not writable by others, in a
 * directory only the caller may change; links are followed and the
 * directory of their target is judged. */
static int test_trusted_read(void) {
    char *text = snapshot(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    char trusted[512], open_dir[512], file[600], shared[600], loose[600], link_in[600], link_out[600];
    (void)snprintf(trusted, sizeof(trusted), "%s/trusted", g_root);
    (void)snprintf(open_dir, sizeof(open_dir), "%s/open", g_root);
    CHECK(text && mkdir(trusted, 0700) == 0 && mkdir(open_dir, 0700) == 0 && chmod(open_dir, 0770) == 0);
    (void)snprintf(file, sizeof(file), "%s/grants.json", trusted);
    (void)snprintf(loose, sizeof(loose), "%s/loose.json", trusted);
    (void)snprintf(shared, sizeof(shared), "%s/grants.json", open_dir);
    CHECK(write_file(file, text, 0644) && write_file(loose, text, 0664) && write_file(shared, text, 0644));
    maelys_git_error_t error = {0};
    CHECK(load(file, &error) == MAELYS_GIT_OK);
    /* Writable by the group: refused. */
    CHECK(load(loose, &error) == MAELYS_GIT_ERR_DENIED);
    /* In a directory the group may change: refused. */
    CHECK(load(shared, &error) == MAELYS_GIT_ERR_DENIED);
    /* A link to the trusted file is followed and accepted; a link to the
     * file of the open directory is refused for that directory. */
    (void)snprintf(link_in, sizeof(link_in), "%s/link-in.json", trusted);
    (void)snprintf(link_out, sizeof(link_out), "%s/link-out.json", trusted);
    CHECK(symlink(file, link_in) == 0 && symlink(shared, link_out) == 0);
    CHECK(load(link_in, &error) == MAELYS_GIT_OK);
    CHECK(load(link_out, &error) == MAELYS_GIT_ERR_DENIED);
    /* Missing, then a FIFO: refused, the FIFO without blocking. */
    char missing[600], fifo[600];
    (void)snprintf(missing, sizeof(missing), "%s/missing.json", trusted);
    (void)snprintf(fifo, sizeof(fifo), "%s/fifo.json", trusted);
    CHECK(load(missing, &error) == MAELYS_GIT_ERR_NOT_FOUND);
    CHECK(mkfifo(fifo, 0600) == 0 && load(fifo, &error) != MAELYS_GIT_OK);
    /* One byte past the bound, read from a file. */
    char big_path[600];
    (void)snprintf(big_path, sizeof(big_path), "%s/big.json", trusted);
    FILE *big = fopen(big_path, "w");
    CHECK(big && fputs(text, big) >= 0);
    for (size_t i = strlen(text); i <= MG_GRANTS_MAX_BYTES; ++i) CHECK(fputc(' ', big) != EOF);
    CHECK(fclose(big) == 0 && chmod(big_path, 0644) == 0);
    CHECK(load(big_path, &error) == MAELYS_GIT_ERR_LIMIT);
    free(text);
    return 1;
}

int main(void) {
    char template[] = "/tmp/maelys_git_grants_XXXXXX";
    char *root = mkdtemp(template);
    if (!root) return 1;
    (void)snprintf(g_root, sizeof(g_root), "%s", root);
    int ok = test_accepted() && test_refused_shapes() && test_bounds() && test_trusted_read();
    if (!test_remove_tree(g_root)) ok = 0;
    if (ok) puts("grants snapshot: closed form, order, bounds, trusted read: ok");
    return ok ? 0 : 1;
}
