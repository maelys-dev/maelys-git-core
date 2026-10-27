#include "internal.h"
#include "policy/grants.h"
#include "policy/refex.h"

#include <maelys/cli/digest.h>
#include <maelys/cli/files.h>
#include <maelys/json.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The parse limits of a snapshot: its bytes, three levels (the object, a
 * section, a tuple), and the values its schema allows, keys included: the
 * object, its nine keys and nine values, then for each tuple its array and
 * at most six fields. A text of more values is refused while it is parsed,
 * before its document grows. */
#define GRANTS_DEPTH 3u
#define MAX_FIELDS 6u
#define GRANTS_TOKENS (19u + (1u + MAX_FIELDS) * MG_GRANTS_MAX_TUPLES)

struct mg_grants {
    mg_grants_view_t view;
    char *strings;                      /* the arena every string of the view points into */
    char sha256[MAELYS_CLI_SHA256_HEX_SIZE];
    maelys_cli_regex_t **regexes;       /* the distinct "regex" patterns, compiled */
    unsigned char *scratch;             /* view.scratch_bytes, for one search at a time */
};

int mg_grants_test_accept_regex;

/* One field of a tuple while it is read: a string, or the integer of a
 * VREF limit. Tuples compare field by field, strings by their bytes. */
typedef struct {
    const char *text;
    int64_t number;
} field_t;

typedef struct {
    const maelys_json_document_t *document;
    maelys_git_error_t *error;
    const char *section;
    size_t index;
    size_t tuples;
    int regex_format;                   /* maelys-git-grants/2 */
} reader_t;

static int refuse(reader_t *reader, maelys_git_result_t code, const char *reason) {
    mg_error_set(reader->error, code, 0, "grants snapshot: %s[%zu]: %s", reader->section, reader->index,
                 reason);
    return 0;
}

static int compare_fields(const field_t *a, const field_t *b, size_t count) {
    for (size_t i = 0u; i < count; ++i) {
        if (a[i].text && b[i].text) {
            int order = strcmp(a[i].text, b[i].text);
            if (order) return order;
        } else if (a[i].number != b[i].number) {
            return a[i].number < b[i].number ? -1 : 1;
        }
    }
    return 0;
}

/* The string of a tuple element, at most MG_GRANTS_MAX_STRING bytes. */
static const char *string_at(reader_t *reader, maelys_json_value_t tuple, size_t position) {
    maelys_json_value_t value;
    maelys_json_view_t view;
    if (maelys_json_array_get(reader->document, tuple, position, &value) != MAELYS_JSON_OK ||
        maelys_json_value_string(reader->document, value, &view) != MAELYS_JSON_OK) {
        (void)refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "a string is expected");
        return NULL;
    }
    if (view.size == 0u || view.size > MG_GRANTS_MAX_STRING) {
        (void)refuse(reader, MAELYS_GIT_ERR_LIMIT, "a string is empty or longer than 1024 bytes");
        return NULL;
    }
    return view.data;
}

static int one_of(const char *value, const char *const *allowed) {
    for (; *allowed; ++allowed)
        if (!strcmp(value, *allowed)) return 1;
    return 0;
}

static int subject_kind(reader_t *reader, const char *text, mg_subject_kind_t *out) {
    if (!strcmp(text, "user")) *out = MG_SUBJECT_USER;
    else if (!strcmp(text, "group")) *out = MG_SUBJECT_GROUP;
    else return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "kind is \"user\" or \"group\"");
    return 1;
}

static int name(reader_t *reader, const char *text) {
    return mg_gitolite_name_is_valid(text) ||
           refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "a user, group or namespace name is invalid");
}

static int repository(reader_t *reader, const char *text) {
    return maelys_git_repository_name_is_valid(text) ||
           refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "a repository name is invalid");
}

/* The generator's refex subset, by its own rule. */
static int pattern(reader_t *reader, int prefix, int deny, const char *text) {
    return mg_gitolite_pattern_is_valid(text, prefix, deny) ||
           refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "a ref pattern is invalid");
}

/* A VREF path: relative, components of [A-Za-z0-9._-], none "." or "..". */
static int vref_path(reader_t *reader, const char *text) {
    int valid = text[0] != '/' && text[strlen(text) - 1u] != '/';
    const char *component = text;
    for (const char *p = text; valid; ++p) {
        if (*p == '/' || *p == '\0') {
            size_t length = (size_t)(p - component);
            valid = length && !(length == 1u && component[0] == '.') &&
                    !(length == 2u && component[0] == '.' && component[1] == '.');
            if (*p == '\0') break;
            component = p + 1;
        } else {
            unsigned char ch = (unsigned char)*p;
            valid = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
                    ch == '.' || ch == '_' || ch == '-';
        }
    }
    return valid || refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "a VREF path is invalid");
}

/* The tuples of SECTION, of ARITY elements each, in strictly increasing
 * order. READ_TUPLE validates one tuple into FIELDS and stores it at
 * index *count of OUT. */
typedef int (*tuple_reader_t)(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out,
                              size_t index);

static int read_section(reader_t *reader, maelys_json_value_t root, const char *section, size_t arity,
                        size_t element_size, tuple_reader_t read_tuple, void **out, size_t *out_count,
                        size_t *index_bytes) {
    reader->section = section;
    reader->index = 0u;
    maelys_json_value_t array;
    size_t count = 0u;
    if (maelys_json_object_get(reader->document, root, section, &array) != MAELYS_JSON_OK ||
        maelys_json_array_size(reader->document, array, &count) != MAELYS_JSON_OK)
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "an array is expected");
    if (count > MG_GRANTS_MAX_TUPLES - reader->tuples)
        return refuse(reader, MAELYS_GIT_ERR_LIMIT, "the snapshot holds more than 65536 grants");
    reader->tuples += count;
    void *elements = count ? calloc(count, element_size) : NULL;
    if (count && !elements) return refuse(reader, MAELYS_GIT_ERR_IO, "out of memory");
    *out = elements;
    *out_count = count;
    *index_bytes += count * element_size;
    field_t previous[MAX_FIELDS], current[MAX_FIELDS];
    for (size_t i = 0u; i < count; ++i) {
        reader->index = i;
        maelys_json_value_t tuple;
        size_t size = 0u;
        if (maelys_json_array_get(reader->document, array, i, &tuple) != MAELYS_JSON_OK ||
            maelys_json_array_size(reader->document, tuple, &size) != MAELYS_JSON_OK || size != arity)
            return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "a tuple has the wrong number of elements");
        memset(current, 0, sizeof(current));
        if (!read_tuple(reader, tuple, current, elements, i)) return 0;
        if (i && compare_fields(previous, current, arity) >= 0)
            return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT,
                          "tuples are not in strictly increasing order");
        memcpy(previous, current, sizeof(previous));
    }
    return 1;
}

static int read_member(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    mg_grant_member_t *member = (mg_grant_member_t *)out + index;
    if (!(member->user = fields[0].text = string_at(reader, tuple, 0u)) ||
        !(member->group = fields[1].text = string_at(reader, tuple, 1u)))
        return 0;
    if (!strcmp(member->group, MG_GRANTS_ALL_GROUP))
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT,
                      "the group all holds every user and has no explicit member");
    return name(reader, member->user) && name(reader, member->group);
}

static int read_nested(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    mg_grant_nested_t *nested = (mg_grant_nested_t *)out + index;
    if (!(nested->group = fields[0].text = string_at(reader, tuple, 0u)) ||
        !(nested->parent = fields[1].text = string_at(reader, tuple, 1u)))
        return 0;
    if (!strcmp(nested->group, MG_GRANTS_ALL_GROUP) || !strcmp(nested->parent, MG_GRANTS_ALL_GROUP))
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT,
                      "the group all holds every user and is not nested");
    return name(reader, nested->group) && name(reader, nested->parent);
}

/* kind and subject, the first two elements of most tuples. */
static int read_subject(reader_t *reader, maelys_json_value_t tuple, field_t *fields,
                        mg_subject_kind_t *kind, const char **subject) {
    return (fields[0].text = string_at(reader, tuple, 0u)) &&
           subject_kind(reader, fields[0].text, kind) &&
           (*subject = fields[1].text = string_at(reader, tuple, 1u)) && name(reader, *subject);
}

static int read_access(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    static const char *const levels[] = {"C", "R", "RW", "RW+", NULL};
    mg_grant_access_t *access = (mg_grant_access_t *)out + index;
    if (!read_subject(reader, tuple, fields, &access->kind, &access->subject) ||
        !(access->repository = fields[2].text = string_at(reader, tuple, 2u)) ||
        !repository(reader, access->repository) ||
        !(access->level = fields[3].text = string_at(reader, tuple, 3u)))
        return 0;
    return one_of(access->level, levels) ||
           refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "level is \"C\", \"R\", \"RW\" or \"RW+\"");
}

static int read_ref(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    static const char *const levels[] = {"RW", "RW+", "-", NULL};
    mg_grant_ref_t *ref = (mg_grant_ref_t *)out + index;
    if (!read_subject(reader, tuple, fields, &ref->kind, &ref->subject) ||
        !(ref->repository = fields[2].text = string_at(reader, tuple, 2u)) ||
        !repository(reader, ref->repository) || !(fields[3].text = string_at(reader, tuple, 3u)))
        return 0;
    if (!strcmp(fields[3].text, "prefix")) ref->form = MG_REF_PREFIX;
    else if (!strcmp(fields[3].text, "exact")) ref->form = MG_REF_EXACT;
    else if (!strcmp(fields[3].text, "regex") && reader->regex_format) ref->form = MG_REF_REGEX;
    else
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT,
                      reader->regex_format ? "form is \"exact\", \"prefix\" or \"regex\""
                                           : "form is \"exact\" or \"prefix\"");
    if (!(ref->pattern = fields[4].text = string_at(reader, tuple, 4u)) ||
        !(ref->level = fields[5].text = string_at(reader, tuple, 5u)))
        return 0;
    if (!one_of(ref->level, levels))
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "level is \"RW\", \"RW+\" or \"-\"");
    /* A regex is checked once per distinct pattern, when it is compiled. */
    if (ref->form == MG_REF_REGEX) return 1;
    return pattern(reader, ref->form == MG_REF_PREFIX, !strcmp(ref->level, "-"), ref->pattern);
}

static int read_creator(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    mg_grant_creator_t *creator = (mg_grant_creator_t *)out + index;
    return read_subject(reader, tuple, fields, &creator->kind, &creator->subject) &&
           (creator->namespace_name = fields[2].text = string_at(reader, tuple, 2u)) &&
           name(reader, creator->namespace_name);
}

static int read_owner(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    static const char *const levels[] = {"R", "RW", "RW+", NULL};
    mg_grant_owner_t *owner = (mg_grant_owner_t *)out + index;
    if (!(owner->namespace_name = fields[0].text = string_at(reader, tuple, 0u)) ||
        !name(reader, owner->namespace_name) || !(owner->level = fields[1].text = string_at(reader, tuple, 1u)))
        return 0;
    return one_of(owner->level, levels) ||
           refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "level is \"R\", \"RW\" or \"RW+\"");
}

static int read_vref_name(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    mg_grant_vref_name_t *vref = (mg_grant_vref_name_t *)out + index;
    return read_subject(reader, tuple, fields, &vref->kind, &vref->subject) &&
           (vref->repository = fields[2].text = string_at(reader, tuple, 2u)) &&
           repository(reader, vref->repository) &&
           (vref->path = fields[3].text = string_at(reader, tuple, 3u)) && vref_path(reader, vref->path);
}

static int read_vref_limit(reader_t *reader, maelys_json_value_t tuple, field_t *fields, void *out, size_t index) {
    static const char *const limits[] = {"count", "new_count", "max_new_binary", NULL};
    mg_grant_vref_limit_t *vref = (mg_grant_vref_limit_t *)out + index;
    if (!read_subject(reader, tuple, fields, &vref->kind, &vref->subject) ||
        !(vref->repository = fields[2].text = string_at(reader, tuple, 2u)) ||
        !repository(reader, vref->repository) || !(vref->limit = fields[3].text = string_at(reader, tuple, 3u)))
        return 0;
    if (!one_of(vref->limit, limits))
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT,
                      "limit is \"count\", \"new_count\" or \"max_new_binary\"");
    maelys_json_value_t value;
    if (maelys_json_array_get(reader->document, tuple, 4u, &value) != MAELYS_JSON_OK ||
        maelys_json_value_i64(reader->document, value, &vref->value) != MAELYS_JSON_OK || vref->value < 0)
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "value is an integer in [0, INT64_MAX]");
    fields[4].number = vref->value;
    return 1;
}

static int compare_names(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* The distinct groups the snapshot names, the group all always among them,
 * and at most MG_GRANTS_MAX_DIRECT_GROUPS direct groups for any member, all
 * included: every one is a slice_member fact of its requests. */
static int count_groups(reader_t *reader, mg_grants_view_t *view) {
    reader->section = "members";
    for (size_t i = 0u, run = 0u; i < view->member_count; ++i) {
        run = i && !strcmp(view->members[i].user, view->members[i - 1u].user) ? run + 1u : 1u;
        reader->index = i;
        if (run + 1u > MG_GRANTS_MAX_DIRECT_GROUPS)
            return refuse(reader, MAELYS_GIT_ERR_LIMIT,
                          "a member belongs directly to more than 64 groups, the group all included");
    }
    size_t capacity = view->member_count + 2u * view->nested_count + view->access_count + view->ref_count +
                      view->creator_count + view->vref_name_count + view->vref_limit_count;
    const char **names = capacity ? calloc(capacity, sizeof(*names)) : NULL;
    if (capacity && !names) return refuse(reader, MAELYS_GIT_ERR_IO, "out of memory");
    size_t used = 0u;
    for (size_t i = 0u; i < view->member_count; ++i) names[used++] = view->members[i].group;
    for (size_t i = 0u; i < view->nested_count; ++i) {
        names[used++] = view->nested[i].group;
        names[used++] = view->nested[i].parent;
    }
#define GROUP_SUBJECTS(array, count) \
    for (size_t i = 0u; i < (count); ++i) \
        if ((array)[i].kind == MG_SUBJECT_GROUP) names[used++] = (array)[i].subject;
    GROUP_SUBJECTS(view->access, view->access_count)
    GROUP_SUBJECTS(view->refs, view->ref_count)
    GROUP_SUBJECTS(view->creators, view->creator_count)
    GROUP_SUBJECTS(view->vref_names, view->vref_name_count)
    GROUP_SUBJECTS(view->vref_limits, view->vref_limit_count)
#undef GROUP_SUBJECTS
    if (used) qsort(names, used, sizeof(*names), compare_names);
    size_t distinct = 0u;
    int all_named = 0;
    for (size_t i = 0u; i < used; ++i) {
        if (!i || strcmp(names[i], names[i - 1u])) ++distinct;
        if (!strcmp(names[i], MG_GRANTS_ALL_GROUP)) all_named = 1;
    }
    if (!all_named) ++distinct;
    free(names);
    view->group_count = distinct;
    reader->section = "groups";
    reader->index = distinct;
    return distinct <= MG_GRANTS_MAX_GROUPS ||
           refuse(reader, MAELYS_GIT_ERR_LIMIT,
                  "the snapshot names more than 4096 groups, the group all included");
}

static const char *const k_sections[] = {"access", "format", "members", "namespace_creators", "nested",
                                         "owner_access", "refs", "vref_limits", "vref_names"};

/* The root: an object of exactly the nine members, and the format. */
static int read_root(reader_t *reader, maelys_json_value_t root) {
    reader->section = "root";
    size_t size = 0u;
    if (maelys_json_value_type(reader->document, root) != MAELYS_JSON_TYPE_OBJECT ||
        maelys_json_object_size(reader->document, root, &size) != MAELYS_JSON_OK ||
        size != sizeof(k_sections) / sizeof(k_sections[0]))
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "an object of nine members is expected");
    for (size_t i = 0u; i < size; ++i) {
        maelys_json_view_t key;
        maelys_json_value_t value;
        reader->index = i;
        if (maelys_json_object_member_at(reader->document, root, i, &key, &value) != MAELYS_JSON_OK ||
            !bsearch(&key.data, k_sections, sizeof(k_sections) / sizeof(k_sections[0]), sizeof(k_sections[0]),
                     compare_names))
            return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "an unknown member");
    }
    maelys_json_value_t format;
    maelys_json_view_t view;
    if (maelys_json_object_get(reader->document, root, "format", &format) != MAELYS_JSON_OK ||
        maelys_json_value_string(reader->document, format, &view) != MAELYS_JSON_OK)
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "format is not " MG_GRANTS_FORMAT);
    if (mg_grants_test_accept_regex && !strcmp(view.data, MG_GRANTS_FORMAT_REGEX)) reader->regex_format = 1;
    else if (strcmp(view.data, MG_GRANTS_FORMAT))
        return refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, "format is not " MG_GRANTS_FORMAT);
    return 1;
}

/* Every string field of the view, given to VISIT, which counts or moves it. */
static void visit_strings(mg_grants_view_t *view, void (*visit)(const char **field, void *context),
                          void *context) {
    mg_grant_member_t *members = (mg_grant_member_t *)view->members;
    mg_grant_nested_t *nested = (mg_grant_nested_t *)view->nested;
    mg_grant_access_t *access = (mg_grant_access_t *)view->access;
    mg_grant_ref_t *refs = (mg_grant_ref_t *)view->refs;
    mg_grant_creator_t *creators = (mg_grant_creator_t *)view->creators;
    mg_grant_owner_t *owners = (mg_grant_owner_t *)view->owners;
    mg_grant_vref_name_t *names = (mg_grant_vref_name_t *)view->vref_names;
    mg_grant_vref_limit_t *limits = (mg_grant_vref_limit_t *)view->vref_limits;
    for (size_t i = 0u; i < view->member_count; ++i) {
        visit(&members[i].user, context);
        visit(&members[i].group, context);
    }
    for (size_t i = 0u; i < view->nested_count; ++i) {
        visit(&nested[i].group, context);
        visit(&nested[i].parent, context);
    }
    for (size_t i = 0u; i < view->access_count; ++i) {
        visit(&access[i].subject, context);
        visit(&access[i].repository, context);
        visit(&access[i].level, context);
    }
    for (size_t i = 0u; i < view->ref_count; ++i) {
        visit(&refs[i].subject, context);
        visit(&refs[i].repository, context);
        visit(&refs[i].pattern, context);
        visit(&refs[i].level, context);
    }
    for (size_t i = 0u; i < view->creator_count; ++i) {
        visit(&creators[i].subject, context);
        visit(&creators[i].namespace_name, context);
    }
    for (size_t i = 0u; i < view->owner_count; ++i) {
        visit(&owners[i].namespace_name, context);
        visit(&owners[i].level, context);
    }
    for (size_t i = 0u; i < view->vref_name_count; ++i) {
        visit(&names[i].subject, context);
        visit(&names[i].repository, context);
        visit(&names[i].path, context);
    }
    for (size_t i = 0u; i < view->vref_limit_count; ++i) {
        visit(&limits[i].subject, context);
        visit(&limits[i].repository, context);
        visit(&limits[i].limit, context);
    }
}

static void count_string(const char **field, void *context) {
    *(size_t *)context += strlen(*field) + 1u;
}

static void move_string(const char **field, void *context) {
    char **cursor = context;
    size_t size = strlen(*field) + 1u;
    memcpy(*cursor, *field, size);
    *field = *cursor;
    *cursor += size;
}

/* Copies every string into one arena, so that the document can go. */
static int keep_strings(mg_grants_t *grants) {
    size_t bytes = 0u;
    visit_strings(&grants->view, count_string, &bytes);
    grants->strings = malloc(bytes ? bytes : 1u);
    if (!grants->strings) return 0;
    char *cursor = grants->strings;
    visit_strings(&grants->view, move_string, &cursor);
    grants->view.index_bytes += bytes;
    return 1;
}

/* A "regex" grant and its pattern, for the compilation of each distinct
 * pattern once; then a repository and a pattern, for the budget of each
 * repository. */
typedef struct {
    const char *pattern, *repository;
    size_t ref, id;
} regex_use_t;

static int compare_uses_by_pattern(const void *a, const void *b) {
    const regex_use_t *x = a, *y = b;
    int order = strcmp(x->pattern, y->pattern);
    return order ? order : (x->ref > y->ref) - (x->ref < y->ref);
}

static int compare_uses_by_repository(const void *a, const void *b) {
    const regex_use_t *x = a, *y = b;
    int order = strcmp(x->repository, y->repository);
    return order ? order : (x->id > y->id) - (x->id < y->id);
}

/* Compiles each distinct "regex" pattern once, by the restrictions of
 * policy/refex.h, and holds the budgets of D3: the states of the patterns
 * of one repository, which bound a request, and of the snapshot, which
 * bound its memory. A snapshot of format /2 holds at least one pattern of
 * the form: a set of grants has one byte form. */
static int compile_patterns(reader_t *reader, mg_grants_t *grants) {
    mg_grants_view_t *view = &grants->view;
    mg_grant_ref_t *refs = (mg_grant_ref_t *)view->refs;
    reader->section = "refs";
    size_t count = 0u;
    for (size_t i = 0u; i < view->ref_count; ++i) count += refs[i].form == MG_REF_REGEX;
    if (!count) {
        reader->index = 0u;
        return !reader->regex_format ||
               refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT,
                      "format " MG_GRANTS_FORMAT_REGEX " holds no regex pattern");
    }
    regex_use_t *uses = calloc(count, sizeof(*uses));
    grants->regexes = calloc(count, sizeof(*grants->regexes));
    if (!uses || !grants->regexes) {
        free(uses);
        return refuse(reader, MAELYS_GIT_ERR_IO, "out of memory");
    }
    size_t used = 0u;
    for (size_t i = 0u; i < view->ref_count; ++i)
        if (refs[i].form == MG_REF_REGEX)
            uses[used++] = (regex_use_t){refs[i].pattern, refs[i].repository, i, 0u};
    qsort(uses, count, sizeof(*uses), compare_uses_by_pattern);
    int ok = 1;
    size_t distinct = 0u, total = 0u, scratch = 0u;
    for (size_t u = 0u; ok && u < count; ++u) {
        if (u && !strcmp(uses[u].pattern, uses[u - 1u].pattern)) {
            uses[u].id = uses[u - 1u].id;
        } else {
            size_t offset = 0u;
            reader->index = uses[u].ref;
            const char *refused = mg_refex_regex_check(uses[u].pattern, &grants->regexes[distinct], &offset);
            if (refused) {
                char reason[200];
                (void)snprintf(reason, sizeof(reason), "a regex pattern is refused at byte %zu: %s", offset,
                               refused);
                ok = refuse(reader, MAELYS_GIT_ERR_INVALID_ARGUMENT, reason);
                break;
            }
            const maelys_cli_regex_t *regex = grants->regexes[distinct];
            total += maelys_cli_regex_states(regex);
            size_t bytes = maelys_cli_regex_scratch_size(regex);
            if (bytes > scratch) scratch = bytes;
            uses[u].id = distinct++;
            if (total > MG_REFEX_TOTAL_STATES)
                ok = refuse(reader, MAELYS_GIT_ERR_LIMIT,
                            "the regex patterns of the snapshot hold more than 1048576 states");
        }
        refs[uses[u].ref].regex = uses[u].id;
    }
    view->regex_count = distinct;
    view->regex_states = total;
    if (ok) {
        qsort(uses, count, sizeof(*uses), compare_uses_by_repository);
        size_t sum = 0u;
        for (size_t u = 0u; ok && u < count; ++u) {
            int same_repository = u && !strcmp(uses[u].repository, uses[u - 1u].repository);
            if (!same_repository) sum = 0u;
            else if (uses[u].id == uses[u - 1u].id) continue;
            sum += maelys_cli_regex_states(grants->regexes[uses[u].id]);
            if (sum > view->regex_repository_states) view->regex_repository_states = sum;
            reader->index = uses[u].ref;
            if (sum > MG_REFEX_REPOSITORY_STATES)
                ok = refuse(reader, MAELYS_GIT_ERR_LIMIT,
                            "the regex patterns of one repository hold more than 65536 states");
        }
    }
    free(uses);
    if (ok) {
        grants->scratch = malloc(scratch);
        if (!grants->scratch) return refuse(reader, MAELYS_GIT_ERR_IO, "out of memory");
        view->scratch_bytes = scratch;
    }
    return ok;
}

void mg_grants_free(mg_grants_t *grants) {
    if (!grants) return;
    for (size_t i = 0u; grants->regexes && i < grants->view.regex_count; ++i)
        maelys_cli_regex_free(grants->regexes[i]);
    free(grants->regexes);
    free(grants->scratch);
    free((void *)grants->view.members);
    free((void *)grants->view.nested);
    free((void *)grants->view.access);
    free((void *)grants->view.refs);
    free((void *)grants->view.creators);
    free((void *)grants->view.owners);
    free((void *)grants->view.vref_names);
    free((void *)grants->view.vref_limits);
    free(grants->strings);
    free(grants);
}

maelys_git_result_t mg_grants_parse(const void *bytes, size_t size, mg_grants_t **out,
                                    maelys_git_error_t *error) {
    if (!bytes || !out) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out = NULL;
    if (size > MG_GRANTS_MAX_BYTES) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "grants snapshot exceeds %u bytes", MG_GRANTS_MAX_BYTES);
        return MAELYS_GIT_ERR_LIMIT;
    }
    mg_grants_t *grants = calloc(1u, sizeof(*grants));
    if (!grants) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "out of memory");
        return MAELYS_GIT_ERR_IO;
    }
    const maelys_json_limits_t limits = {.maximum_bytes = MG_GRANTS_MAX_BYTES,
                                         .maximum_depth = GRANTS_DEPTH,
                                         .maximum_tokens = GRANTS_TOKENS};
    maelys_json_error_t json_error;
    maelys_json_document_t *document = NULL;
    maelys_json_result_t parsed = maelys_json_document_parse(bytes, size, MAELYS_JSON_PROFILE_RFC8259, &limits,
                                                             &document, &json_error);
    if (parsed != MAELYS_JSON_OK) {
        maelys_git_result_t code = parsed == MAELYS_JSON_ERR_LIMIT ? MAELYS_GIT_ERR_LIMIT
                                                                    : MAELYS_GIT_ERR_INVALID_ARGUMENT;
        mg_error_set(error, code, 0, "grants snapshot is not valid JSON within its limits: %s",
                     maelys_json_result_string(parsed));
        mg_grants_free(grants);
        return code;
    }
    /* One set of grants, one byte form: the bytes received are hashed only
     * when they are the canonical serialization of what they hold. */
    int canonical = 0;
    if (maelys_json_document_is_canonical(document, 0u, &canonical) != MAELYS_JSON_OK || !canonical) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0,
                     "grants snapshot is not in Canonical JSON v1");
        maelys_json_document_release(document);
        mg_grants_free(grants);
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    reader_t reader = {.document = document, .error = error};
    mg_grants_view_t *view = &grants->view;
    maelys_json_value_t root = maelys_json_document_root(document);
    int ok = read_root(&reader, root) &&
        read_section(&reader, root, "members", 2u, sizeof(mg_grant_member_t), read_member,
                     (void **)&view->members, &view->member_count, &view->index_bytes) &&
        read_section(&reader, root, "nested", 2u, sizeof(mg_grant_nested_t), read_nested,
                     (void **)&view->nested, &view->nested_count, &view->index_bytes) &&
        read_section(&reader, root, "access", 4u, sizeof(mg_grant_access_t), read_access,
                     (void **)&view->access, &view->access_count, &view->index_bytes) &&
        read_section(&reader, root, "refs", 6u, sizeof(mg_grant_ref_t), read_ref,
                     (void **)&view->refs, &view->ref_count, &view->index_bytes) &&
        read_section(&reader, root, "namespace_creators", 3u, sizeof(mg_grant_creator_t), read_creator,
                     (void **)&view->creators, &view->creator_count, &view->index_bytes) &&
        read_section(&reader, root, "owner_access", 2u, sizeof(mg_grant_owner_t), read_owner,
                     (void **)&view->owners, &view->owner_count, &view->index_bytes) &&
        read_section(&reader, root, "vref_names", 4u, sizeof(mg_grant_vref_name_t), read_vref_name,
                     (void **)&view->vref_names, &view->vref_name_count, &view->index_bytes) &&
        read_section(&reader, root, "vref_limits", 5u, sizeof(mg_grant_vref_limit_t), read_vref_limit,
                     (void **)&view->vref_limits, &view->vref_limit_count, &view->index_bytes) &&
        count_groups(&reader, view);
    if (ok && !keep_strings(grants)) ok = refuse(&reader, MAELYS_GIT_ERR_IO, "out of memory");
    if (ok) ok = compile_patterns(&reader, grants);
    view->format = reader.regex_format ? MG_GRANTS_FORMAT_REGEX : MG_GRANTS_FORMAT;
    maelys_json_document_release(document);
    if (!ok) {
        mg_grants_free(grants);
        return error && error->code != MAELYS_GIT_OK ? error->code : MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    maelys_cli_sha256_hex(bytes, size, grants->sha256);
    *out = grants;
    return MAELYS_GIT_OK;
}

void (*mg_grants_test_between_reads)(const char *path);

/* Whether two observations of one descriptor show the same file, unchanged:
 * its identity, its size, its change and modification times. */
static int same_file(const struct stat *a, const struct stat *b) {
#ifdef __APPLE__
    const struct timespec *ac = &a->st_ctimespec, *bc = &b->st_ctimespec;
    const struct timespec *am = &a->st_mtimespec, *bm = &b->st_mtimespec;
#else
    const struct timespec *ac = &a->st_ctim, *bc = &b->st_ctim;
    const struct timespec *am = &a->st_mtim, *bm = &b->st_mtim;
#endif
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
           ac->tv_sec == bc->tv_sec && ac->tv_nsec == bc->tv_nsec && am->tv_sec == bm->tv_sec &&
           am->tv_nsec == bm->tv_nsec;
}

/* The bytes of the file at PATH, read as a trusted file: links followed and
 * their target's directory judged. The descriptor read is observed before
 * and after the read; a file that changed meanwhile is refused for this
 * read. That guard detects a writer that broke the contract of publication
 * (an immutable file, replaced by a rename); it proves nothing more. */
maelys_git_result_t mg_grants_read(const char *path, unsigned char **out_bytes, size_t *out_size,
                                   maelys_git_error_t *error) {
    *out_bytes = NULL;
    *out_size = 0u;
    int descriptor = -1;
    const char *reason = NULL;
    struct stat before, after;
    int failed = maelys_cli_open_trusted(path,
                                         MAELYS_CLI_FILE_REGULAR | MAELYS_CLI_FILE_OWNER_TRUSTED |
                                             MAELYS_CLI_FILE_NOT_WRITABLE_BY_OTHERS |
                                             MAELYS_CLI_FILE_TRUSTED_DIRECTORY,
                                         &descriptor, &reason) != 0;
    if (!failed && fstat(descriptor, &before) != 0) failed = 1;
    if (!failed && maelys_cli_read_descriptor(descriptor, MG_GRANTS_MAX_BYTES, out_bytes, out_size) != 0)
        failed = 1;
    if (!failed && *out_size == 0u) {
        errno = EFBIG;
        failed = 1;
    }
    int saved = errno;
    if (!failed && mg_grants_test_between_reads) mg_grants_test_between_reads(path);
    int changed = !failed && (fstat(descriptor, &after) != 0 || !same_file(&before, &after));
    if (descriptor >= 0) (void)close(descriptor);
    if (failed) {
        free(*out_bytes);
        *out_bytes = NULL;
        maelys_git_result_t code = saved == EPERM || saved == EACCES ? MAELYS_GIT_ERR_DENIED
                                 : saved == ENOENT ? MAELYS_GIT_ERR_NOT_FOUND
                                 : saved == EFBIG ? MAELYS_GIT_ERR_LIMIT : MAELYS_GIT_ERR_IO;
        mg_error_set(error, code, saved, "grants snapshot %s refused: %s", path,
                     reason ? reason : saved == EFBIG ? "empty, or larger than 4 MiB" : strerror(saved));
        return code;
    }
    if (changed) {
        free(*out_bytes);
        *out_bytes = NULL;
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0,
                     "grants snapshot %s changed while it was read: publish it by renaming a new file", path);
        return MAELYS_GIT_ERR_IO;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_grants_load(const char *path, mg_grants_t **out, maelys_git_error_t *error) {
    if (!path || !out) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out = NULL;
    unsigned char *bytes = NULL;
    size_t size = 0u;
    maelys_git_result_t result = mg_grants_read(path, &bytes, &size, error);
    if (result != MAELYS_GIT_OK) return result;
    result = mg_grants_parse(bytes, size, out, error);
    free(bytes);
    return result;
}

maelys_git_result_t mg_grants_reload(const char *path, const mg_grants_t *current, mg_grants_t **out,
                                     maelys_git_error_t *error) {
    if (!path || !out) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    *out = NULL;
    unsigned char *bytes = NULL;
    size_t size = 0u;
    maelys_git_result_t result = mg_grants_read(path, &bytes, &size, error);
    if (result != MAELYS_GIT_OK) return result;
    char sha256[MAELYS_CLI_SHA256_HEX_SIZE];
    maelys_cli_sha256_hex(bytes, size, sha256);
    if (!current || strcmp(sha256, current->sha256) != 0) result = mg_grants_parse(bytes, size, out, error);
    free(bytes);
    return result;
}

const char *mg_grants_sha256(const mg_grants_t *grants) {
    return grants ? grants->sha256 : "";
}

void mg_grants_view(const mg_grants_t *grants, mg_grants_view_t *out) {
    if (grants && out) *out = grants->view;
}

const struct maelys_cli_regex *mg_grants_regex(const mg_grants_t *grants, size_t index) {
    return grants && index < grants->view.regex_count ? grants->regexes[index] : NULL;
}

void *mg_grants_scratch(const mg_grants_t *grants, size_t *out_size) {
    if (out_size) *out_size = grants ? grants->view.scratch_bytes : 0u;
    return grants ? grants->scratch : NULL;
}
