#include "internal.h"
#include "policy/slice.h"

#include <stdlib.h>
#include <string.h>

static const struct {
    const char *name;
    size_t arity;
} k_predicates[MG_SLICE_PREDICATE_COUNT] = {
    [MG_SLICE_MEMBER] = {"slice_member", 2u},
    [MG_SLICE_NESTED] = {"slice_nested", 2u},
    [MG_SLICE_ACCESS] = {"slice_access", 3u},
    [MG_SLICE_GROUP_ACCESS] = {"slice_group_access", 3u},
    [MG_SLICE_REF_MATCH] = {"slice_ref_match", 3u},
    [MG_SLICE_GROUP_REF_MATCH] = {"slice_group_ref_match", 3u},
    [MG_SLICE_REF_LEVEL] = {"slice_ref_level", 3u},
    [MG_SLICE_GROUP_REF_LEVEL] = {"slice_group_ref_level", 3u},
    [MG_SLICE_NAMESPACE_CREATOR] = {"slice_namespace_creator", 2u},
    [MG_SLICE_GROUP_NAMESPACE_CREATOR] = {"slice_group_namespace_creator", 2u},
    [MG_SLICE_OWNER_ACCESS] = {"slice_owner_access", 2u},
    [MG_SLICE_VREF_NAME] = {"slice_vref_name", 3u},
    [MG_SLICE_GROUP_VREF_NAME] = {"slice_group_vref_name", 3u},
    [MG_SLICE_VREF_COUNT] = {"slice_vref_count", 3u},
    [MG_SLICE_GROUP_VREF_COUNT] = {"slice_group_vref_count", 3u},
    [MG_SLICE_VREF_NEW_COUNT] = {"slice_vref_new_count", 3u},
    [MG_SLICE_GROUP_VREF_NEW_COUNT] = {"slice_group_vref_new_count", 3u},
    [MG_SLICE_VREF_MAX_NEW_BINARY] = {"slice_vref_max_new_binary", 3u},
    [MG_SLICE_GROUP_VREF_MAX_NEW_BINARY] = {"slice_group_vref_max_new_binary", 3u},
};

const char *mg_slice_predicate_name(mg_slice_predicate_t predicate) {
    return predicate < MG_SLICE_PREDICATE_COUNT ? k_predicates[predicate].name : NULL;
}

size_t mg_slice_predicate_arity(mg_slice_predicate_t predicate) {
    return predicate < MG_SLICE_PREDICATE_COUNT ? k_predicates[predicate].arity : 0u;
}

int mg_slice_pattern_matches(int prefix, const char *pattern, const char *ref) {
    if (!pattern || !ref) return 0;
    return prefix ? strncmp(ref, pattern, strlen(pattern)) == 0 : strcmp(ref, pattern) == 0;
}

const char *mg_slice_owner_namespace(const char *repository, const char *user, char *out, size_t size) {
    if (!repository || !user || !maelys_git_repository_name_is_valid(repository)) return NULL;
    const char *first_end = strchr(repository, '/');
    if (!first_end) return NULL;
    const char *second = first_end + 1, *second_end = strchr(second, '/');
    if (!second_end || strchr(second_end + 1, '\0') == second_end + 1) return NULL;
    size_t first_length = (size_t)(first_end - repository);
    if ((size_t)(second_end - second) != strlen(user) || strncmp(second, user, strlen(user)) ||
        first_length + 1u > size)
        return NULL;
    memcpy(out, repository, first_length);
    out[first_length] = '\0';
    return out;
}

static int compare_text(const char *a, const char *b) {
    if (a == b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    return strcmp(a, b);
}

int mg_slice_fact_compare(const mg_slice_fact_t *a, const mg_slice_fact_t *b) {
    if (a->predicate != b->predicate) return a->predicate < b->predicate ? -1 : 1;
    for (size_t i = 0u; i < 3u; ++i) {
        int order = compare_text(a->text[i], b->text[i]);
        if (order) return order;
    }
    return a->number == b->number ? 0 : (a->number < b->number ? -1 : 1);
}

static int compare_facts(const void *a, const void *b) {
    return mg_slice_fact_compare(a, b);
}

void mg_slice_normalize(mg_slice_t *slice) {
    if (!slice->count) return;
    qsort(slice->facts, slice->count, sizeof(*slice->facts), compare_facts);
    size_t kept = 1u;
    for (size_t i = 1u; i < slice->count; ++i)
        if (mg_slice_fact_compare(&slice->facts[kept - 1u], &slice->facts[i]))
            slice->facts[kept++] = slice->facts[i];
    slice->count = kept;
}

int mg_slice_add(mg_slice_t *slice, mg_slice_predicate_t predicate, const char *a, const char *b,
                 const char *c, int64_t number) {
    if (slice->count == slice->capacity) {
        size_t capacity = slice->capacity ? slice->capacity * 2u : 32u;
        mg_slice_fact_t *grown = realloc(slice->facts, capacity * sizeof(*grown));
        if (!grown) return 0;
        slice->facts = grown;
        slice->capacity = capacity;
    }
    slice->facts[slice->count++] = (mg_slice_fact_t){predicate, {a, b, c}, number};
    return 1;
}

void mg_slice_clear(mg_slice_t *slice) {
    if (!slice) return;
    free(slice->facts);
    memset(slice, 0, sizeof(*slice));
}

/* ---- lookups in the sorted sections ----------------------------------- */

/* Sections are ordered by the text of the kind ("group" before "user"),
 * then the subject, then the repository or namespace. */
static const char *kind_text(mg_subject_kind_t kind) {
    return kind == MG_SUBJECT_GROUP ? "group" : "user";
}

/* The key of element I of a section: its kind, subject and repository (or
 * namespace), NULL past the end of what the key covers. */
typedef void (*key_of_t)(const mg_grants_view_t *view, size_t i, const char **kind, const char **subject,
                         const char **place);

static int compare_key(const char *kind, const char *subject, const char *place, const char *other_kind,
                       const char *other_subject, const char *other_place) {
    int order = strcmp(kind, other_kind);
    if (!order) order = strcmp(subject, other_subject);
    if (!order && place && other_place) order = strcmp(place, other_place);
    return order;
}

/* [*first, *last): the elements whose key is (kind, subject[, place]). */
static void equal_range(const mg_grants_view_t *view, size_t count, key_of_t key_of, const char *kind,
                        const char *subject, const char *place, size_t *first, size_t *last) {
    size_t low = 0u, high = count;
    while (low < high) {
        size_t middle = low + (high - low) / 2u;
        const char *k, *s, *p;
        key_of(view, middle, &k, &s, &p);
        if (compare_key(k, s, place ? p : NULL, kind, subject, place) < 0) low = middle + 1u;
        else high = middle;
    }
    *first = low;
    size_t end = low;
    while (end < count) {
        const char *k, *s, *p;
        key_of(view, end, &k, &s, &p);
        if (compare_key(k, s, place ? p : NULL, kind, subject, place)) break;
        ++end;
    }
    *last = end;
}

static void access_key(const mg_grants_view_t *view, size_t i, const char **kind, const char **subject,
                       const char **place) {
    *kind = kind_text(view->access[i].kind);
    *subject = view->access[i].subject;
    *place = view->access[i].repository;
}

static void ref_key(const mg_grants_view_t *view, size_t i, const char **kind, const char **subject,
                    const char **place) {
    *kind = kind_text(view->refs[i].kind);
    *subject = view->refs[i].subject;
    *place = view->refs[i].repository;
}

static void creator_key(const mg_grants_view_t *view, size_t i, const char **kind, const char **subject,
                        const char **place) {
    *kind = kind_text(view->creators[i].kind);
    *subject = view->creators[i].subject;
    *place = view->creators[i].namespace_name;
}

static void vref_name_key(const mg_grants_view_t *view, size_t i, const char **kind, const char **subject,
                          const char **place) {
    *kind = kind_text(view->vref_names[i].kind);
    *subject = view->vref_names[i].subject;
    *place = view->vref_names[i].repository;
}

static void vref_limit_key(const mg_grants_view_t *view, size_t i, const char **kind, const char **subject,
                           const char **place) {
    *kind = kind_text(view->vref_limits[i].kind);
    *subject = view->vref_limits[i].subject;
    *place = view->vref_limits[i].repository;
}

/* The first member whose user (or nested group) is NAME, by binary search. */
static size_t first_member(const mg_grants_view_t *view, const char *user) {
    size_t low = 0u, high = view->member_count;
    while (low < high) {
        size_t middle = low + (high - low) / 2u;
        if (strcmp(view->members[middle].user, user) < 0) low = middle + 1u;
        else high = middle;
    }
    return low;
}

static size_t first_nested(const mg_grants_view_t *view, const char *group) {
    size_t low = 0u, high = view->nested_count;
    while (low < high) {
        size_t middle = low + (high - low) / 2u;
        if (strcmp(view->nested[middle].group, group) < 0) low = middle + 1u;
        else high = middle;
    }
    return low;
}

/* ---- extraction ----------------------------------------------------------- */

/* The groups a user reaches, in the order reached, with an index on their
 * text: open addressing, linear probing, at most half full, so that a
 * closure of G groups costs about G lookups rather than G squared
 * comparisons. */
typedef struct {
    const char **names;
    size_t count, capacity;
    size_t *slots;      /* 1 + the index of a name in names; 0 for a free slot */
    size_t slot_count;  /* a power of two */
} names_t;

/* FNV-1a over the bytes of NAME. */
static size_t name_hash(const char *name) {
    uint64_t hash = UINT64_C(14695981039346656037);
    for (const unsigned char *p = (const unsigned char *)name; *p; ++p) {
        hash ^= *p;
        hash *= UINT64_C(1099511628211);
    }
    return (size_t)hash;
}

/* The slot that holds NAME, or the free slot where it would go. */
static size_t names_slot(const names_t *names, const char *name) {
    size_t mask = names->slot_count - 1u;
    size_t slot = name_hash(name) & mask;
    while (names->slots[slot] && strcmp(names->names[names->slots[slot] - 1u], name))
        slot = (slot + 1u) & mask;
    return slot;
}

static int names_grow(names_t *names) {
    size_t slot_count = names->slot_count ? names->slot_count * 2u : 32u;
    size_t *slots = calloc(slot_count, sizeof(*slots));
    if (!slots) return 0;
    free(names->slots);
    names->slots = slots;
    names->slot_count = slot_count;
    for (size_t i = 0u; i < names->count; ++i) names->slots[names_slot(names, names->names[i])] = i + 1u;
    return 1;
}

/* Appends NAME unless it is there already; 0 when memory runs out. */
static int names_insert(names_t *names, const char *name) {
    if (2u * (names->count + 1u) > names->slot_count && !names_grow(names)) return 0;
    size_t slot = names_slot(names, name);
    if (names->slots[slot]) return 1;
    if (names->count == names->capacity) {
        size_t capacity = names->capacity ? names->capacity * 2u : 16u;
        const char **grown = realloc(names->names, capacity * sizeof(*grown));
        if (!grown) return 0;
        names->names = grown;
        names->capacity = capacity;
    }
    names->names[names->count++] = name;
    names->slots[slot] = names->count;
    return 1;
}

static int is_write_level(const char *level) {
    return !strcmp(level, "RW") || !strcmp(level, "RW+");
}

static int has_path(const mg_slice_request_t *request, const char *path) {
    for (size_t i = 0u; i < request->path_count; ++i)
        if (request->paths[i] && !strcmp(request->paths[i], path)) return 1;
    return 0;
}

static mg_slice_predicate_t vref_limit_predicate(const char *limit, int group) {
    if (!strcmp(limit, "count")) return group ? MG_SLICE_GROUP_VREF_COUNT : MG_SLICE_VREF_COUNT;
    if (!strcmp(limit, "new_count")) return group ? MG_SLICE_GROUP_VREF_NEW_COUNT : MG_SLICE_VREF_NEW_COUNT;
    return group ? MG_SLICE_GROUP_VREF_MAX_NEW_BINARY : MG_SLICE_VREF_MAX_NEW_BINARY;
}

/* The grants of one subject (U, or one of its groups) on the repository
 * and on the owned namespace. Every string of a fact belongs to the
 * snapshot or to the request, never to this frame. */
static int subject_facts(const mg_grants_view_t *view, const mg_slice_request_t *request, int group,
                         const char *subject, const char *owned, mg_slice_t *out) {
    const char *kind = group ? "group" : "user";
    size_t first, last;
    equal_range(view, view->access_count, access_key, kind, subject, request->repository, &first, &last);
    for (size_t i = first; i < last; ++i)
        if (!mg_slice_add(out, group ? MG_SLICE_GROUP_ACCESS : MG_SLICE_ACCESS, subject, request->repository,
                          view->access[i].level, 0))
            return 0;
    equal_range(view, view->ref_count, ref_key, kind, subject, request->repository, &first, &last);
    for (size_t i = first; i < last; ++i) {
        const mg_grant_ref_t *ref = &view->refs[i];
        if (request->ref && mg_slice_pattern_matches(ref->prefix, ref->pattern, request->ref) &&
            !mg_slice_add(out, group ? MG_SLICE_GROUP_REF_MATCH : MG_SLICE_REF_MATCH, subject,
                          request->repository, ref->level, 0))
            return 0;
        if (is_write_level(ref->level) &&
            !mg_slice_add(out, group ? MG_SLICE_GROUP_REF_LEVEL : MG_SLICE_REF_LEVEL, subject,
                          request->repository, ref->level, 0))
            return 0;
    }
    if (owned) {
        equal_range(view, view->creator_count, creator_key, kind, subject, owned, &first, &last);
        for (size_t i = first; i < last; ++i)
            if (!mg_slice_add(out, group ? MG_SLICE_GROUP_NAMESPACE_CREATOR : MG_SLICE_NAMESPACE_CREATOR,
                              subject, view->creators[i].namespace_name, NULL, 0))
                return 0;
    }
    equal_range(view, view->vref_name_count, vref_name_key, kind, subject, request->repository, &first, &last);
    for (size_t i = first; i < last; ++i)
        if (has_path(request, view->vref_names[i].path) &&
            !mg_slice_add(out, group ? MG_SLICE_GROUP_VREF_NAME : MG_SLICE_VREF_NAME, subject,
                          request->repository, view->vref_names[i].path, 0))
            return 0;
    equal_range(view, view->vref_limit_count, vref_limit_key, kind, subject, request->repository, &first, &last);
    for (size_t i = first; i < last; ++i)
        if (!mg_slice_add(out, vref_limit_predicate(view->vref_limits[i].limit, group), subject,
                          request->repository, NULL, view->vref_limits[i].value))
            return 0;
    return 1;
}

maelys_git_result_t mg_slice_extract(const mg_grants_t *grants, const mg_slice_request_t *request,
                                     mg_slice_t *out, maelys_git_error_t *error) {
    if (!grants || !request || !request->user || !request->repository || !out) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0, "a snapshot, a user and a repository are required");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    mg_grants_view_t view;
    mg_grants_view(grants, &view);
    names_t groups = {0};
    /* The groups of U: all, which holds every user, the direct ones, then
     * each nesting edge from a group already reached, breadth first. */
    int ok = mg_slice_add(out, MG_SLICE_MEMBER, request->user, MG_GRANTS_ALL_GROUP, NULL, 0) &&
             names_insert(&groups, MG_GRANTS_ALL_GROUP);
    for (size_t i = first_member(&view, request->user);
         ok && i < view.member_count && !strcmp(view.members[i].user, request->user); ++i) {
        ok = mg_slice_add(out, MG_SLICE_MEMBER, request->user, view.members[i].group, NULL, 0);
        if (ok) ok = names_insert(&groups, view.members[i].group);
    }
    for (size_t g = 0u; ok && g < groups.count; ++g) {
        const char *group = groups.names[g];
        for (size_t i = first_nested(&view, group);
             ok && i < view.nested_count && !strcmp(view.nested[i].group, group); ++i) {
            ok = mg_slice_add(out, MG_SLICE_NESTED, group, view.nested[i].parent, NULL, 0);
            if (ok) ok = names_insert(&groups, view.nested[i].parent);
        }
    }
    char owned_buffer[512];
    const char *owned = mg_slice_owner_namespace(request->repository, request->user, owned_buffer,
                                                 sizeof(owned_buffer));
    if (ok) ok = subject_facts(&view, request, 0, request->user, owned, out);
    for (size_t g = 0u; ok && g < groups.count; ++g)
        ok = subject_facts(&view, request, 1, groups.names[g], owned, out);
    if (ok && owned) {
        /* owner_access is sorted by namespace. */
        for (size_t i = 0u; ok && i < view.owner_count; ++i)
            if (!strcmp(view.owners[i].namespace_name, owned))
                ok = mg_slice_add(out, MG_SLICE_OWNER_ACCESS, view.owners[i].namespace_name, view.owners[i].level,
                                  NULL, 0);
    }
    free(groups.names);
    free(groups.slots);
    if (!ok) {
        mg_slice_clear(out);
        mg_error_set(error, MAELYS_GIT_ERR_IO, 0, "out of memory while extracting a slice");
        return MAELYS_GIT_ERR_IO;
    }
    mg_slice_normalize(out);
    return MAELYS_GIT_OK;
}
