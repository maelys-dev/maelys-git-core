#ifndef MAELYS_GIT_TEST_SLICE_REFERENCE_H
#define MAELYS_GIT_TEST_SLICE_REFERENCE_H

/* The reference extractor: every fact of a snapshot that the definitions of
 * maelys-git-slice/1 admit for a request, by a full scan of the snapshot,
 * without its index. The tests compare mg_slice_extract with it; a bench
 * measures both. */

#include "policy/slice.h"
#include "test_support.h"

typedef struct {
    const char *names[MG_GRANTS_MAX_GROUPS];
    size_t count;
} group_set_t;

static int in_set(const group_set_t *set, const char *name) {
    for (size_t i = 0u; i < set->count; ++i)
        if (!strcmp(set->names[i], name)) return 1;
    return 0;
}

/* Is S, of kind K, U itself or one of its groups? */
static int is_subject(const mg_slice_request_t *request, const group_set_t *groups, mg_subject_kind_t kind,
                      const char *subject) {
    return kind == MG_SUBJECT_USER ? !strcmp(subject, request->user) : in_set(groups, subject);
}

static int requested_path(const mg_slice_request_t *request, const char *path) {
    for (size_t i = 0u; i < request->path_count; ++i)
        if (!strcmp(request->paths[i], path)) return 1;
    return 0;
}

/* The namespace U owns in the repository, by splitting it literally. */
static const char *reference_owned(const char *repository, const char *user, char *out, size_t size) {
    char copy[512];
    (void)snprintf(copy, sizeof(copy), "%s", repository);
    char *segments[64];
    size_t count = 0u;
    char *save = NULL;
    for (char *segment = strtok_r(copy, "/", &save); segment && count < 64u; segment = strtok_r(NULL, "/", &save))
        segments[count++] = segment;
    if (count < 3u || strcmp(segments[1], user)) return NULL;
    (void)snprintf(out, size, "%s", segments[0]);
    return out;
}

/* Every fact of the snapshot that the definitions admit, by a full scan. */
static int reference_slice(const mg_grants_t *grants, const mg_slice_request_t *request, mg_slice_t *out) {
    mg_grants_view_t view;
    mg_grants_view(grants, &view);
    memset(out, 0, sizeof(*out));
    group_set_t groups = {0};
    for (size_t i = 0u; i < view.member_count; ++i)
        if (!strcmp(view.members[i].user, request->user) && !in_set(&groups, view.members[i].group)) {
            CHECK(groups.count < MG_GRANTS_MAX_GROUPS);
            groups.names[groups.count++] = view.members[i].group;
        }
    for (int changed = 1; changed;) {
        changed = 0;
        for (size_t i = 0u; i < view.nested_count; ++i)
            if (in_set(&groups, view.nested[i].group) && !in_set(&groups, view.nested[i].parent)) {
                CHECK(groups.count < MG_GRANTS_MAX_GROUPS);
                groups.names[groups.count++] = view.nested[i].parent;
                changed = 1;
            }
    }
    for (size_t i = 0u; i < view.member_count; ++i)
        if (!strcmp(view.members[i].user, request->user))
            CHECK(mg_slice_add(out, MG_SLICE_MEMBER, request->user, view.members[i].group, NULL, 0));
    for (size_t i = 0u; i < view.nested_count; ++i)
        if (in_set(&groups, view.nested[i].group))
            CHECK(mg_slice_add(out, MG_SLICE_NESTED, view.nested[i].group, view.nested[i].parent, NULL, 0));
    for (size_t i = 0u; i < view.access_count; ++i) {
        const mg_grant_access_t *a = &view.access[i];
        if (is_subject(request, &groups, a->kind, a->subject) && !strcmp(a->repository, request->repository))
            CHECK(mg_slice_add(out, a->kind == MG_SUBJECT_GROUP ? MG_SLICE_GROUP_ACCESS : MG_SLICE_ACCESS,
                               a->subject, a->repository, a->level, 0));
    }
    for (size_t i = 0u; i < view.ref_count; ++i) {
        const mg_grant_ref_t *r = &view.refs[i];
        if (!is_subject(request, &groups, r->kind, r->subject) || strcmp(r->repository, request->repository))
            continue;
        int group = r->kind == MG_SUBJECT_GROUP;
        int matches = request->ref &&
            (r->prefix ? strncmp(request->ref, r->pattern, strlen(r->pattern)) == 0 : !strcmp(request->ref, r->pattern));
        if (matches)
            CHECK(mg_slice_add(out, group ? MG_SLICE_GROUP_REF_MATCH : MG_SLICE_REF_MATCH, r->subject,
                               r->repository, r->level, 0));
        if (!strcmp(r->level, "RW") || !strcmp(r->level, "RW+"))
            CHECK(mg_slice_add(out, group ? MG_SLICE_GROUP_REF_LEVEL : MG_SLICE_REF_LEVEL, r->subject,
                               r->repository, r->level, 0));
    }
    char owned_buffer[512];
    const char *owned = reference_owned(request->repository, request->user, owned_buffer, sizeof(owned_buffer));
    for (size_t i = 0u; owned && i < view.creator_count; ++i) {
        const mg_grant_creator_t *c = &view.creators[i];
        if (is_subject(request, &groups, c->kind, c->subject) && !strcmp(c->namespace_name, owned))
            CHECK(mg_slice_add(out, c->kind == MG_SUBJECT_GROUP ? MG_SLICE_GROUP_NAMESPACE_CREATOR
                                                                 : MG_SLICE_NAMESPACE_CREATOR,
                               c->subject, c->namespace_name, NULL, 0));
    }
    for (size_t i = 0u; owned && i < view.owner_count; ++i)
        if (!strcmp(view.owners[i].namespace_name, owned))
            CHECK(mg_slice_add(out, MG_SLICE_OWNER_ACCESS, view.owners[i].namespace_name, view.owners[i].level,
                               NULL, 0));
    for (size_t i = 0u; i < view.vref_name_count; ++i) {
        const mg_grant_vref_name_t *v = &view.vref_names[i];
        if (is_subject(request, &groups, v->kind, v->subject) && !strcmp(v->repository, request->repository) &&
            requested_path(request, v->path))
            CHECK(mg_slice_add(out, v->kind == MG_SUBJECT_GROUP ? MG_SLICE_GROUP_VREF_NAME : MG_SLICE_VREF_NAME,
                               v->subject, v->repository, v->path, 0));
    }
    for (size_t i = 0u; i < view.vref_limit_count; ++i) {
        const mg_grant_vref_limit_t *v = &view.vref_limits[i];
        if (!is_subject(request, &groups, v->kind, v->subject) || strcmp(v->repository, request->repository))
            continue;
        int group = v->kind == MG_SUBJECT_GROUP;
        mg_slice_predicate_t predicate =
            !strcmp(v->limit, "count") ? (group ? MG_SLICE_GROUP_VREF_COUNT : MG_SLICE_VREF_COUNT)
            : !strcmp(v->limit, "new_count") ? (group ? MG_SLICE_GROUP_VREF_NEW_COUNT : MG_SLICE_VREF_NEW_COUNT)
                                             : (group ? MG_SLICE_GROUP_VREF_MAX_NEW_BINARY
                                                      : MG_SLICE_VREF_MAX_NEW_BINARY);
        CHECK(mg_slice_add(out, predicate, v->subject, v->repository, NULL, v->value));
    }
    mg_slice_normalize(out);
    return 1;
}

#endif
