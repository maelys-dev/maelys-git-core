#include "internal.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *maelys_git_ref_kind_name(maelys_git_ref_kind_t kind) {
    switch (kind) {
        case MAELYS_GIT_REF_BRANCH: return "branch";
        case MAELYS_GIT_REF_TAG: return "tag";
        case MAELYS_GIT_REF_OTHER: return "other";
        default: return "unknown";
    }
}

const char *maelys_git_update_kind_name(maelys_git_update_kind_t kind) {
    switch (kind) {
        case MAELYS_GIT_UPDATE_CREATE: return "create";
        case MAELYS_GIT_UPDATE_FAST_FORWARD: return "fast_forward";
        case MAELYS_GIT_UPDATE_FORCE: return "force";
        case MAELYS_GIT_UPDATE_DELETE: return "delete";
        default: return "unknown";
    }
}

const char *maelys_git_change_kind_name(maelys_git_change_kind_t kind) {
    switch (kind) {
        case MAELYS_GIT_CHANGE_ADD: return "added";
        case MAELYS_GIT_CHANGE_MODIFY: return "modified";
        case MAELYS_GIT_CHANGE_DELETE: return "deleted";
        case MAELYS_GIT_CHANGE_RENAME: return "renamed";
        case MAELYS_GIT_CHANGE_TYPE: return "type_changed";
        default: return "unknown";
    }
}

maelys_git_ref_kind_t maelys_git_classify_ref(const char *ref_name) {
    if (ref_name && strncmp(ref_name, "refs/heads/", 11u) == 0) return MAELYS_GIT_REF_BRANCH;
    if (ref_name && strncmp(ref_name, "refs/tags/", 10u) == 0) return MAELYS_GIT_REF_TAG;
    return MAELYS_GIT_REF_OTHER;
}

maelys_git_result_t maelys_git_repository_classify_update(
    const char *git_executable,
    const char *repository_path,
    const char *old_oid,
    const char *new_oid,
    maelys_git_update_kind_t *out_kind,
    maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!git_executable || !repository_path || !mg_is_oid(old_oid) ||
        !mg_is_oid(new_oid) || !out_kind) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    if (mg_is_zero_oid(old_oid)) {
        *out_kind = MAELYS_GIT_UPDATE_CREATE;
        return MAELYS_GIT_OK;
    }
    if (mg_is_zero_oid(new_oid)) {
        *out_kind = MAELYS_GIT_UPDATE_DELETE;
        return MAELYS_GIT_OK;
    }
    char *argv[] = {(char *)git_executable, "--git-dir", (char *)repository_path,
                    "merge-base", "--is-ancestor", (char *)old_oid,
                    (char *)new_oid, NULL};
    int status = 0;
    maelys_git_result_t result = mg_process_run_status(git_executable, argv, &status, error);
    if (result != MAELYS_GIT_OK) return result;
    if (status == 0) *out_kind = MAELYS_GIT_UPDATE_FAST_FORWARD;
    else if (status == 1) *out_kind = MAELYS_GIT_UPDATE_FORCE;
    else {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "git merge-base failed with status %d", status);
        return MAELYS_GIT_ERR_PROCESS;
    }
    return MAELYS_GIT_OK;
}

void maelys_git_inspection_limits_default(maelys_git_inspection_limits_t *limits) {
    if (!limits) return;
    *limits = (maelys_git_inspection_limits_t){
        .max_commits = 10000u,
        .max_changes = 100000u,
        .max_total_new_blob_size = 10ULL * 1024ULL * 1024ULL * 1024ULL,
        .max_inspected_blob_bytes = 512u * 1024u * 1024u,
    };
}

static int limits_valid(const maelys_git_inspection_limits_t *limits) {
    return limits && limits->max_commits > 0u && limits->max_changes > 0u &&
           limits->max_total_new_blob_size > 0u &&
           limits->max_inspected_blob_bytes > 0u;
}

static maelys_git_result_t emit_change(maelys_git_change_t *change,
                                       const maelys_git_inspection_limits_t *limits,
                                       maelys_git_change_visitor_t visitor,
                                       void *context,
                                       maelys_git_change_summary_t *summary,
                                       maelys_git_error_t *error) {
    if (summary->changed_count >= limits->max_changes) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                     "change count exceeds configured limit %zu", limits->max_changes);
        return MAELYS_GIT_ERR_LIMIT;
    }
    if (change->new_blob_size > ULLONG_MAX - summary->total_new_blob_size ||
        summary->total_new_blob_size + change->new_blob_size >
            limits->max_total_new_blob_size) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                     "new blob bytes exceed configured limit %llu",
                     limits->max_total_new_blob_size);
        return MAELYS_GIT_ERR_LIMIT;
    }
    summary->changed_count++;
    summary->total_new_blob_size += change->new_blob_size;
    if (change->new_blob_size > summary->max_new_blob_size)
        summary->max_new_blob_size = change->new_blob_size;
    if (change->binary) summary->has_binary = 1;
    switch (change->kind) {
        case MAELYS_GIT_CHANGE_ADD: summary->added_count++; break;
        case MAELYS_GIT_CHANGE_DELETE: summary->deleted_count++; break;
        case MAELYS_GIT_CHANGE_RENAME: summary->renamed_count++; break;
        default: summary->modified_count++; break;
    }
    return visitor ? visitor(change, context, error) : MAELYS_GIT_OK;
}

static int parse_mode(const char *text, unsigned int *out) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 8);
    if (errno != 0 || !end || *end != '\0' || value > 0777777u) return 0;
    *out = (unsigned int)value;
    return 1;
}

static int read_tree_change(FILE *stream,
                            int deleting,
                            maelys_git_change_t *change,
                            maelys_git_error_t *error) {
    char *record = NULL;
    size_t capacity = 0u;
    ssize_t length = getdelim(&record, &capacity, '\0', stream);
    if (length <= 0) {
        free(record);
        if (ferror(stream)) {
            mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot read git tree stream");
            return -1;
        }
        return 0;
    }
    if (record[length - 1] == '\0') record[length - 1] = '\0';
    char *tab = strchr(record, '\t');
    char mode_text[16], type[16], object[65], extra;
    if (!tab) {
        free(record);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid git ls-tree record");
        return -1;
    }
    *tab = '\0';
    const char *path = tab + 1u;
    int parsed = sscanf(record, "%15s %15s %64s %c",
                        mode_text, type, object, &extra);
    if (parsed != 3 || !*path ||
        (strcmp(type, "blob") != 0 && strcmp(type, "commit") != 0)) {
        free(record);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid git ls-tree record");
        return -1;
    }
    memset(change, 0, sizeof(*change));
    change->kind = deleting ? MAELYS_GIT_CHANGE_DELETE : MAELYS_GIT_CHANGE_ADD;
    if (!parse_mode(mode_text, deleting ? &change->old_mode : &change->new_mode) ||
        !mg_copy_string(change->path, sizeof(change->path), path) ||
        !mg_copy_string(deleting ? change->old_oid : change->new_oid, 65u, object)) {
        free(record);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid git tree values");
        return -1;
    }
    memset(deleting ? change->new_oid : change->old_oid, '0', strlen(object));
    (deleting ? change->new_oid : change->old_oid)[strlen(object)] = '\0';
    change->submodule = (deleting ? change->old_mode : change->new_mode) == 0160000u;
    change->symlink = (deleting ? change->old_mode : change->new_mode) == 0120000u;
    free(record);
    return 1;
}

static int read_diff_change(FILE *stream,
                            maelys_git_change_t *change,
                            maelys_git_error_t *error) {
    char *header = NULL, *path = NULL;
    size_t header_capacity = 0u, path_capacity = 0u;
    ssize_t header_length = getdelim(&header, &header_capacity, '\0', stream);
    if (header_length <= 0) {
        free(header);
        if (ferror(stream)) {
            mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot read git diff stream");
            return -1;
        }
        return 0;
    }
    if (header[header_length - 1] == '\0') header[header_length - 1] = '\0';
    ssize_t path_length = getdelim(&path, &path_capacity, '\0', stream);
    if (path_length <= 0) goto invalid;
    if (path[path_length - 1] == '\0') path[path_length - 1] = '\0';
    char old_mode[16], new_mode[16], old_object[65], new_object[65], status_text[8], extra;
    if (sscanf(header, ":%15s %15s %64s %64s %7s%c",
               old_mode, new_mode, old_object, new_object, status_text, &extra) != 5)
        goto invalid;
    memset(change, 0, sizeof(*change));
    change->kind = status_text[0] == 'A' ? MAELYS_GIT_CHANGE_ADD :
                   status_text[0] == 'D' ? MAELYS_GIT_CHANGE_DELETE :
                   status_text[0] == 'R' ? MAELYS_GIT_CHANGE_RENAME :
                   status_text[0] == 'T' ? MAELYS_GIT_CHANGE_TYPE : MAELYS_GIT_CHANGE_MODIFY;
    if (!parse_mode(old_mode, &change->old_mode) ||
        !parse_mode(new_mode, &change->new_mode) ||
        !mg_copy_string(change->old_oid, sizeof(change->old_oid), old_object) ||
        !mg_copy_string(change->new_oid, sizeof(change->new_oid), new_object) ||
        !mg_copy_string(change->path, sizeof(change->path), path))
        goto invalid;
    if (change->kind == MAELYS_GIT_CHANGE_RENAME) {
        if (!mg_copy_string(change->old_path, sizeof(change->old_path), path)) goto invalid;
        path_length = getdelim(&path, &path_capacity, '\0', stream);
        if (path_length <= 0) goto invalid;
        if (path[path_length - 1] == '\0') path[path_length - 1] = '\0';
        if (!mg_copy_string(change->path, sizeof(change->path), path)) goto invalid;
    }
    change->submodule = change->new_mode == 0160000u ||
                        (mg_is_zero_oid(change->new_oid) && change->old_mode == 0160000u);
    change->symlink = change->new_mode == 0120000u ||
                      (mg_is_zero_oid(change->new_oid) && change->old_mode == 0120000u);
    free(header); free(path);
    return 1;
invalid:
    free(header); free(path);
    mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid git diff-tree stream");
    return -1;
}

static const char *inspection_oid(const maelys_git_change_t *change) {
    if (change->submodule) return NULL;
    return mg_is_zero_oid(change->new_oid) ? change->old_oid : change->new_oid;
}

static int is_lfs_pointer(const unsigned char *data, size_t length) {
    static const char marker[] = "version https://git-lfs.github.com/spec/v1\n";
    return length >= sizeof(marker) - 1u &&
           memcmp(data, marker, sizeof(marker) - 1u) == 0;
}

static maelys_git_result_t inspect_batch_record(
    FILE *batch,
    const char *expected_oid,
    int is_new,
    maelys_git_change_t *change,
    unsigned long long *inspected_bytes,
    const maelys_git_inspection_limits_t *limits,
    maelys_git_error_t *error) {
    if (!expected_oid) return MAELYS_GIT_OK;
    char header[256], oid[65], type[32], extra;
    unsigned long long size = 0u;
    if (!fgets(header, sizeof(header), batch) ||
        sscanf(header, "%64s %31s %llu %c", oid, type, &size, &extra) != 3 ||
        strcmp(oid, expected_oid) != 0 || strcmp(type, "blob") != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid git cat-file batch header");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    if (size > ULLONG_MAX - *inspected_bytes ||
        *inspected_bytes + size > limits->max_inspected_blob_bytes) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                     "inspected blob bytes exceed configured limit %zu",
                     limits->max_inspected_blob_bytes);
        return MAELYS_GIT_ERR_LIMIT;
    }
    *inspected_bytes += size;
    unsigned char prefix[8000];
    size_t prefix_length = size < sizeof(prefix) ? (size_t)size : sizeof(prefix);
    if (prefix_length && fread(prefix, 1u, prefix_length, batch) != prefix_length) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "truncated git cat-file content");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    unsigned long long remaining = size - prefix_length;
    unsigned char discard[16384];
    while (remaining) {
        size_t chunk = remaining < sizeof(discard) ? (size_t)remaining : sizeof(discard);
        if (fread(discard, 1u, chunk, batch) != chunk) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "truncated git cat-file content");
            return MAELYS_GIT_ERR_PROTOCOL;
        }
        remaining -= chunk;
    }
    if (fgetc(batch) != '\n') {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid git cat-file separator");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    change->binary = memchr(prefix, '\0', prefix_length) != NULL;
    change->lfs_pointer = !change->binary && size <= 1024u &&
                          is_lfs_pointer(prefix, prefix_length);
    if (is_new) change->new_blob_size = size;
    return MAELYS_GIT_OK;
}

static maelys_git_result_t run_blob_batch(const char *git,
                                          const char *repository,
                                          FILE *requests,
                                          FILE *batch,
                                          size_t request_count,
                                          const maelys_git_inspection_limits_t *limits,
                                          maelys_git_error_t *error) {
    if (request_count == 0u) return MAELYS_GIT_OK;
    if (request_count > (SIZE_MAX - 1u) / 128u) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "cat-file batch quota overflows host size");
        return MAELYS_GIT_ERR_LIMIT;
    }
    size_t overhead = request_count * 128u + 1u;
    if (limits->max_inspected_blob_bytes > SIZE_MAX - overhead) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "cat-file batch quota overflows host size");
        return MAELYS_GIT_ERR_LIMIT;
    }
    size_t output_limit = limits->max_inspected_blob_bytes + overhead;
    char *argv[] = {(char *)git, "--git-dir", (char *)repository,
                    "cat-file", "--batch", NULL};
    int status = 0;
    maelys_git_result_t result = mg_process_filter_spool_status(
        git, argv, requests, batch, output_limit, &status, error);
    if (result == MAELYS_GIT_OK && status != 0) {
        mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0,
                     "git cat-file --batch failed with status %d", status);
        return MAELYS_GIT_ERR_PROCESS;
    }
    if (result == MAELYS_GIT_OK) rewind(batch);
    return result;
}

static maelys_git_result_t visit_tree(const char *git,
                                      const char *repository,
                                      const char *oid,
                                      int deleting,
                                      const maelys_git_inspection_limits_t *limits,
                                      maelys_git_change_visitor_t visitor,
                                      void *context,
                                      maelys_git_change_summary_t *summary,
                                      maelys_git_error_t *error) {
    FILE *stream = tmpfile();
    if (!stream) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "tmpfile failed: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    char *argv[] = {(char *)git, "--git-dir", (char *)repository,
                    "ls-tree", "-r", "-z", "--full-tree", (char *)oid, NULL};
    int status = 0;
    maelys_git_result_t result = mg_process_spool_status(
        git, argv, stream, 256u * 1024u * 1024u, &status, error);
    if (result != MAELYS_GIT_OK || status != 0) {
        if (result == MAELYS_GIT_OK)
            mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0, "git ls-tree failed with status %d", status);
        fclose(stream);
        return result == MAELYS_GIT_OK ? MAELYS_GIT_ERR_PROCESS : result;
    }
    FILE *requests = tmpfile(), *batch = tmpfile();
    if (!requests || !batch) {
        if (requests) fclose(requests);
        if (batch) fclose(batch);
        fclose(stream);
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "tmpfile failed: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    rewind(stream);
    size_t change_count = 0u, request_count = 0u;
    maelys_git_change_t change;
    int read_result;
    while ((read_result = read_tree_change(stream, deleting, &change, error)) > 0) {
        if (++change_count > limits->max_changes) {
            mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                         "change count exceeds configured limit %zu", limits->max_changes);
            result = MAELYS_GIT_ERR_LIMIT;
            break;
        }
        const char *inspect = inspection_oid(&change);
        if (inspect && fprintf(requests, "%s\n", inspect) < 0) {
            result = MAELYS_GIT_ERR_IO;
            break;
        }
        if (inspect) ++request_count;
    }
    if (read_result < 0 && result == MAELYS_GIT_OK) result = error->code;
    if (result == MAELYS_GIT_OK)
        result = run_blob_batch(git, repository, requests, batch,
                                request_count, limits, error);
    if (result == MAELYS_GIT_OK) {
        rewind(stream);
        unsigned long long inspected_bytes = 0u;
        while ((read_result = read_tree_change(stream, deleting, &change, error)) > 0) {
            const char *inspect = inspection_oid(&change);
            result = inspect_batch_record(batch, inspect,
                                          !mg_is_zero_oid(change.new_oid),
                                          &change, &inspected_bytes, limits, error);
            if (result == MAELYS_GIT_OK)
                result = emit_change(&change, limits, visitor, context, summary, error);
            if (result != MAELYS_GIT_OK) break;
        }
        if (result == MAELYS_GIT_OK) summary->inspected_blob_bytes = (size_t)inspected_bytes;
        if (read_result < 0 && result == MAELYS_GIT_OK) result = error->code;
        if (result == MAELYS_GIT_OK && request_count && fgetc(batch) != EOF) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                         "git cat-file returned unexpected trailing data");
            result = MAELYS_GIT_ERR_PROTOCOL;
        }
    }
    fclose(requests); fclose(batch); fclose(stream);
    return result;
}

static maelys_git_result_t visit_diff(const char *git,
                                      const char *repository,
                                      const char *old_oid,
                                      const char *new_oid,
                                      const maelys_git_inspection_limits_t *limits,
                                      maelys_git_change_visitor_t visitor,
                                      void *context,
                                      maelys_git_change_summary_t *summary,
                                      maelys_git_error_t *error) {
    FILE *stream = tmpfile();
    if (!stream) return MAELYS_GIT_ERR_IO;
    char *argv[] = {(char *)git, "--git-dir", (char *)repository,
                    "diff-tree", "--raw", "-r", "-z", "-M",
                    (char *)old_oid, (char *)new_oid, "--", NULL};
    int status = 0;
    maelys_git_result_t result = mg_process_spool_status(
        git, argv, stream, 256u * 1024u * 1024u, &status, error);
    if (result != MAELYS_GIT_OK || status != 0) {
        if (result == MAELYS_GIT_OK)
            mg_error_set(error, MAELYS_GIT_ERR_PROCESS, 0, "git diff-tree failed with status %d", status);
        fclose(stream);
        return result == MAELYS_GIT_OK ? MAELYS_GIT_ERR_PROCESS : result;
    }
    FILE *requests = tmpfile(), *batch = tmpfile();
    if (!requests || !batch) {
        if (requests) fclose(requests);
        if (batch) fclose(batch);
        fclose(stream);
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "tmpfile failed: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    rewind(stream);
    size_t change_count = 0u, request_count = 0u;
    maelys_git_change_t change;
    int read_result;
    while ((read_result = read_diff_change(stream, &change, error)) > 0) {
        if (++change_count > limits->max_changes) {
            mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0,
                         "change count exceeds configured limit %zu", limits->max_changes);
            result = MAELYS_GIT_ERR_LIMIT;
            break;
        }
        const char *inspect = inspection_oid(&change);
        if (inspect && fprintf(requests, "%s\n", inspect) < 0) {
            result = MAELYS_GIT_ERR_IO;
            break;
        }
        if (inspect) ++request_count;
    }
    if (read_result < 0 && result == MAELYS_GIT_OK) result = error->code;
    if (result == MAELYS_GIT_OK)
        result = run_blob_batch(git, repository, requests, batch,
                                request_count, limits, error);
    if (result == MAELYS_GIT_OK) {
        rewind(stream);
        unsigned long long inspected_bytes = 0u;
        while ((read_result = read_diff_change(stream, &change, error)) > 0) {
            const char *inspect = inspection_oid(&change);
            result = inspect_batch_record(batch, inspect,
                                          !mg_is_zero_oid(change.new_oid),
                                          &change, &inspected_bytes, limits, error);
            if (result == MAELYS_GIT_OK)
                result = emit_change(&change, limits, visitor, context, summary, error);
            if (result != MAELYS_GIT_OK) break;
        }
        if (result == MAELYS_GIT_OK) summary->inspected_blob_bytes = (size_t)inspected_bytes;
        if (read_result < 0 && result == MAELYS_GIT_OK) result = error->code;
        if (result == MAELYS_GIT_OK && request_count && fgetc(batch) != EOF) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0,
                         "git cat-file returned unexpected trailing data");
            result = MAELYS_GIT_ERR_PROTOCOL;
        }
    }
    fclose(requests); fclose(batch); fclose(stream);
    return result;
}

maelys_git_result_t maelys_git_repository_visit_changes(
    const char *git_executable,
    const char *repository_path,
    const char *old_oid,
    const char *new_oid,
    maelys_git_change_visitor_t visitor,
    void *visitor_context,
    maelys_git_change_summary_t *out_summary,
    maelys_git_error_t *error) {
    maelys_git_inspection_limits_t limits;
    maelys_git_inspection_limits_default(&limits);
    return maelys_git_repository_visit_changes_ex(
        git_executable, repository_path, old_oid, new_oid, &limits,
        visitor, visitor_context, out_summary, error);
}

maelys_git_result_t maelys_git_repository_visit_changes_ex(
    const char *git_executable,
    const char *repository_path,
    const char *old_oid,
    const char *new_oid,
    const maelys_git_inspection_limits_t *limits,
    maelys_git_change_visitor_t visitor,
    void *visitor_context,
    maelys_git_change_summary_t *out_summary,
    maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!git_executable || !repository_path || !mg_is_oid(old_oid) ||
        !mg_is_oid(new_oid) || !limits_valid(limits) || !out_summary)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_summary, 0, sizeof(*out_summary));
    if (mg_is_zero_oid(old_oid) && mg_is_zero_oid(new_oid)) return MAELYS_GIT_OK;
    if (mg_is_zero_oid(old_oid))
        return visit_tree(git_executable, repository_path, new_oid, 0, limits, visitor,
                          visitor_context, out_summary, error);
    if (mg_is_zero_oid(new_oid))
        return visit_tree(git_executable, repository_path, old_oid, 1, limits, visitor,
                          visitor_context, out_summary, error);
    return visit_diff(git_executable, repository_path, old_oid, new_oid, limits, visitor,
                      visitor_context, out_summary, error);
}

void maelys_git_receive_transaction_clear(maelys_git_receive_transaction_t *transaction) {
    if (!transaction) return;
    free(transaction->updates);
    memset(transaction, 0, sizeof(*transaction));
}

maelys_git_result_t maelys_git_receive_transaction_read(
    FILE *input,
    maelys_git_receive_transaction_t *out_transaction,
    maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!input || !out_transaction) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    memset(out_transaction, 0, sizeof(*out_transaction));
    char line[MAELYS_GIT_MAX_REF + 160u];
    size_t capacity = 0u;
    while (fgets(line, sizeof(line), input)) {
        size_t length = strlen(line);
        if (length == 0u || line[length - 1u] != '\n') {
            maelys_git_receive_transaction_clear(out_transaction);
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "pre-receive input line is incomplete");
            return MAELYS_GIT_ERR_PROTOCOL;
        }
        if (out_transaction->update_count >= MAELYS_GIT_MAX_RECEIVE_UPDATES) {
            maelys_git_receive_transaction_clear(out_transaction);
            mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "receive transaction has too many ref updates");
            return MAELYS_GIT_ERR_LIMIT;
        }
        if (out_transaction->update_count == capacity) {
            size_t next = capacity ? capacity * 2u : 8u;
            maelys_git_receive_update_t *updates = realloc(
                out_transaction->updates, next * sizeof(*updates));
            if (!updates) { maelys_git_receive_transaction_clear(out_transaction); return MAELYS_GIT_ERR_IO; }
            out_transaction->updates = updates;
            capacity = next;
        }
        maelys_git_receive_update_t *update = &out_transaction->updates[out_transaction->update_count];
        memset(update, 0, sizeof(*update));
        line[length - 1u] = '\0';
        char extra;
        if (sscanf(line, "%64s %64s %511s %c", update->old_oid, update->new_oid,
                   update->ref_name, &extra) != 3 || !mg_is_oid(update->old_oid) ||
            !mg_is_oid(update->new_oid) || !maelys_git_ref_name_is_valid(update->ref_name)) {
            maelys_git_receive_transaction_clear(out_transaction);
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid pre-receive update");
            return MAELYS_GIT_ERR_PROTOCOL;
        }
        update->ref_kind = maelys_git_classify_ref(update->ref_name);
        out_transaction->update_count++;
    }
    if (ferror(input) || out_transaction->update_count == 0u) {
        maelys_git_receive_transaction_clear(out_transaction);
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "receive transaction is empty or unreadable");
        return MAELYS_GIT_ERR_PROTOCOL;
    }
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_run_inspectors(
    const maelys_git_inspector_t *inspectors,
    size_t inspector_count,
    const maelys_git_receive_update_t *update,
    const maelys_git_change_t *change,
    maelys_git_error_t *error) {
    if ((!inspectors && inspector_count) || !update) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    for (size_t i = 0u; i < inspector_count; ++i) {
        if (!inspectors[i].name || !inspectors[i].inspect) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
        maelys_git_result_t result = inspectors[i].inspect(update, change, inspectors[i].context, error);
        if (result != MAELYS_GIT_OK) return result;
    }
    return MAELYS_GIT_OK;
}
