/* The qualification laboratory of GIT-C10 (harness plan §2.3), compiled
 * into the -lab targets only. Three things live here: the fault points the
 * product reaches and what each does on its passage; the markers every
 * passage and every injection write, one JSON line each, appended to the
 * marker file beside the fault file; and the SQLite VFS maelys-lab, which
 * wraps the default VFS, names every file it opens, counts the operations
 * of each phase a point opens, and fails one exact operation with one
 * exact SQLite code when a point armed it. */
#include "lab.h"

#include "agent_internal.h"
#include "receipt/receipt_internal.h"

#include <maelys/cli/files.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#ifndef MG_LAB_FAULT_FILE
#error "MG_LAB_FAULT_FILE names the fault file the executor reads"
#endif

#define COUNT(array) (sizeof(array) / sizeof((array)[0]))
#define LAB_MAX_SPECS 16u
#define LAB_MAX_FAULT_BYTES 4096u
#define LAB_SPEC_MAX 127u
#define LAB_PAUSE_MS 300000
#define LAB_EXIT_MISCONFIGURED 70

/* ---- the points -------------------------------------------------------------- */

enum {
    ALLOW_LOG = 1u,
    ALLOW_KILL = 2u,
    ALLOW_PAUSE = 4u,
    ALLOW_SYNTHETIC = 8u,
    ALLOW_VFS = 16u,
    ALLOW_APPLY = 32u
};
#define AGENT_POINT (ALLOW_LOG | ALLOW_KILL | ALLOW_PAUSE)

typedef struct {
    const char *name;
    unsigned allowed;
} lab_point_t;

/* The points of B the plan names for step 2c; a point joins this table only
 * with its scenario. The deliverable check reads the names between the
 * two marks below. */
/* points:begin */
static const lab_point_t k_points[] = {
    {"store.pending_insert", AGENT_POINT},
    {"store.complete_commit", AGENT_POINT | ALLOW_SYNTHETIC | ALLOW_VFS},
    {"store.open_after_barrier", AGENT_POINT},
    {"supervisor.after_spawn", AGENT_POINT},
    {"supervisor.before_validate", AGENT_POINT},
    {"grants.sync", AGENT_POINT | ALLOW_SYNTHETIC},
    {"http.after_poll", AGENT_POINT},
    {"http.before_ack", AGENT_POINT},
    {"http.trace", ALLOW_LOG},
    {"vfs.trace", ALLOW_LOG},
    {"executor.record_launch", ALLOW_LOG},
    {"executor.alter_receipt", ALLOW_APPLY},
    {"executor.drop_receipt_keep_text", ALLOW_APPLY},
    {"executor.drop_receipt_and_text", ALLOW_APPLY},
    {"executor.receipt_without_grants", ALLOW_APPLY},
    {"executor.wrong_grants", ALLOW_APPLY},
    {"executor.invalid_envelope", ALLOW_APPLY},
    {"executor.hang", ALLOW_APPLY},
    {"executor.exit_after_effect", ALLOW_APPLY},
};
/* points:end */

enum {
    POINT_HTTP_TRACE = 8,
    POINT_VFS_TRACE = 9,
    POINT_ALTER_RECEIPT = 11,
    POINT_DROP_RECEIPT_KEEP_TEXT,
    POINT_DROP_RECEIPT_AND_TEXT,
    POINT_RECEIPT_WITHOUT_GRANTS,
    POINT_WRONG_GRANTS,
    POINT_INVALID_ENVELOPE,
    POINT_HANG,
    POINT_EXIT_AFTER_EFFECT
};

/* The codes a synthetic or VFS fault may name: those of the layer the
 * point belongs to. A decimal number is accepted as given. */
typedef struct {
    const char *name;
    int code;
} lab_code_t;

static const lab_code_t k_codes[] = {
    {"SQLITE_FULL", SQLITE_FULL},
    {"SQLITE_IOERR", SQLITE_IOERR},
    {"SQLITE_IOERR_FSYNC", SQLITE_IOERR_FSYNC},
    {"SQLITE_IOERR_WRITE", SQLITE_IOERR_WRITE},
    {"SQLITE_IOERR_TRUNCATE", SQLITE_IOERR_TRUNCATE},
    {"SQLITE_IOERR_FSTAT", SQLITE_IOERR_FSTAT},
    {"SQLITE_BUSY", SQLITE_BUSY},
    {"SQLITE_READONLY", SQLITE_READONLY},
    {"SQLITE_NOMEM", SQLITE_NOMEM},
    {"EIO", EIO},
    {"ENOSPC", ENOSPC},
    {"EACCES", EACCES},
    {"EPERM", EPERM},
    {"EMFILE", EMFILE},
    {"EROFS", EROFS},
    {"EDQUOT", EDQUOT},
};

/* The files the VFS names, by the flags of their opening, and the
 * operations a fault may target. */
static const char *const k_kinds[] = {"main", "wal", "journal", "temp", "other"};
static const char *const k_ops[] = {"xWrite", "xSync", "xTruncate", "xFileSize"};
enum { OP_WRITE = 0, OP_SYNC, OP_TRUNCATE, OP_FILESIZE };

typedef enum {
    LAB_ACT_APPLY = 0,
    LAB_ACT_LOG,
    LAB_ACT_KILL,
    LAB_ACT_PAUSE,
    LAB_ACT_SYNTHETIC,
    LAB_ACT_VFS
} lab_action_t;

static const char *const k_action_names[] = {"apply", "log", "kill", "pause", "synthetic", "vfs"};

typedef struct {
    size_t point;
    lab_action_t action;
    int code;
    const char *code_name;
    unsigned passage;       /* the passage of the point that triggers, 1-based */
    size_t vfs_kind, vfs_op;
    unsigned vfs_occurrence;
    int fired;
    char text[LAB_SPEC_MAX + 1u];
} lab_spec_t;

typedef enum { LAB_ROLE_NONE = 0, LAB_ROLE_AGENT, LAB_ROLE_EXECUTOR } lab_role_t;

static struct {
    int initialized;
    lab_role_t role;
    const char *role_name;
    lab_spec_t specs[LAB_MAX_SPECS];
    size_t spec_count;
    unsigned passages[COUNT(k_points)];
    size_t phase;           /* the last point reached, or SIZE_MAX */
    unsigned phase_seq;     /* the instance of the phase: one more at every point */
    char context[MG_MESSAGE_ID_MAX];
    int markers;            /* the marker file, or -1 */
    char dir[PATH_MAX];     /* the directory of the fault file */
    int trace_http, trace_vfs;
    struct {
        int armed;
        size_t kind, op, phase;
        unsigned seq;       /* the instance of the phase that armed */
        int code;
        const char *code_name;
        unsigned occurrence;
    } vfs;
    unsigned counts[COUNT(k_kinds)][COUNT(k_ops)]; /* operations of the phase */
} lab = {.markers = -1, .phase = SIZE_MAX};

/* ---- markers ------------------------------------------------------------------- */

static void marker_begin(mg_json_t *json, const char *event, size_t point) {
    mg_json_begin(json, MG_JSON_DATA);
    mg_json_object(json, NULL);
    mg_json_i64(json, "ts_ms", mg_now_ms());
    mg_json_i64(json, "pid", (int64_t)getpid());
    mg_json_string(json, "role", lab.role_name ? lab.role_name : "none");
    mg_json_string(json, "event", event);
    if (point < COUNT(k_points)) {
        mg_json_string(json, "point", k_points[point].name);
        mg_json_i64(json, "passage", (int64_t)lab.passages[point]);
    }
    if (lab.phase < COUNT(k_points)) mg_json_string(json, "phase", k_points[lab.phase].name);
    if (lab.context[0]) mg_json_string(json, "message_id", lab.context);
}

/* One line, appended by one write: lines of several processes never mix. */
static void marker_end(mg_json_t *json) {
    mg_json_end_object(json);
    char *line = NULL;
    size_t size = 0u;
    if (mg_json_finish(json, &line, &size) == MAELYS_JSON_OK && lab.markers >= 0) {
        struct iovec parts[2] = {{line, size}, {"\n", 1u}};
        ssize_t written;
        do { written = writev(lab.markers, parts, 2); } while (written < 0 && errno == EINTR);
    }
    free(line);
}

static void marker(const char *event, size_t point) {
    mg_json_t json;
    marker_begin(&json, event, point);
    marker_end(&json);
}

static void refuse(const char *what, const char *detail) {
    (void)fprintf(stderr, "maelys-git-lab: %s: %s\n", what, detail ? detail : "");
    (void)fflush(stderr);
    _exit(LAB_EXIT_MISCONFIGURED);
}

/* ---- the faults, as given ------------------------------------------------------ */

static size_t find_point(const char *name) {
    for (size_t i = 0u; i < COUNT(k_points); ++i)
        if (strcmp(k_points[i].name, name) == 0) return i;
    return SIZE_MAX;
}

static size_t find_name(const char *const *names, size_t count, const char *name) {
    for (size_t i = 0u; i < count; ++i)
        if (strcmp(names[i], name) == 0) return i;
    return SIZE_MAX;
}

static int parse_code(const char *text, int *out_code, const char **out_name) {
    for (size_t i = 0u; i < COUNT(k_codes); ++i)
        if (strcmp(k_codes[i].name, text) == 0) {
            *out_code = k_codes[i].code;
            *out_name = k_codes[i].name;
            return 1;
        }
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (!text[0] || !end || *end || value <= 0 || value > INT_MAX) return 0;
    *out_code = (int)value;
    *out_name = "number";
    return 1;
}

static int parse_unsigned(const char *text, unsigned *out) {
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (!text[0] || !end || *end || value == 0ul || value > UINT_MAX) return 0;
    *out = (unsigned)value;
    return 1;
}

/* <point>[:<action>[:<n>]], action = kill | pause | log | apply |
 * synthetic=<code> | vfs=<file>:<op>:<code>[:<occurrence>]; a point alone
 * is its own effect. */
static const char *parse_spec(const char *text, size_t length, lab_spec_t *out) {
    memset(out, 0, sizeof(*out));
    if (length > LAB_SPEC_MAX) return "longer than 127 bytes";
    memcpy(out->text, text, length);
    out->text[length] = '\0';
    char buffer[LAB_SPEC_MAX + 1u];
    memcpy(buffer, out->text, length + 1u);
    const char *fields[8] = {0};
    size_t count = 0u;
    for (char *cursor = buffer; cursor && count < COUNT(fields); ++count) {
        fields[count] = cursor;
        char *colon = strchr(cursor, ':');
        if (colon) *colon = '\0';
        cursor = colon ? colon + 1 : NULL;
    }
    if (count == 0u || !fields[0][0]) return "no point";
    out->point = find_point(fields[0]);
    if (out->point == SIZE_MAX) return "unknown point";
    out->passage = 1u;
    const char *action = count > 1u ? fields[1] : "apply";
    size_t passage_field = 2u;
    if (strncmp(action, "vfs=", 4u) == 0) {
        out->action = LAB_ACT_VFS;
        out->vfs_kind = find_name(k_kinds, COUNT(k_kinds), action + 4);
        if (out->vfs_kind == SIZE_MAX) return "unknown VFS file";
        if (count < 4u) return "vfs needs <file>:<op>:<code>";
        out->vfs_op = find_name(k_ops, COUNT(k_ops), fields[2]);
        if (out->vfs_op == SIZE_MAX) return "unknown VFS operation";
        if (!parse_code(fields[3], &out->code, &out->code_name)) return "unknown code";
        out->vfs_occurrence = 1u;
        if (count > 4u && !parse_unsigned(fields[4], &out->vfs_occurrence)) return "bad occurrence";
        passage_field = 5u;
    } else if (strncmp(action, "synthetic=", 10u) == 0) {
        out->action = LAB_ACT_SYNTHETIC;
        if (!parse_code(action + 10, &out->code, &out->code_name)) return "unknown code";
    } else {
        size_t index = find_name(k_action_names, COUNT(k_action_names), action);
        if (index == SIZE_MAX || index == LAB_ACT_SYNTHETIC || index == LAB_ACT_VFS) return "unknown action";
        out->action = (lab_action_t)index;
    }
    if (count > passage_field && !parse_unsigned(fields[passage_field], &out->passage)) return "bad passage";
    if (count > passage_field + 1u) return "too many fields";
    static const unsigned needed[] = {ALLOW_APPLY, ALLOW_LOG, ALLOW_KILL, ALLOW_PAUSE, ALLOW_SYNTHETIC, ALLOW_VFS};
    if (!(k_points[out->point].allowed & needed[out->action])) return "action not allowed at this point";
    return NULL;
}

static void add_spec(const char *text, size_t length) {
    while (length > 0u && (text[length - 1u] == ' ' || text[length - 1u] == '\t' || text[length - 1u] == '\r'))
        --length;
    while (length > 0u && (text[0] == ' ' || text[0] == '\t')) { ++text; --length; }
    if (length == 0u || text[0] == '#') return;
    if (lab.spec_count >= LAB_MAX_SPECS) refuse("too many faults", "at most 16");
    const char *why = parse_spec(text, length, &lab.specs[lab.spec_count]);
    if (why) refuse("fault refused", why);
    ++lab.spec_count;
}

static void load_specs(const char *text, size_t size, char separator) {
    const char *cursor = text, *end = text + size;
    while (cursor < end) {
        const char *stop = memchr(cursor, separator, (size_t)(end - cursor));
        if (!stop) stop = end;
        add_spec(cursor, (size_t)(stop - cursor));
        cursor = stop + 1;
    }
}

static void load_file(void) {
    unsigned char *bytes = NULL;
    size_t size = 0u;
    const char *reason = NULL;
    if (maelys_cli_read_trusted_file(MG_LAB_FAULT_FILE,
                                     MAELYS_CLI_FILE_REGULAR | MAELYS_CLI_FILE_NO_SYMLINK |
                                         MAELYS_CLI_FILE_OWNER_CALLER | MAELYS_CLI_FILE_PRIVATE,
                                     0u, LAB_MAX_FAULT_BYTES, &bytes, &size, &reason) != 0) {
        if (errno == ENOENT) return; /* no fault file: no fault */
        refuse("fault file " MG_LAB_FAULT_FILE " refused", reason ? reason : strerror(errno));
    }
    load_specs((const char *)bytes, size, '\n');
    free(bytes);
}

/* ---- the SQLite VFS of the laboratory --------------------------------------------- */

typedef struct {
    sqlite3_file base;
    sqlite3_file *real;
    size_t kind;
} lab_file_t;

static sqlite3_vfs lab_vfs;
static sqlite3_vfs *real_vfs;
static sqlite3_io_methods lab_methods;

static size_t classify(int flags) {
    if (flags & SQLITE_OPEN_MAIN_DB) return 0u;
    if (flags & SQLITE_OPEN_WAL) return 1u;
    if (flags & SQLITE_OPEN_MAIN_JOURNAL) return 2u;
    if (flags & (SQLITE_OPEN_TEMP_DB | SQLITE_OPEN_TEMP_JOURNAL | SQLITE_OPEN_TRANSIENT_DB |
                 SQLITE_OPEN_SUBJOURNAL | SQLITE_OPEN_SUPER_JOURNAL))
        return 3u;
    return 4u;
}

/* The operation OP on a file of KIND, in the current phase: counted,
 * traced when vfs.trace is on, and failed with the armed code when it is
 * the armed occurrence. Returns the SQLite code to give back, or OK. */
static int vfs_check(const lab_file_t *file, size_t op) {
    unsigned n = ++lab.counts[file->kind][op];
    if (lab.trace_vfs) {
        mg_json_t json;
        marker_begin(&json, "vfs_op", SIZE_MAX);
        mg_json_string(&json, "file", k_kinds[file->kind]);
        mg_json_string(&json, "op", k_ops[op]);
        mg_json_i64(&json, "n", (int64_t)n);
        marker_end(&json);
    }
    if (lab.vfs.armed && lab.vfs.kind == file->kind && lab.vfs.op == op && lab.vfs.seq == lab.phase_seq &&
        n == lab.vfs.occurrence) {
        lab.vfs.armed = 0;
        mg_json_t json;
        marker_begin(&json, "vfs_fault", lab.vfs.phase);
        mg_json_string(&json, "file", k_kinds[file->kind]);
        mg_json_string(&json, "op", k_ops[op]);
        mg_json_i64(&json, "occurrence", (int64_t)n);
        mg_json_i64(&json, "code", lab.vfs.code);
        mg_json_string(&json, "code_name", lab.vfs.code_name);
        marker_end(&json);
        return lab.vfs.code;
    }
    return SQLITE_OK;
}

/* An armed fault whose phase ends before its occurrence never carries
 * over to the next phase, nor to the next passage of the same point:
 * reported with the count seen, and disarmed. Also run at exit for the
 * last phase of the process. */
static void vfs_disarm_unreached(void) {
    if (!lab.vfs.armed) return;
    lab.vfs.armed = 0;
    mg_json_t json;
    marker_begin(&json, "vfs_unreached", lab.vfs.phase);
    mg_json_string(&json, "file", k_kinds[lab.vfs.kind]);
    mg_json_string(&json, "op", k_ops[lab.vfs.op]);
    mg_json_i64(&json, "occurrence", (int64_t)lab.vfs.occurrence);
    mg_json_i64(&json, "seen", (int64_t)lab.counts[lab.vfs.kind][lab.vfs.op]);
    mg_json_i64(&json, "code", lab.vfs.code);
    mg_json_string(&json, "code_name", lab.vfs.code_name);
    marker_end(&json);
}

#define REAL(file) (((lab_file_t *)(file))->real)

/* Closes the underlying file once: its methods are cleared after, so a
 * second close through the wrapper reaches nothing. */
static int lab_close(sqlite3_file *file) {
    sqlite3_file *real = REAL(file);
    if (!real->pMethods) return SQLITE_OK;
    int rc = real->pMethods->xClose(real);
    real->pMethods = NULL;
    return rc;
}
static int lab_read(sqlite3_file *file, void *buffer, int amount, sqlite3_int64 offset) {
    return REAL(file)->pMethods->xRead(REAL(file), buffer, amount, offset);
}
static int lab_write(sqlite3_file *file, const void *buffer, int amount, sqlite3_int64 offset) {
    int rc = vfs_check((lab_file_t *)file, OP_WRITE);
    return rc != SQLITE_OK ? rc : REAL(file)->pMethods->xWrite(REAL(file), buffer, amount, offset);
}
static int lab_truncate(sqlite3_file *file, sqlite3_int64 size) {
    int rc = vfs_check((lab_file_t *)file, OP_TRUNCATE);
    return rc != SQLITE_OK ? rc : REAL(file)->pMethods->xTruncate(REAL(file), size);
}
static int lab_sync(sqlite3_file *file, int flags) {
    int rc = vfs_check((lab_file_t *)file, OP_SYNC);
    return rc != SQLITE_OK ? rc : REAL(file)->pMethods->xSync(REAL(file), flags);
}
static int lab_file_size(sqlite3_file *file, sqlite3_int64 *out_size) {
    int rc = vfs_check((lab_file_t *)file, OP_FILESIZE);
    return rc != SQLITE_OK ? rc : REAL(file)->pMethods->xFileSize(REAL(file), out_size);
}
static int lab_lock(sqlite3_file *file, int level) {
    return REAL(file)->pMethods->xLock(REAL(file), level);
}
static int lab_unlock(sqlite3_file *file, int level) {
    return REAL(file)->pMethods->xUnlock(REAL(file), level);
}
static int lab_check_reserved_lock(sqlite3_file *file, int *out) {
    return REAL(file)->pMethods->xCheckReservedLock(REAL(file), out);
}
static int lab_file_control(sqlite3_file *file, int operation, void *argument) {
    return REAL(file)->pMethods->xFileControl(REAL(file), operation, argument);
}
static int lab_sector_size(sqlite3_file *file) {
    return REAL(file)->pMethods->xSectorSize(REAL(file));
}
static int lab_device_characteristics(sqlite3_file *file) {
    return REAL(file)->pMethods->xDeviceCharacteristics(REAL(file));
}
static int lab_shm_map(sqlite3_file *file, int page, int size, int extend, void volatile **out) {
    if (REAL(file)->pMethods->iVersion < 2) return SQLITE_IOERR_SHMMAP;
    return REAL(file)->pMethods->xShmMap(REAL(file), page, size, extend, out);
}
static int lab_shm_lock(sqlite3_file *file, int offset, int n, int flags) {
    if (REAL(file)->pMethods->iVersion < 2) return SQLITE_IOERR_SHMLOCK;
    return REAL(file)->pMethods->xShmLock(REAL(file), offset, n, flags);
}
static void lab_shm_barrier(sqlite3_file *file) {
    if (REAL(file)->pMethods->iVersion >= 2) REAL(file)->pMethods->xShmBarrier(REAL(file));
}
static int lab_shm_unmap(sqlite3_file *file, int delete_flag) {
    if (REAL(file)->pMethods->iVersion < 2) return SQLITE_OK;
    return REAL(file)->pMethods->xShmUnmap(REAL(file), delete_flag);
}
static int lab_fetch(sqlite3_file *file, sqlite3_int64 offset, int amount, void **out) {
    if (REAL(file)->pMethods->iVersion < 3) { *out = NULL; return SQLITE_OK; }
    return REAL(file)->pMethods->xFetch(REAL(file), offset, amount, out);
}
static int lab_unfetch(sqlite3_file *file, sqlite3_int64 offset, void *page) {
    if (REAL(file)->pMethods->iVersion < 3) return SQLITE_OK;
    return REAL(file)->pMethods->xUnfetch(REAL(file), offset, page);
}

static int lab_open(sqlite3_vfs *vfs, const char *name, sqlite3_file *file, int flags, int *out_flags) {
    (void)vfs;
    lab_file_t *wrapped = (lab_file_t *)file;
    wrapped->real = (sqlite3_file *)((char *)file + sizeof(*wrapped));
    wrapped->kind = classify(flags);
    wrapped->real->pMethods = NULL;
    int rc = real_vfs->xOpen(real_vfs, name, wrapped->real, flags, out_flags);
    mg_json_t json;
    marker_begin(&json, "vfs_open", SIZE_MAX);
    mg_json_string(&json, "file", k_kinds[wrapped->kind]);
    if (name) mg_json_string(&json, "path", name);
    else mg_json_null(&json, "path");
    mg_json_i64(&json, "flags", flags);
    mg_json_i64(&json, "rc", rc);
    mg_json_boolean(&json, "methods", wrapped->real->pMethods != NULL);
    marker_end(&json);
    /* The contract of xOpen: when it fails with pMethods set, the caller
     * closes the file. The wrapper exposes its methods whenever the
     * underlying VFS exposed its own, in success and in failure alike, so
     * that close reaches the underlying file. */
    file->pMethods = wrapped->real->pMethods ? &lab_methods : NULL;
    return rc;
}
static int lab_delete(sqlite3_vfs *vfs, const char *name, int sync_directory) {
    (void)vfs;
    return real_vfs->xDelete(real_vfs, name, sync_directory);
}
static int lab_access(sqlite3_vfs *vfs, const char *name, int flags, int *out) {
    (void)vfs;
    return real_vfs->xAccess(real_vfs, name, flags, out);
}
static int lab_full_pathname(sqlite3_vfs *vfs, const char *name, int capacity, char *out) {
    (void)vfs;
    return real_vfs->xFullPathname(real_vfs, name, capacity, out);
}
static void *lab_dl_open(sqlite3_vfs *vfs, const char *name) {
    (void)vfs;
    return real_vfs->xDlOpen ? real_vfs->xDlOpen(real_vfs, name) : NULL;
}
static void lab_dl_error(sqlite3_vfs *vfs, int capacity, char *out) {
    (void)vfs;
    if (real_vfs->xDlError) real_vfs->xDlError(real_vfs, capacity, out);
}
static void (*lab_dl_sym(sqlite3_vfs *vfs, void *handle, const char *symbol))(void) {
    (void)vfs;
    return real_vfs->xDlSym ? real_vfs->xDlSym(real_vfs, handle, symbol) : NULL;
}
static void lab_dl_close(sqlite3_vfs *vfs, void *handle) {
    (void)vfs;
    if (real_vfs->xDlClose) real_vfs->xDlClose(real_vfs, handle);
}
static int lab_randomness(sqlite3_vfs *vfs, int count, char *out) {
    (void)vfs;
    return real_vfs->xRandomness(real_vfs, count, out);
}
static int lab_sleep(sqlite3_vfs *vfs, int microseconds) {
    (void)vfs;
    return real_vfs->xSleep(real_vfs, microseconds);
}
static int lab_current_time(sqlite3_vfs *vfs, double *out) {
    (void)vfs;
    return real_vfs->xCurrentTime(real_vfs, out);
}
static int lab_last_error(sqlite3_vfs *vfs, int capacity, char *out) {
    (void)vfs;
    return real_vfs->xGetLastError ? real_vfs->xGetLastError(real_vfs, capacity, out) : 0;
}
static int lab_current_time_int64(sqlite3_vfs *vfs, sqlite3_int64 *out) {
    (void)vfs;
    if (real_vfs->iVersion >= 2 && real_vfs->xCurrentTimeInt64)
        return real_vfs->xCurrentTimeInt64(real_vfs, out);
    double days = 0.0;
    int rc = real_vfs->xCurrentTime(real_vfs, &days);
    *out = (sqlite3_int64)(days * 86400000.0);
    return rc;
}

static void vfs_register(void) {
    real_vfs = sqlite3_vfs_find(NULL);
    if (!real_vfs) refuse("no default SQLite VFS", "");
    memset(&lab_vfs, 0, sizeof(lab_vfs));
    lab_vfs.iVersion = 2;
    lab_vfs.szOsFile = (int)sizeof(lab_file_t) + real_vfs->szOsFile;
    lab_vfs.mxPathname = real_vfs->mxPathname;
    lab_vfs.zName = "maelys-lab";
    lab_vfs.pAppData = real_vfs;
    lab_vfs.xOpen = lab_open;
    lab_vfs.xDelete = lab_delete;
    lab_vfs.xAccess = lab_access;
    lab_vfs.xFullPathname = lab_full_pathname;
    lab_vfs.xDlOpen = lab_dl_open;
    lab_vfs.xDlError = lab_dl_error;
    lab_vfs.xDlSym = lab_dl_sym;
    lab_vfs.xDlClose = lab_dl_close;
    lab_vfs.xRandomness = lab_randomness;
    lab_vfs.xSleep = lab_sleep;
    lab_vfs.xCurrentTime = lab_current_time;
    lab_vfs.xGetLastError = lab_last_error;
    lab_vfs.xCurrentTimeInt64 = lab_current_time_int64;
    memset(&lab_methods, 0, sizeof(lab_methods));
    lab_methods.iVersion = 3;
    lab_methods.xClose = lab_close;
    lab_methods.xRead = lab_read;
    lab_methods.xWrite = lab_write;
    lab_methods.xTruncate = lab_truncate;
    lab_methods.xSync = lab_sync;
    lab_methods.xFileSize = lab_file_size;
    lab_methods.xLock = lab_lock;
    lab_methods.xUnlock = lab_unlock;
    lab_methods.xCheckReservedLock = lab_check_reserved_lock;
    lab_methods.xFileControl = lab_file_control;
    lab_methods.xSectorSize = lab_sector_size;
    lab_methods.xDeviceCharacteristics = lab_device_characteristics;
    lab_methods.xShmMap = lab_shm_map;
    lab_methods.xShmLock = lab_shm_lock;
    lab_methods.xShmBarrier = lab_shm_barrier;
    lab_methods.xShmUnmap = lab_shm_unmap;
    lab_methods.xFetch = lab_fetch;
    lab_methods.xUnfetch = lab_unfetch;
    if (sqlite3_vfs_register(&lab_vfs, 1) != SQLITE_OK) refuse("cannot register the VFS maelys-lab", "");
    (void)atexit(vfs_disarm_unreached);
}

/* ---- initialization -------------------------------------------------------------- */

void mg_lab_init(const char *role) {
    if (lab.initialized) return;
    lab.initialized = 1;
    lab.role = strcmp(role, "agent") == 0 ? LAB_ROLE_AGENT : LAB_ROLE_EXECUTOR;
    lab.role_name = lab.role == LAB_ROLE_AGENT ? "agent" : "executor";
    const char *fault_file = MG_LAB_FAULT_FILE;
    const char *slash = strrchr(fault_file, '/');
    if (slash && slash != fault_file)
        (void)snprintf(lab.dir, sizeof(lab.dir), "%.*s", (int)(slash - fault_file), fault_file);
    else
        (void)snprintf(lab.dir, sizeof(lab.dir), "%s", slash ? "/" : ".");
    if (lab.role == LAB_ROLE_AGENT) {
        const char *given = getenv("MG_QUAL_FAULT");
        if (given) load_specs(given, strlen(given), ';');
    } else {
        load_file();
    }
    char path[PATH_MAX + 32u];
    (void)snprintf(path, sizeof(path), "%s/markers.jsonl", lab.dir);
    lab.markers = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    for (size_t i = 0u; i < lab.spec_count; ++i) {
        if (lab.specs[i].action != LAB_ACT_LOG) continue;
        if (lab.specs[i].point == POINT_HTTP_TRACE) lab.trace_http = 1;
        if (lab.specs[i].point == POINT_VFS_TRACE) lab.trace_vfs = 1;
    }
    mg_json_t json;
    marker_begin(&json, "init", SIZE_MAX);
    mg_json_string(&json, "built_with", "MG_LAB_FAULTS");
    mg_json_string(&json, "fault_file", MG_LAB_FAULT_FILE);
    mg_json_boolean(&json, "markers_open", lab.markers >= 0);
    mg_json_array(&json, "faults");
    for (size_t i = 0u; i < lab.spec_count; ++i) mg_json_string(&json, NULL, lab.specs[i].text);
    mg_json_end_array(&json);
    marker_end(&json);
    if (lab.role == LAB_ROLE_AGENT) vfs_register();
}

void mg_lab_context(const char *message_id) {
    if (!message_id) lab.context[0] = '\0';
    else (void)snprintf(lab.context, sizeof(lab.context), "%s", message_id);
}

/* ---- reaching a point ---------------------------------------------------------- */

static void wait_for_resume(size_t point) {
    char path[PATH_MAX + 64u];
    (void)snprintf(path, sizeof(path), "%s/resume.%s", lab.dir, k_points[point].name);
    marker("paused", point);
    int64_t deadline = mg_monotonic_ms() + LAB_PAUSE_MS;
    while (access(path, F_OK) != 0) {
        if (mg_monotonic_ms() >= deadline) {
            marker("pause_expired", point);
            _exit(LAB_EXIT_MISCONFIGURED);
        }
        struct timespec slice = {0, 10000000L};
        (void)nanosleep(&slice, NULL);
    }
    marker("resumed", point);
}

mg_lab_outcome_t mg_lab_reach(const char *point) {
    mg_lab_outcome_t outcome = {0, 0, 0, NULL};
    if (!lab.initialized) return outcome;
    size_t index = find_point(point);
    if (index == SIZE_MAX) {
        (void)fprintf(stderr, "maelys-git-lab: unknown point %s\n", point);
        return outcome;
    }
    ++lab.passages[index];
    /* A phase runs from a point to the next: the VFS counts its operations
     * from here, whatever the point, and a fault armed for the phase that
     * ends here is reported if it has not fired. */
    vfs_disarm_unreached();
    ++lab.phase_seq;
    lab.phase = index;
    memset(lab.counts, 0, sizeof(lab.counts));
    marker("reached", index);
    lab_spec_t *spec = NULL;
    for (size_t i = 0u; i < lab.spec_count && !spec; ++i)
        if (lab.specs[i].point == index && lab.specs[i].passage == lab.passages[index] && !lab.specs[i].fired)
            spec = &lab.specs[i];
    if (!spec) return outcome;
    spec->fired = 1;
    mg_json_t json;
    switch (spec->action) {
    case LAB_ACT_LOG:
        break;
    case LAB_ACT_KILL:
        marker("kill", index);
        (void)kill(getpid(), SIGKILL);
        for (;;) (void)pause();
    case LAB_ACT_PAUSE:
        wait_for_resume(index);
        break;
    case LAB_ACT_SYNTHETIC:
        marker_begin(&json, "synthetic", index);
        mg_json_i64(&json, "code", spec->code);
        mg_json_string(&json, "code_name", spec->code_name);
        marker_end(&json);
        outcome.synthetic = 1;
        outcome.code = spec->code;
        outcome.code_name = spec->code_name;
        break;
    case LAB_ACT_VFS:
        lab.vfs.armed = 1;
        lab.vfs.kind = spec->vfs_kind;
        lab.vfs.op = spec->vfs_op;
        lab.vfs.phase = index;
        lab.vfs.seq = lab.phase_seq;
        lab.vfs.code = spec->code;
        lab.vfs.code_name = spec->code_name;
        lab.vfs.occurrence = spec->vfs_occurrence;
        marker_begin(&json, "armed", index);
        mg_json_string(&json, "file", k_kinds[spec->vfs_kind]);
        mg_json_string(&json, "op", k_ops[spec->vfs_op]);
        mg_json_i64(&json, "code", spec->code);
        mg_json_string(&json, "code_name", spec->code_name);
        mg_json_i64(&json, "occurrence", (int64_t)spec->vfs_occurrence);
        marker_end(&json);
        break;
    case LAB_ACT_APPLY:
        marker("apply", index);
        outcome.apply = 1;
        break;
    }
    return outcome;
}

void mg_lab_http_trace(const char *method, const char *target, int result, const char *result_name,
                       int64_t duration_ms) {
    if (!lab.initialized || !lab.trace_http) return;
    mg_json_t json;
    marker_begin(&json, "http_advance", POINT_HTTP_TRACE);
    mg_json_string(&json, "method", method);
    mg_json_string(&json, "target", target);
    mg_json_i64(&json, "result", result);
    mg_json_string(&json, "result_name", result_name ? result_name : "");
    mg_json_i64(&json, "duration_ms", duration_ms);
    marker_end(&json);
}

/* ---- the executor's alterations ------------------------------------------------- */

static const maelys_json_limits_t k_line_limits = {
    .maximum_bytes = MAELYS_GIT_MAX_PROTOCOL_LINE,
    .maximum_depth = MG_PROTOCOL_MAX_DEPTH,
    .maximum_tokens = MG_PROTOCOL_MAX_TOKENS,
};

static maelys_json_document_t *parse_line(const char *line) {
    maelys_json_document_t *document = NULL;
    if (maelys_json_document_parse(line, strlen(line), MAELYS_JSON_PROFILE_RFC8259, &k_line_limits, &document,
                                   NULL) != MAELYS_JSON_OK)
        return NULL;
    return document;
}

static char flipped(char hex) {
    return hex == '0' ? '1' : '0';
}

typedef enum { RECEIPT_ALTER, RECEIPT_WITHOUT_GRANTS, RECEIPT_WRONG_GRANTS } receipt_change_t;

/* The receipt of DOCUMENT rewritten with one change, as canonical bytes:
 * one byte of policySetFingerprint changed (the receipt's digest is then
 * not the one the result names); grants removed and the version put back
 * to 1 (a valid receipt of version 1); or grants.sha256 changed (a valid
 * receipt naming other grants). NULL when the receipt has not what the
 * change needs. */
static char *changed_receipt(const maelys_json_document_t *document, maelys_json_value_t receipt,
                             receipt_change_t change) {
    maelys_json_writer_t *writer = NULL;
    maelys_json_result_t status = maelys_json_writer_create(MAELYS_JSON_PROFILE_RFC8259, &k_line_limits, 0u, &writer);
    maelys_json_view_t view;
    char digest[65];
    if (status != MAELYS_JSON_OK) return NULL;
    if (change == RECEIPT_ALTER) {
        static const char *const keys[] = {"policySetFingerprint"};
        if (maelys_json_object_get_string(document, receipt, "policySetFingerprint", &view) != MAELYS_JSON_OK ||
            view.size != 64u)
            status = MAELYS_JSON_ERR_ARGUMENT;
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_begin_except(writer, document, receipt, keys, 1u);
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_key_cstr(writer, "policySetFingerprint");
        if (status == MAELYS_JSON_OK) {
            memcpy(digest, view.data, 64u);
            digest[64] = '\0';
            digest[0] = flipped(digest[0]);
            status = maelys_json_writer_string_cstr(writer, digest);
        }
    } else if (change == RECEIPT_WITHOUT_GRANTS) {
        static const char *const keys[] = {"grants", "version"};
        maelys_json_value_t grants = 0;
        if (maelys_json_object_get(document, receipt, "grants", &grants) != MAELYS_JSON_OK)
            status = MAELYS_JSON_ERR_ARGUMENT;
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_begin_except(writer, document, receipt, keys, 2u);
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_key_cstr(writer, "version");
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_u64(writer, 1u);
    } else {
        static const char *const keys[] = {"grants"};
        static const char *const grants_keys[] = {"sha256"};
        maelys_json_value_t grants = 0;
        if (maelys_json_object_get(document, receipt, "grants", &grants) != MAELYS_JSON_OK ||
            maelys_json_object_get_string(document, grants, "sha256", &view) != MAELYS_JSON_OK || view.size != 64u)
            status = MAELYS_JSON_ERR_ARGUMENT;
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_begin_except(writer, document, receipt, keys, 1u);
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_key_cstr(writer, "grants");
        if (status == MAELYS_JSON_OK)
            status = maelys_json_writer_object_begin_except(writer, document, grants, grants_keys, 1u);
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_key_cstr(writer, "sha256");
        if (status == MAELYS_JSON_OK) {
            memcpy(digest, view.data, 64u);
            digest[64] = '\0';
            digest[0] = flipped(digest[0]);
            status = maelys_json_writer_string_cstr(writer, digest);
        }
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_end(writer);
    }
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_end(writer);
    char *bytes = NULL;
    size_t size = 0u;
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_finish(writer, &bytes, &size);
    maelys_json_writer_release(writer);
    return status == MAELYS_JSON_OK ? bytes : NULL;
}

/* The result line of DOCUMENT with its payload rewritten: the members
 * DROP removed, and, when RECEIPT is given, that receipt in place of the
 * original with SHA256 as its named digest. */
static char *rebuilt_line(const maelys_json_document_t *document, const char *const *drop, size_t drop_count,
                          const maelys_json_document_t *receipt, const char *sha256) {
    static const char *const payload_key[] = {"payload"};
    maelys_json_value_t root = maelys_json_document_root(document), payload = 0;
    if (maelys_json_object_get(document, root, "payload", &payload) != MAELYS_JSON_OK) return NULL;
    maelys_json_writer_t *writer = NULL;
    maelys_json_result_t status = maelys_json_writer_create(MAELYS_JSON_PROFILE_RFC8259, &k_line_limits, 0u, &writer);
    if (status != MAELYS_JSON_OK) return NULL;
    status = maelys_json_writer_object_begin_except(writer, document, root, payload_key, 1u);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_key_cstr(writer, "payload");
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_begin_except(writer, document, payload, drop, drop_count);
    if (status == MAELYS_JSON_OK && receipt) {
        status = maelys_json_writer_key_cstr(writer, "receipt");
        if (status == MAELYS_JSON_OK)
            status = maelys_json_writer_value(writer, receipt, maelys_json_document_root(receipt));
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_key_cstr(writer, "receipt_sha256");
        if (status == MAELYS_JSON_OK) status = maelys_json_writer_string_cstr(writer, sha256);
    }
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_end(writer);
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_object_end(writer);
    char *bytes = NULL;
    size_t size = 0u;
    if (status == MAELYS_JSON_OK) status = maelys_json_writer_finish(writer, &bytes, &size);
    maelys_json_writer_release(writer);
    return status == MAELYS_JSON_OK ? bytes : NULL;
}

static void skipped(size_t point, const char *why) {
    mg_json_t json;
    marker_begin(&json, "skipped", point);
    mg_json_string(&json, "why", why);
    marker_end(&json);
}

/* One alteration of the receipt the line carries; the line is replaced. */
static maelys_git_result_t alter_receipt(char **line, size_t point, receipt_change_t change) {
    static const char *const drop[] = {"receipt", "receipt_sha256"};
    maelys_json_document_t *document = parse_line(*line);
    if (!document) return MAELYS_GIT_ERR_IO;
    maelys_json_value_t root = maelys_json_document_root(document), payload = 0, receipt = 0;
    maelys_json_view_t named;
    if (maelys_json_object_get(document, root, "payload", &payload) != MAELYS_JSON_OK ||
        maelys_json_object_get(document, payload, "receipt", &receipt) != MAELYS_JSON_OK ||
        maelys_json_object_get_string(document, payload, "receipt_sha256", &named) != MAELYS_JSON_OK ||
        named.size != 64u) {
        maelys_json_document_release(document);
        skipped(point, "the result carries no receipt");
        return MAELYS_GIT_OK;
    }
    char kept[65];
    memcpy(kept, named.data, 64u);
    kept[64] = '\0';
    char *bytes = changed_receipt(document, receipt, change);
    if (!bytes) {
        maelys_json_document_release(document);
        skipped(point, "the receipt has not what the change needs");
        return MAELYS_GIT_OK;
    }
    maelys_json_document_t *changed = parse_line(bytes);
    char sha256[65] = "";
    maelys_git_result_t result = MAELYS_GIT_OK;
    if (!changed) {
        result = MAELYS_GIT_ERR_IO;
    } else if (change != RECEIPT_ALTER) {
        /* A valid receipt of the new shape names its own digest. */
        char *canonical = NULL;
        size_t size = 0u;
        mg_receipt_text_t text;
        maelys_git_error_t error = {0};
        result = mg_receipt_rewrite(changed, maelys_json_document_root(changed), &canonical, &size, sha256, &text,
                                    &error);
        free(canonical);
    } else {
        memcpy(sha256, kept, sizeof(sha256));
    }
    char *rebuilt = result == MAELYS_GIT_OK ? rebuilt_line(document, drop, 2u, changed, sha256) : NULL;
    maelys_json_document_release(changed);
    maelys_json_document_release(document);
    free(bytes);
    if (!rebuilt) return result == MAELYS_GIT_OK ? MAELYS_GIT_ERR_IO : result;
    free(*line);
    *line = rebuilt;
    return MAELYS_GIT_OK;
}

static maelys_git_result_t drop_members(char **line, size_t point, const char *const *drop, size_t count) {
    maelys_json_document_t *document = parse_line(*line);
    if (!document) return MAELYS_GIT_ERR_IO;
    maelys_json_value_t root = maelys_json_document_root(document), payload = 0, receipt = 0;
    if (maelys_json_object_get(document, root, "payload", &payload) != MAELYS_JSON_OK ||
        maelys_json_object_get(document, payload, "receipt", &receipt) != MAELYS_JSON_OK) {
        maelys_json_document_release(document);
        skipped(point, "the result carries no receipt");
        return MAELYS_GIT_OK;
    }
    char *rebuilt = rebuilt_line(document, drop, count, NULL, NULL);
    maelys_json_document_release(document);
    if (!rebuilt) return MAELYS_GIT_ERR_IO;
    free(*line);
    *line = rebuilt;
    return MAELYS_GIT_OK;
}

maelys_git_result_t mg_lab_alter_result(char **line) {
    static const char *const drop_receipt[] = {"receipt", "receipt_sha256"};
    static const char *const drop_all[] = {"receipt", "receipt_sha256", "explanation_text"};
    if (!lab.initialized || !line || !*line) return MAELYS_GIT_OK;
    maelys_git_result_t result = MAELYS_GIT_OK;
    for (size_t point = (size_t)POINT_ALTER_RECEIPT; point <= (size_t)POINT_EXIT_AFTER_EFFECT && result == MAELYS_GIT_OK;
         ++point) {
        if (!mg_lab_reach(k_points[point].name).apply) continue;
        switch (point) {
        case POINT_ALTER_RECEIPT:
            result = alter_receipt(line, point, RECEIPT_ALTER);
            break;
        case POINT_DROP_RECEIPT_KEEP_TEXT:
            result = drop_members(line, point, drop_receipt, COUNT(drop_receipt));
            break;
        case POINT_DROP_RECEIPT_AND_TEXT:
            result = drop_members(line, point, drop_all, COUNT(drop_all));
            break;
        case POINT_RECEIPT_WITHOUT_GRANTS:
            result = alter_receipt(line, point, RECEIPT_WITHOUT_GRANTS);
            break;
        case POINT_WRONG_GRANTS:
            result = alter_receipt(line, point, RECEIPT_WRONG_GRANTS);
            break;
        case POINT_INVALID_ENVELOPE: {
            char *invalid = strdup("{\"lab\":\"invalid envelope\"}");
            if (!invalid) { result = MAELYS_GIT_ERR_IO; break; }
            free(*line);
            *line = invalid;
            break;
        }
        case POINT_HANG:
            for (;;) (void)pause();
        case POINT_EXIT_AFTER_EFFECT:
            _exit(0);
        default:
            break;
        }
    }
    return result;
}
