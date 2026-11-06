/* The fidelity of the SQLite VFS of the qualification laboratory (GIT-C10
 * step 2c): an armed fault fires in the instance of the phase that armed
 * it and in no other, a fault whose phase ends before its occurrence is
 * reported and disarmed, and the wrapper keeps the xOpen contract of
 * SQLite in failure with exactly one close of the underlying file. One
 * case per process, named by the only argument: the runtime reads
 * MG_QUAL_FAULT once and registers its VFS once. The markers are read
 * from the file beside MG_LAB_FAULT_FILE, from its size before the
 * initialization. Built with the -lab targets, never installed. */
#include "agent/lab.h"

#include <sqlite3.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;
#define CHECK(condition, ...)                                              \
    do {                                                                   \
        if (!(condition)) {                                                \
            ++failures;                                                    \
            (void)fprintf(stderr, "test_lab_vfs: " __VA_ARGS__);           \
            (void)fputc('\n', stderr);                                     \
        }                                                                  \
    } while (0)

static char lab_dir[4096];
static char markers_path[4096 + 32];
static long markers_start;

/* The directory of the fault file exists, and the markers written before
 * this process are set apart. */
static void lab_dir_ready(void) {
    const char *fault = MG_LAB_FAULT_FILE;
    const char *slash = strrchr(fault, '/');
    if (!slash || slash == fault) {
        (void)fprintf(stderr, "test_lab_vfs: the fault file %s has no directory\n", fault);
        exit(2);
    }
    (void)snprintf(lab_dir, sizeof(lab_dir), "%.*s", (int)(slash - fault), fault);
    if (mkdir(lab_dir, 0700) != 0 && errno != EEXIST) {
        perror(lab_dir);
        exit(2);
    }
    (void)snprintf(markers_path, sizeof(markers_path), "%s/markers.jsonl", lab_dir);
    struct stat st;
    markers_start = stat(markers_path, &st) == 0 ? (long)st.st_size : 0L;
}

/* The markers this process (and its children) wrote: the file from the
 * recorded size to its end, NUL-terminated. */
static char *markers_tail(void) {
    FILE *stream = fopen(markers_path, "rb");
    if (!stream) return strdup("");
    (void)fseek(stream, 0L, SEEK_END);
    long end = ftell(stream);
    long size = end > markers_start ? end - markers_start : 0L;
    char *text = malloc((size_t)size + 1u);
    if (!text) exit(2);
    (void)fseek(stream, markers_start, SEEK_SET);
    size_t got = fread(text, 1u, (size_t)size, stream);
    text[got] = '\0';
    (void)fclose(stream);
    return text;
}

/* The lines of TEXT that contain every one of the fragments (NULL ends
 * the list). */
static unsigned lines_with(const char *text, const char *first, ...) {
    unsigned count = 0u;
    const char *line = text;
    while (*line) {
        const char *end = strchr(line, '\n');
        size_t length = end ? (size_t)(end - line) : strlen(line);
        char *copy = malloc(length + 1u);
        if (!copy) exit(2);
        memcpy(copy, line, length);
        copy[length] = '\0';
        int all = strstr(copy, first) != NULL;
        va_list fragments;
        va_start(fragments, first);
        for (const char *fragment = va_arg(fragments, const char *); all && fragment;
             fragment = va_arg(fragments, const char *))
            all = strstr(copy, fragment) != NULL;
        va_end(fragments);
        free(copy);
        count += all ? 1u : 0u;
        if (!end) break;
        line = end + 1;
    }
    return count;
}

static sqlite3_file *open_main(sqlite3_vfs *vfs, const char *path, int *out_rc) {
    sqlite3_file *file = calloc(1u, (size_t)vfs->szOsFile);
    if (!file) exit(2);
    int flags = 0;
    *out_rc = vfs->xOpen(vfs, path, file, SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                         &flags);
    return file;
}

static sqlite3_vfs *lab_vfs_ready(const char *spec) {
    if (spec) {
        if (setenv("MG_QUAL_FAULT", spec, 1) != 0) exit(2);
    } else {
        (void)unsetenv("MG_QUAL_FAULT");
    }
    mg_lab_init("agent");
    sqlite3_vfs *vfs = sqlite3_vfs_find(NULL);
    CHECK(vfs && strcmp(vfs->zName, "maelys-lab") == 0, "the default VFS is not maelys-lab");
    return vfs;
}

static void database_path(char *out, size_t capacity, const char *name) {
    (void)snprintf(out, capacity, "%s/vfs-test-%s-%ld.db", lab_dir, name, (long)getpid());
}

/* ---- the lifetime of an armed fault ----------------------------------------- */

#define FSYNC_SECOND "store.complete_commit:vfs=main:xSync:SQLITE_IOERR_FSYNC:2"

/* The armed occurrence fires in the phase that armed it; nothing before a
 * point, nothing after the fault. */
static void case_armed_phase_only(void) {
    sqlite3_vfs *vfs = lab_vfs_ready(FSYNC_SECOND);
    char path[4096];
    database_path(path, sizeof(path), "armed");
    int rc;
    sqlite3_file *file = open_main(vfs, path, &rc);
    CHECK(rc == SQLITE_OK, "open: %d", rc);
    CHECK(file->pMethods->xSync(file, SQLITE_SYNC_NORMAL) == SQLITE_OK, "a sync before any point failed");
    mg_lab_context("command-one");
    (void)mg_lab_reach("store.complete_commit");
    CHECK(file->pMethods->xSync(file, SQLITE_SYNC_NORMAL) == SQLITE_OK, "the first sync failed");
    CHECK(file->pMethods->xSync(file, SQLITE_SYNC_NORMAL) == SQLITE_IOERR_FSYNC, "the second sync did not fail");
    CHECK(file->pMethods->xSync(file, SQLITE_SYNC_NORMAL) == SQLITE_OK, "the third sync failed: still armed");
    CHECK(file->pMethods->xClose(file) == SQLITE_OK, "close failed");
    free(file);
    (void)unlink(path);
    char *tail = markers_tail();
    CHECK(lines_with(tail, "\"event\":\"armed\"", "\"message_id\":\"command-one\"", "\"passage\":1", NULL) == 1u,
          "one armed marker on command-one expected");
    CHECK(lines_with(tail, "\"event\":\"vfs_fault\"", "\"message_id\":\"command-one\"", "\"occurrence\":2", NULL) == 1u,
          "one vfs_fault marker on command-one expected");
    CHECK(lines_with(tail, "\"event\":\"vfs_unreached\"", NULL) == 0u, "no vfs_unreached marker expected");
    free(tail);
}

/* The reviewer's reproduction (2C-01): the occurrence not reached in the
 * first passage, the phase left for another point, then the same point
 * reached again on another command. The old arming must not fire there. */
static void case_unreached_disarmed(void) {
    sqlite3_vfs *vfs = lab_vfs_ready(FSYNC_SECOND);
    char path[4096];
    database_path(path, sizeof(path), "unreached");
    int rc;
    sqlite3_file *file = open_main(vfs, path, &rc);
    CHECK(rc == SQLITE_OK, "open: %d", rc);
    mg_lab_context("command-one");
    (void)mg_lab_reach("store.complete_commit");
    CHECK(file->pMethods->xSync(file, SQLITE_SYNC_NORMAL) == SQLITE_OK, "the only sync of the first passage failed");
    (void)mg_lab_reach("http.after_poll");
    CHECK(file->pMethods->xSync(file, SQLITE_SYNC_NORMAL) == SQLITE_OK, "a sync in another phase failed (1)");
    CHECK(file->pMethods->xSync(file, SQLITE_SYNC_NORMAL) == SQLITE_OK, "a sync in another phase failed (2)");
    mg_lab_context("command-two");
    (void)mg_lab_reach("store.complete_commit");
    CHECK(file->pMethods->xSync(file, SQLITE_SYNC_NORMAL) == SQLITE_OK, "command-two: the first sync failed");
    CHECK(file->pMethods->xSync(file, SQLITE_SYNC_NORMAL) == SQLITE_OK,
          "command-two: the second sync failed: the fault armed on command-one survived its phase");
    CHECK(file->pMethods->xClose(file) == SQLITE_OK, "close failed");
    free(file);
    (void)unlink(path);
    char *tail = markers_tail();
    CHECK(lines_with(tail, "\"event\":\"armed\"", NULL) == 1u, "exactly one armed marker expected");
    CHECK(lines_with(tail, "\"event\":\"armed\"", "\"message_id\":\"command-one\"", NULL) == 1u,
          "the armed marker belongs to command-one");
    CHECK(lines_with(tail, "\"event\":\"vfs_unreached\"", "\"point\":\"store.complete_commit\"",
                     "\"message_id\":\"command-one\"", "\"seen\":1", "\"occurrence\":2", NULL) == 1u,
          "one vfs_unreached marker on command-one with seen 1 of 2 expected");
    CHECK(lines_with(tail, "\"event\":\"vfs_fault\"", NULL) == 0u, "no vfs_fault marker expected");
    free(tail);
}

/* A fault targeted at the second passage fires there, and only there. */
static void case_second_passage(void) {
    sqlite3_vfs *vfs = lab_vfs_ready("store.complete_commit:vfs=main:xSync:SQLITE_IOERR_FSYNC:1:2");
    char path[4096];
    database_path(path, sizeof(path), "second");
    int rc;
    sqlite3_file *file = open_main(vfs, path, &rc);
    CHECK(rc == SQLITE_OK, "open: %d", rc);
    mg_lab_context("command-one");
    (void)mg_lab_reach("store.complete_commit");
    CHECK(file->pMethods->xSync(file, SQLITE_SYNC_NORMAL) == SQLITE_OK, "command-one: sync failed");
    (void)mg_lab_reach("http.after_poll");
    mg_lab_context("command-two");
    (void)mg_lab_reach("store.complete_commit");
    CHECK(file->pMethods->xSync(file, SQLITE_SYNC_NORMAL) == SQLITE_IOERR_FSYNC,
          "command-two: the first sync did not fail");
    CHECK(file->pMethods->xSync(file, SQLITE_SYNC_NORMAL) == SQLITE_OK, "command-two: the second sync failed");
    CHECK(file->pMethods->xClose(file) == SQLITE_OK, "close failed");
    free(file);
    (void)unlink(path);
    char *tail = markers_tail();
    CHECK(lines_with(tail, "\"event\":\"armed\"", "\"message_id\":\"command-two\"", "\"passage\":2", NULL) == 1u,
          "one armed marker on command-two, passage 2, expected");
    CHECK(lines_with(tail, "\"event\":\"armed\"", "\"message_id\":\"command-one\"", NULL) == 0u,
          "no armed marker on command-one expected");
    CHECK(lines_with(tail, "\"event\":\"vfs_fault\"", "\"message_id\":\"command-two\"", "\"passage\":2", NULL) == 1u,
          "one vfs_fault marker on command-two expected");
    CHECK(lines_with(tail, "\"event\":\"vfs_unreached\"", NULL) == 0u, "no vfs_unreached marker expected");
    free(tail);
}

/* A fault still armed when the process exits is reported at exit: the
 * arming happens in a child that returns normally. */
static void case_unreached_at_exit(void) {
    pid_t child = fork();
    if (child < 0) exit(2);
    if (child == 0) {
        sqlite3_vfs *vfs = lab_vfs_ready(FSYNC_SECOND);
        char path[4096];
        database_path(path, sizeof(path), "exit");
        int rc;
        sqlite3_file *file = open_main(vfs, path, &rc);
        if (rc != SQLITE_OK) _exit(3);
        mg_lab_context("command-one");
        (void)mg_lab_reach("store.complete_commit");
        if (file->pMethods->xSync(file, SQLITE_SYNC_NORMAL) != SQLITE_OK) _exit(4);
        (void)file->pMethods->xClose(file);
        free(file);
        (void)unlink(path);
        exit(failures ? 5 : 0);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "the child did not exit 0: %d", status);
    char *tail = markers_tail();
    CHECK(lines_with(tail, "\"event\":\"vfs_unreached\"", "\"message_id\":\"command-one\"", "\"seen\":1", NULL) == 1u,
          "one vfs_unreached marker at exit expected");
    CHECK(lines_with(tail, "\"event\":\"vfs_fault\"", NULL) == 0u, "no vfs_fault marker expected");
    free(tail);
}

/* ---- the xOpen contract --------------------------------------------------- */

/* An underlying VFS of test around the real default: its xOpen acquires a
 * descriptor, exposes a close method or not, and returns the code the case
 * chose; the close counts and releases the descriptor. */
static int resource = -1;
static unsigned closes;
static int open_result = SQLITE_OK;
static int open_sets_methods = 1;

static int fake_close(sqlite3_file *file) {
    (void)file;
    ++closes;
    if (resource >= 0) (void)close(resource);
    resource = -1;
    return SQLITE_OK;
}
static const sqlite3_io_methods fake_methods = {.iVersion = 1, .xClose = fake_close};

static int fake_open(sqlite3_vfs *vfs, const char *name, sqlite3_file *file, int flags, int *out_flags) {
    (void)vfs;
    (void)name;
    (void)flags;
    if (out_flags) *out_flags = 0;
    resource = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (resource < 0) exit(2);
    if (open_sets_methods) file->pMethods = &fake_methods;
    return open_result;
}

static sqlite3_vfs fake_vfs;

static sqlite3_vfs *fake_underlying_ready(int result, int sets_methods) {
    open_result = result;
    open_sets_methods = sets_methods;
    sqlite3_vfs *real = sqlite3_vfs_find(NULL);
    if (!real) exit(2);
    fake_vfs = *real;
    fake_vfs.zName = "test-lab-vfs-underlying";
    fake_vfs.pNext = NULL;
    fake_vfs.xOpen = fake_open;
    if (sqlite3_vfs_register(&fake_vfs, 1) != SQLITE_OK) exit(2);
    return lab_vfs_ready(NULL);
}

static int resource_open(void) {
    return resource >= 0 && fcntl(resource, F_GETFD) >= 0;
}

/* The reviewer's reproduction (2C-02): xOpen fails after exposing a close
 * method. The wrapper must expose its own, the close must reach the
 * underlying file exactly once, and a second close must reach nothing. */
static void case_open_error_with_methods(void) {
    sqlite3_vfs *vfs = fake_underlying_ready(SQLITE_CANTOPEN, 1);
    int rc;
    sqlite3_file *file = open_main(vfs, "/dev/null", &rc);
    CHECK(rc == SQLITE_CANTOPEN, "the failure of the underlying open was not returned: %d", rc);
    CHECK(file->pMethods != NULL, "the wrapper hid the close method of the failed open");
    CHECK(resource_open(), "the resource was released before any close");
    if (file->pMethods) {
        CHECK(file->pMethods->xClose(file) == SQLITE_OK, "close failed");
        CHECK(closes == 1u, "one close expected, %u", closes);
        CHECK(!resource_open(), "the resource is still open after the close");
        CHECK(file->pMethods->xClose(file) == SQLITE_OK, "a second close failed");
        CHECK(closes == 1u, "the second close reached the underlying file: %u", closes);
    }
    free(file);
    char *tail = markers_tail();
    CHECK(lines_with(tail, "\"event\":\"vfs_open\"", "\"rc\":14", "\"methods\":true", NULL) == 1u,
          "one vfs_open marker with rc 14 and methods true expected");
    free(tail);
    if (resource >= 0) (void)close(resource);
}

/* xOpen fails without exposing any method: nothing to close, and the
 * wrapper exposes nothing either. */
static void case_open_error_without_methods(void) {
    sqlite3_vfs *vfs = fake_underlying_ready(SQLITE_CANTOPEN, 0);
    int rc;
    sqlite3_file *file = open_main(vfs, "/dev/null", &rc);
    CHECK(rc == SQLITE_CANTOPEN, "the failure of the underlying open was not returned: %d", rc);
    CHECK(file->pMethods == NULL, "the wrapper exposed methods the underlying VFS did not");
    CHECK(closes == 0u, "no close expected, %u", closes);
    free(file);
    char *tail = markers_tail();
    CHECK(lines_with(tail, "\"event\":\"vfs_open\"", "\"rc\":14", "\"methods\":false", NULL) == 1u,
          "one vfs_open marker with rc 14 and methods false expected");
    free(tail);
    if (resource >= 0) (void)close(resource);
}

/* The ordinary path: an open that succeeds is closed exactly once. */
static void case_open_ok_closes_once(void) {
    sqlite3_vfs *vfs = fake_underlying_ready(SQLITE_OK, 1);
    int rc;
    sqlite3_file *file = open_main(vfs, "/dev/null", &rc);
    CHECK(rc == SQLITE_OK, "open: %d", rc);
    CHECK(file->pMethods != NULL, "the wrapper exposed no methods on success");
    if (file->pMethods) {
        CHECK(file->pMethods->xClose(file) == SQLITE_OK, "close failed");
        CHECK(closes == 1u, "one close expected, %u", closes);
        CHECK(!resource_open(), "the resource is still open after the close");
        CHECK(file->pMethods->xClose(file) == SQLITE_OK, "a second close failed");
        CHECK(closes == 1u, "the second close reached the underlying file: %u", closes);
    }
    free(file);
    if (resource >= 0) (void)close(resource);
}

/* ---- dispatch ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    static const struct {
        const char *name;
        void (*run)(void);
    } cases[] = {
        {"armed_phase_only", case_armed_phase_only},
        {"unreached_disarmed", case_unreached_disarmed},
        {"second_passage", case_second_passage},
        {"unreached_at_exit", case_unreached_at_exit},
        {"open_error_with_methods", case_open_error_with_methods},
        {"open_error_without_methods", case_open_error_without_methods},
        {"open_ok_closes_once", case_open_ok_closes_once},
    };
    if (argc != 2) {
        (void)fprintf(stderr, "usage: test_lab_vfs CASE\n");
        return 2;
    }
    lab_dir_ready();
    for (size_t i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (strcmp(cases[i].name, argv[1]) != 0) continue;
        cases[i].run();
        if (failures) (void)fprintf(stderr, "test_lab_vfs: %s: %d failure(s)\n", argv[1], failures);
        return failures ? 1 : 0;
    }
    (void)fprintf(stderr, "test_lab_vfs: unknown case %s\n", argv[1]);
    return 2;
}
