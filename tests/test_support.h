#ifndef MAELYS_GIT_TEST_SUPPORT_H
#define MAELYS_GIT_TEST_SUPPORT_H

/* Shared fixtures for the C test programs. */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 0; \
    } \
} while (0)

static inline int test_remove_tree(const char *path) {
    DIR *directory = opendir(path);
    if (!directory) return unlink(path) == 0;
    struct dirent *entry;
    int ok = 1;
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char child[4096];
        int count = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (count < 0 || (size_t)count >= sizeof(child)) { ok = 0; break; }
        struct stat status;
        if (lstat(child, &status) != 0) { ok = 0; break; }
        if (S_ISDIR(status.st_mode)) ok = test_remove_tree(child) && ok;
        else ok = unlink(child) == 0 && ok;
    }
    (void)closedir(directory);
    return rmdir(path) == 0 && ok;
}

#endif
