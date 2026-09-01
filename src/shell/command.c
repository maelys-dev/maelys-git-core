#include "internal.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int valid_component(const char *start, size_t length) {
    if (length == 0u) return 0;
    if ((length == 1u && start[0] == '.') ||
        (length == 2u && start[0] == '.' && start[1] == '.') ||
        (length == 11u && memcmp(start, ".maelys-git", 11u) == 0)) return 0;
    return 1;
}

int maelys_git_repository_name_is_valid(const char *name) {
    if (!name || !*name || name[0] == '/' || strlen(name) >= MAELYS_GIT_MAX_REPOSITORY) return 0;
    const char *component = name;
    for (const char *p = name;; ++p) {
        unsigned char ch = (unsigned char)*p;
        if (ch == '/' || ch == '\0') {
            if (!valid_component(component, (size_t)(p - component))) return 0;
            if (ch == '\0') break;
            component = p + 1;
            continue;
        }
        if (!(isalnum(ch) || ch == '.' || ch == '_' || ch == '-')) return 0;
    }
    size_t length = strlen(name);
    return length > 4u && strcmp(name + length - 4u, ".git") == 0;
}

int maelys_git_ref_name_is_valid(const char *ref_name) {
    if (!ref_name || strncmp(ref_name, "refs/", 5u) != 0 ||
        strlen(ref_name) >= MAELYS_GIT_MAX_REF) return 0;
    if (strstr(ref_name, "..") || strstr(ref_name, "@{") || strstr(ref_name, "//")) return 0;
    size_t length = strlen(ref_name);
    if (length == 0u || ref_name[length - 1u] == '/' || ref_name[length - 1u] == '.') return 0;
    for (const unsigned char *p = (const unsigned char *)ref_name; *p; ++p) {
        if (*p <= 0x20u || *p == 0x7fu || strchr("~^:?*[\\", *p)) return 0;
    }
    return 1;
}

maelys_git_result_t maelys_git_parse_ssh_command(const char *original_command,
                                                  maelys_git_ssh_command_t *out,
                                                  maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!original_command || !out) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_ARGUMENT, 0, "SSH command and output are required");
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    const char *rest = NULL;
    maelys_git_service_t service;
    if (strncmp(original_command, "git-upload-pack ", 16u) == 0) {
        service = MAELYS_GIT_SERVICE_UPLOAD_PACK;
        rest = original_command + 16u;
    } else if (strncmp(original_command, "git-receive-pack ", 17u) == 0) {
        service = MAELYS_GIT_SERVICE_RECEIVE_PACK;
        rest = original_command + 17u;
    } else {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_COMMAND, 0, "only git-upload-pack and git-receive-pack are accepted");
        return MAELYS_GIT_ERR_INVALID_COMMAND;
    }
    size_t length = strlen(rest);
    if (length < 3u || (rest[0] != '\'' && rest[0] != '"') || rest[length - 1u] != rest[0]) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_COMMAND, 0, "repository must be a single quoted argument");
        return MAELYS_GIT_ERR_INVALID_COMMAND;
    }
    size_t repository_length = length - 2u;
    if (repository_length >= sizeof(out->repository)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, 0, "repository name is too long");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    memcpy(out->repository, rest + 1u, repository_length);
    out->repository[repository_length] = '\0';
    if (!maelys_git_repository_name_is_valid(out->repository)) {
        mg_error_set(error, MAELYS_GIT_ERR_INVALID_REPOSITORY, 0, "invalid repository name");
        return MAELYS_GIT_ERR_INVALID_REPOSITORY;
    }
    out->service = service;
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_exec_service(const char *git_executable,
                                             maelys_git_service_t service,
                                             const char *repository_path,
                                             const char *principal,
                                             maelys_git_error_t *error) {
    if (!git_executable || !repository_path || !principal || !*principal) {
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    }
    const char *subcommand = service == MAELYS_GIT_SERVICE_UPLOAD_PACK
                                 ? "upload-pack"
                                 : service == MAELYS_GIT_SERVICE_RECEIVE_PACK ? "receive-pack" : NULL;
    if (!subcommand) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    char *const argv[] = {(char *)git_executable, (char *)subcommand, (char *)repository_path, NULL};
    char principal_environment[1024];
    int count = snprintf(principal_environment,
                         sizeof(principal_environment),
                         "MAELYS_GIT_PRINCIPAL=%s",
                         principal);
    if (count < 0 || (size_t)count >= sizeof(principal_environment)) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "principal is too long");
        return MAELYS_GIT_ERR_LIMIT;
    }
    char *const environment[] = {
        "PATH=/usr/bin:/bin",
        "LANG=C",
        "LC_ALL=C",
        "GIT_CONFIG_NOSYSTEM=1",
        principal_environment,
        NULL
    };
    execve(git_executable, argv, environment);
    mg_error_set(error, MAELYS_GIT_ERR_PROCESS, errno, "execve(%s) failed: %s", git_executable, strerror(errno));
    return MAELYS_GIT_ERR_PROCESS;
}
