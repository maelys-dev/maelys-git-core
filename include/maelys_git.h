#ifndef MAELYS_GIT_H
#define MAELYS_GIT_H

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAELYS_GIT_VERSION "0.1.0"
#define MAELYS_GIT_MAX_REPOSITORY 512u
#define MAELYS_GIT_MAX_REF 512u
#define MAELYS_GIT_MAX_ERROR 512u
#define MAELYS_GIT_MAX_PROTOCOL_LINE (64u * 1024u)
#define MAELYS_GIT_MAX_CHANGED_PATHS 64u

typedef enum {
    MAELYS_GIT_OK = 0,
    MAELYS_GIT_ERR_INVALID_ARGUMENT = -1,
    MAELYS_GIT_ERR_INVALID_COMMAND = -2,
    MAELYS_GIT_ERR_INVALID_REPOSITORY = -3,
    MAELYS_GIT_ERR_POLICY = -4,
    MAELYS_GIT_ERR_DENIED = -5,
    MAELYS_GIT_ERR_IO = -6,
    MAELYS_GIT_ERR_PROCESS = -7,
    MAELYS_GIT_ERR_PROTOCOL = -8,
    MAELYS_GIT_ERR_LIMIT = -9,
    MAELYS_GIT_ERR_NOT_FOUND = -10
} maelys_git_result_t;

typedef struct {
    maelys_git_result_t code;
    int system_error;
    char message[MAELYS_GIT_MAX_ERROR];
} maelys_git_error_t;

const char *maelys_git_result_name(maelys_git_result_t result);
void maelys_git_error_clear(maelys_git_error_t *error);

typedef enum {
    MAELYS_GIT_SERVICE_UPLOAD_PACK = 1,
    MAELYS_GIT_SERVICE_RECEIVE_PACK = 2
} maelys_git_service_t;

typedef struct {
    maelys_git_service_t service;
    char repository[MAELYS_GIT_MAX_REPOSITORY];
} maelys_git_ssh_command_t;

maelys_git_result_t maelys_git_parse_ssh_command(
    const char *original_command,
    maelys_git_ssh_command_t *out,
    maelys_git_error_t *error);

int maelys_git_repository_name_is_valid(const char *name);
int maelys_git_ref_name_is_valid(const char *ref_name);

maelys_git_result_t maelys_git_resolve_repository(
    const char *repository_root,
    const char *repository_name,
    char *out_path,
    size_t out_capacity,
    maelys_git_error_t *error);

typedef struct maelys_git_policy maelys_git_policy_t;

typedef struct {
    const char *request_id;
    const char *principal;
    const char *repository;
    const char *operation;
    const char *ref_name;
    const char *ssh_key;
    const char *remote_address;
    const char *const *paths;
    size_t path_count;
} maelys_git_policy_request_t;

typedef struct {
    int allowed;
    int explicit_deny;
    size_t matched_policy;
    char reason[MAELYS_GIT_MAX_ERROR];
} maelys_git_policy_decision_t;

maelys_git_result_t maelys_git_policy_open(
    const char *manifest_path,
    maelys_git_policy_t **out_policy,
    maelys_git_error_t *error);
void maelys_git_policy_close(maelys_git_policy_t *policy);
maelys_git_result_t maelys_git_policy_authorize(
    maelys_git_policy_t *policy,
    const maelys_git_policy_request_t *request,
    maelys_git_policy_decision_t *out_decision,
    maelys_git_error_t *error);

typedef struct {
    char **items;
    size_t count;
} maelys_git_path_list_t;

void maelys_git_path_list_clear(maelys_git_path_list_t *paths);

maelys_git_result_t maelys_git_repository_changed_paths(
    const char *git_executable,
    const char *repository_path,
    const char *old_oid,
    const char *new_oid,
    maelys_git_path_list_t *out_paths,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_repository_init_bare(
    const char *git_executable,
    const char *repository_root,
    const char *repository_name,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_repository_update_ref(
    const char *git_executable,
    const char *repository_path,
    const char *ref_name,
    const char *new_oid,
    const char *expected_old_oid,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_exec_service(
    const char *git_executable,
    maelys_git_service_t service,
    const char *repository_path,
    const char *principal,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_pre_receive(
    maelys_git_policy_t *policy,
    const char *git_executable,
    const char *repository_path,
    const char *repository_name,
    const char *principal,
    FILE *input,
    FILE *diagnostics,
    maelys_git_error_t *error);

maelys_git_result_t maelys_git_post_receive(
    const char *repository_name,
    const char *principal,
    FILE *input,
    FILE *events,
    maelys_git_error_t *error);

#ifdef __cplusplus
}
#endif

#endif
