#ifndef MAELYS_GIT_AGENT_INTERNAL_H
#define MAELYS_GIT_AGENT_INTERNAL_H

#include "internal.h"
#include "common/json_write.h"
#include "maelys_git_agent.h"

#include <maelys/json.h>
#include <sqlite3.h>
#include <stdint.h>

#define MG_AGENT_ID_MAX 128u
#define MG_MESSAGE_ID_MAX 128u
#define MG_COMMAND_MAX 64u
#define MG_AUTHORITY_MAX 512u
#define MG_TARGET_MAX 1024u
#define MG_TOKEN_MAX 4096u

/* Config v1 is a flat object of 14 required scalar fields. Parser tokens
 * count the root, each key and each value. Whitespace counts toward bytes. */
#define MG_CONFIG_MAX_BYTES (64u * 1024u)
#define MG_CONFIG_MAX_DEPTH 1u
#define MG_CONFIG_FIELD_COUNT 14u
/* grants_path, the one optional member: a configuration of version 1 holds
 * 14 members, or 15 with it. */
#define MG_CONFIG_OPTIONAL_FIELDS 1u
#define MG_CONFIG_MAX_TOKENS (1u + 2u * (MG_CONFIG_FIELD_COUNT + MG_CONFIG_OPTIONAL_FIELDS))

/* Explicit protocol budgets; tokens include object keys and containers.
 * The token ceiling admits every JSON shape fitting the 64 KiB byte cap. */
#define MG_PROTOCOL_MAX_DEPTH 32u
#define MG_PROTOCOL_MAX_TOKENS ((MAELYS_GIT_MAX_PROTOCOL_LINE + 1u) / 2u)
/* The poll object and commands array add two levels around a command. */
#define MG_POLL_MAX_DEPTH (MG_PROTOCOL_MAX_DEPTH + 2u)
#define MG_POLL_MAX_COMMANDS 32u

typedef struct {
    char protocol[32];
    char message_id[MG_MESSAGE_ID_MAX];
    char agent_id[MG_AGENT_ID_MAX];
    char type[32];
    char command[MG_COMMAND_MAX];
    char repository[MAELYS_GIT_MAX_REPOSITORY];
    char principal[512];
    int64_t issued_at_ms;
    int64_t expires_at_ms;
    /* Owned document plus borrowed payload handle. No shallow ownership
     * copies: all views expire at mg_protocol_message_clear(). */
    maelys_json_document_t *document;
    maelys_json_value_t payload;
} mg_agent_message_t;

typedef struct {
    maelys_json_document_t *document;
    maelys_json_view_t cursor; /* Borrowed from document. */
    size_t command_count;
    maelys_json_value_t commands; /* The array of commands, in document. */
} mg_agent_poll_t;

struct maelys_git_agent_config {
    char agent_id[MG_AGENT_ID_MAX];
    char authority[MG_AUTHORITY_MAX];
    char ca_file[4096];
    char token_file[4096];
    char database_path[4096];
    char manifest_path[4096];
    char repository_root[4096];
    char git_executable[4096];
    char executor_path[4096];
    char grants_path[4096]; /* empty without a snapshot of grants */
    char command_target[MG_TARGET_MAX];
    char event_target[MG_TARGET_MAX];
    uint64_t poll_timeout_ms;
    uint64_t request_timeout_ms;
};

struct maelys_git_agent_store {
    sqlite3 *database;
};

typedef enum {
    MG_STORE_COMMAND_NEW = 1,
    MG_STORE_COMMAND_PENDING,
    MG_STORE_COMMAND_RUNNING,
    MG_STORE_COMMAND_COMPLETE,
    MG_STORE_COMMAND_FAILED
} mg_store_command_state_t;

typedef struct {
    char id[MG_MESSAGE_ID_MAX];
    char kind[64];
    char *payload;
    unsigned attempts;
} mg_outbox_item_t;

/* 1 when every member of `object` is named in the NULL-terminated list. */
int mg_document_object_has_only(const maelys_json_document_t *document,
                                maelys_json_value_t object,
                                const char *const *allowed);

maelys_git_result_t mg_protocol_parse(const char *bytes,
                                      size_t length,
                                      mg_agent_message_t *out,
                                      maelys_git_error_t *error);
void mg_protocol_message_clear(mg_agent_message_t *message);
maelys_git_result_t mg_protocol_poll_parse(const char *bytes, size_t length,
                                           mg_agent_poll_t *out,
                                           maelys_git_error_t *error);
void mg_protocol_poll_clear(mg_agent_poll_t *poll);
/* The deduplication form of a received command, v2: the command as the
 * poll gave it, written again by maelys-json, printable ASCII, compact, its
 * keys sorted by UTF-16 code units. It is what the journal compares when a
 * message_id comes back. NULL on failure, with the error set. */
char *mg_protocol_poll_command_form(const mg_agent_poll_t *poll, size_t index,
                                    maelys_git_error_t *error);
/* The same command in the same form, without the line limit: what an audit
 * of a rejected command records, whatever its size. */
char *mg_protocol_poll_command_text(const mg_agent_poll_t *poll, size_t index,
                                    maelys_git_error_t *error);
/* The v2 form of one command given as JSON in any form, a v1 form included:
 * parsed with the protocol's limits, then written as above. */
char *mg_protocol_deduplication_form(const char *bytes, size_t length,
                                     maelys_git_error_t *error);
maelys_git_result_t mg_protocol_validate_result(const char *bytes, size_t length,
                                                const mg_agent_message_t *command,
                                                int *out_succeeded,
                                                maelys_git_error_t *error);
/* A result line of `command`: begin writes the envelope and opens the
 * payload, whose members the caller writes; end closes and serializes it, as
 * one line of at most 65 536 bytes of JSON, the separator excluded. End
 * returns NULL on failure, with MAELYS_GIT_ERR_LIMIT when the result would
 * not fit the line, MAELYS_GIT_ERR_IO otherwise. */
void mg_protocol_result_begin(mg_json_t *json, const mg_agent_message_t *command,
                              const char *status);
char *mg_protocol_result_end(mg_json_t *json, maelys_git_error_t *error);

maelys_git_result_t mg_config_load(const char *path,
                                   maelys_git_agent_config_t **out,
                                   maelys_git_error_t *error);
void mg_config_free(maelys_git_agent_config_t *config);
maelys_git_result_t mg_token_load(const char *path,
                                  char *out,
                                  size_t capacity,
                                  maelys_git_error_t *error);

maelys_git_result_t mg_store_open(const char *path,
                                  maelys_git_agent_store_t **out,
                                  maelys_git_error_t *error);
void mg_store_close(maelys_git_agent_store_t *store);
maelys_git_result_t mg_store_record_command(maelys_git_agent_store_t *store,
                                            const mg_agent_message_t *message,
                                            const char *raw_json,
                                            mg_store_command_state_t *out_state,
                                            char **out_result,
                                            maelys_git_error_t *error);
maelys_git_result_t mg_store_mark_running(maelys_git_agent_store_t *store,
                                          const char *command_id,
                                          maelys_git_error_t *error);
/* What an executor result carries that the agent audits: the receipt's
 * canonical bytes, verified, and the explanation text, checked against the
 * receipt's size and digest. `published` is the result rewritten without the
 * text when the command did not ask for it; NULL when the result is
 * published as the executor wrote it. */
typedef struct {
    char *receipt;
    char *text;
    char *published;
    char *grants; /* the snapshot of grants the executor was started with */
} mg_receipt_events_t;

/* Reads an executor result for `command`. A result without a receipt gives
 * no event. A receipt that does not verify, whose digest is not the
 * result's, or a text that is not the one the receipt vouches for, is
 * MAELYS_GIT_ERR_PROTOCOL: the command fails and nothing is audited. */
maelys_git_result_t mg_receipt_events_prepare(const mg_agent_message_t *command,
                                              const char *result_json,
                                              mg_receipt_events_t *out_events,
                                              maelys_git_error_t *error);
void mg_receipt_events_clear(mg_receipt_events_t *events);

/* A snapshot of grants in the agent's store: its SHA-256 and the path of the
 * immutable file that holds its bytes; empty without a snapshot. */
typedef struct {
    char sha256[65];
    char path[4096];
    int lock; /* the store's lock, held shared until released; -1 when none */
} mg_grants_archive_t;

/* Reads the snapshot at GRANTS_PATH and keeps its bytes in the store beside
 * the journal at DATABASE_PATH, grants-store/<sha256>.json: a directory
 * private to the agent's account, a file written once, read-only, synced
 * with its directory. A file already there is read again and must hold the
 * bytes its name says. Nothing is returned on failure. */
maelys_git_result_t mg_grants_store_archive(const char *grants_path, const char *database_path,
                                            mg_grants_archive_t *out, maelys_git_error_t *error);
/* Releases the lock an archive holds, once the executor that reads its
 * file has exited; nothing for an archive without one. */
void mg_grants_archive_release(mg_grants_archive_t *archive);

/* One file of the store, as a purge judges it. */
typedef struct {
    char sha256[65];
    int64_t bytes;
    int64_t last_used_ms; /* its last grants_snapshot event, or its writing if later */
    int keep;
    const char *reason;   /* "current", "latest", "recent" or "expired" */
} mg_grants_store_entry_t;

typedef struct {
    char store[4096];
    mg_grants_store_entry_t *entries; /* most recently used first */
    size_t count;
    size_t removed;      /* removed, or to remove in a plan */
    int64_t freed_bytes;
} mg_grants_store_prune_t;

/* Judges the files of the store beside the journal of CONFIG: it keeps the
 * snapshot grants_path holds now, the KEEP most recently used, and those
 * used less than MAX_AGE_MS before NOW_MS; the others expire. With APPLY,
 * it takes the store's lock exclusive (waiting at most WAIT_MS for running
 * commands), removes the expired files, syncs the directory and audits a
 * grants_store_pruned event. A missing store gives an empty result. */
maelys_git_result_t mg_grants_store_prune(const maelys_git_agent_config_t *config, size_t keep,
                                          uint64_t max_age_ms, int64_t now_ms, uint64_t wait_ms, int apply,
                                          mg_grants_store_prune_t *out, maelys_git_error_t *error);
void mg_grants_store_prune_clear(mg_grants_store_prune_t *result);

/* Gives VISIT the digest and the time of every grants_snapshot event. */
maelys_git_result_t mg_store_grants_uses(maelys_git_agent_store_t *store,
                                         void (*visit)(const char *sha256, int64_t at_ms, void *context),
                                         void *context, maelys_git_error_t *error);

/* Adds to EVENTS the snapshot ARCHIVE names, which the agent audits with the
 * completion. A receipt of version 2 must name those grants, and a receipt
 * without an archived snapshot must name none: otherwise the executor
 * decided on other bytes, MAELYS_GIT_ERR_PROTOCOL. */
maelys_git_result_t mg_receipt_events_add_grants(mg_receipt_events_t *events, const mg_grants_archive_t *archive,
                                                 maelys_git_error_t *error);

/* Records the result, queues it and audits the completion, with the
 * receipt and explanation events when given, in one transaction. */
maelys_git_result_t mg_store_complete_command(maelys_git_agent_store_t *store,
                                              const char *command_id,
                                              int succeeded,
                                              const char *result_json,
                                              const mg_receipt_events_t *events,
                                              int64_t now_ms,
                                              maelys_git_error_t *error);
maelys_git_result_t mg_store_enqueue(maelys_git_agent_store_t *store,
                                     const char *id,
                                     const char *kind,
                                     const char *payload,
                                     int64_t now_ms,
                                     maelys_git_error_t *error);
maelys_git_result_t mg_store_next_outbox(maelys_git_agent_store_t *store,
                                         int64_t now_ms,
                                         mg_outbox_item_t *out,
                                         maelys_git_error_t *error);
void mg_outbox_item_clear(mg_outbox_item_t *item);
maelys_git_result_t mg_store_ack_outbox(maelys_git_agent_store_t *store,
                                        const char *id,
                                        maelys_git_error_t *error);
maelys_git_result_t mg_store_retry_outbox(maelys_git_agent_store_t *store,
                                          const char *id,
                                          unsigned attempts,
                                          int64_t next_attempt_ms,
                                          maelys_git_error_t *error);
maelys_git_result_t mg_store_get_cursor(maelys_git_agent_store_t *store,
                                        char *out,
                                        size_t capacity,
                                        maelys_git_error_t *error);
maelys_git_result_t mg_store_set_cursor(maelys_git_agent_store_t *store,
                                        const char *cursor,
                                        maelys_git_error_t *error);
maelys_git_result_t mg_store_audit(maelys_git_agent_store_t *store,
                                   const char *event_id,
                                   const char *kind,
                                   const char *payload,
                                   int64_t now_ms,
                                   maelys_git_error_t *error);

int64_t mg_now_ms(void);
uint64_t mg_retry_delay_ms(const char *key,
                           unsigned attempt,
                           uint64_t base_ms,
                           uint64_t maximum_ms);

/* The payload members one command accepts, NULL-terminated. */
typedef struct {
    const char *command;
    const char *const *members;
} mg_executor_payload_t;

/* Every command the executor runs, ending with a NULL command. */
extern const mg_executor_payload_t mg_executor_payloads[];

/* Executes one command. `denial_mode` says whether the denial of a command
 * that changes a repository carries the explanation text: an executor whose
 * results an agent audits renders it, the agent keeps it in its audit and
 * removes it from what it publishes. */
maelys_git_result_t mg_executor_execute(maelys_git_policy_t *policy,
                                        const char *git_executable,
                                        const char *repository_root,
                                        const mg_agent_message_t *message,
                                        maelys_git_explain_mode_t denial_mode,
                                        char **out_result_json,
                                        maelys_git_error_t *error);

/* maelys_git_agent_serve with the executor's denial mode. */
maelys_git_result_t mg_agent_serve(maelys_git_policy_t *policy,
                                   const char *git_executable,
                                   const char *repository_root,
                                   FILE *input,
                                   FILE *output,
                                   FILE *diagnostics,
                                   maelys_git_explain_mode_t denial_mode,
                                   maelys_git_error_t *error);

#ifdef MAELYS_GIT_ENABLE_CLOUD_AGENT
/* Runs COMMAND in a fresh executor. With a snapshot of grants configured,
 * its bytes are first kept in the agent's store, and the executor reads that
 * file and its digest only: OUT_GRANTS (which may be NULL) names them. A
 * snapshot that cannot be kept starts no executor; the command is answered by
 * a correlated failed result whose message starts with "grants store
 * unavailable: ". */
maelys_git_result_t mg_supervisor_execute(const maelys_git_agent_config_t *config,
                                          const mg_agent_message_t *command,
                                          const char *request_json,
                                          mg_grants_archive_t *out_grants,
                                          char **out_response_json,
                                          int *out_succeeded,
                                          maelys_git_error_t *error);
maelys_git_result_t mg_cloud_run(const maelys_git_agent_config_t *config,
                                 int run_once,
                                 maelys_git_error_t *error);
#endif

#endif
