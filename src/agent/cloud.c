#include "agent_internal.h"

#include "maelys/http_client.h"
#include "maelys/http_tls_modules.h"
#include "maelys/http_transports.h"
#include "maelys/sys/clock.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    const unsigned char *bytes;
    size_t length;
    size_t offset;
} body_source_t;

typedef struct {
    unsigned char bytes[MAELYS_GIT_MAX_PROTOCOL_LINE + 1u];
    size_t length;
} body_capture_t;

typedef struct {
    maelys_http_tls_provider_t *tls;
    maelys_http_transport_t *transport;
    maelys_http_client_t *commands;
    maelys_http_client_t *events;
} cloud_clients_t;

static maelys_http_source_step_t fixed_source(void *opaque,
                                              unsigned char *buffer,
                                              size_t capacity,
                                              size_t *out_length) {
    body_source_t *source = opaque;
    size_t remaining = source->length - source->offset;
    if (remaining == 0u) { *out_length = 0u; return MAELYS_HTTP_SOURCE_END; }
    size_t count = remaining < capacity ? remaining : capacity;
    memcpy(buffer, source->bytes + source->offset, count);
    source->offset += count;
    *out_length = count;
    return MAELYS_HTTP_SOURCE_DATA;
}

static maelys_http_sink_step_t capture_body(void *opaque,
                                            const unsigned char *bytes,
                                            size_t length) {
    body_capture_t *capture = opaque;
    if (capture->length + length > MAELYS_GIT_MAX_PROTOCOL_LINE)
        return MAELYS_HTTP_SINK_FAILED;
    memcpy(capture->bytes + capture->length, bytes, length);
    capture->length += length;
    capture->bytes[capture->length] = '\0';
    return MAELYS_HTTP_SINK_ACCEPT;
}

static maelys_http_redirect_decision_t deny_redirect(
    void *context, unsigned status, maelys_http_slice_t old_authority,
    maelys_http_slice_t scheme, maelys_http_slice_t authority,
    maelys_http_slice_t target, size_t redirect_index) {
    (void)context; (void)status; (void)old_authority; (void)scheme;
    (void)authority; (void)target; (void)redirect_index;
    return MAELYS_HTTP_REDIRECT_DENY;
}

static maelys_git_result_t clients_create(const maelys_git_agent_config_t *config,
                                          cloud_clients_t *clients,
                                          maelys_git_error_t *error) {
    memset(clients, 0, sizeof(*clients));
    maelys_http_tls_client_files_t files = {.ca_file = config->ca_file};
    char *diagnostic = NULL;
    maelys_http_result_t result = maelys_http_tls_mbedtls_client_create(
        &files, &clients->tls, &diagnostic);
    if (result == MAELYS_HTTP_OK)
        result = maelys_http_posix_transport_create(clients->tls, &clients->transport, &diagnostic);
    maelys_http_client_limits_t limits;
    maelys_http_client_limits_default(&limits);
    limits.parser.max_body_bytes = MAELYS_GIT_MAX_PROTOCOL_LINE;
    limits.max_request_body_bytes = MAELYS_GIT_MAX_PROTOCOL_LINE;
    limits.max_wait_slice_ms = 250u;
    if (result == MAELYS_HTTP_OK)
        result = maelys_http_client_create(clients->transport, &limits, &clients->commands);
    if (result == MAELYS_HTTP_OK)
        result = maelys_http_client_create(clients->transport, &limits, &clients->events);
    if (result == MAELYS_HTTP_OK)
        result = maelys_http_client_set_connection_reuse(clients->commands, 1);
    if (result == MAELYS_HTTP_OK)
        result = maelys_http_client_set_connection_reuse(clients->events, 1);
    if (result != MAELYS_HTTP_OK) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, (int)result, "HTTP client setup failed: %s",
                     diagnostic ? diagnostic : maelys_http_result_string(result));
        free(diagnostic);
        return MAELYS_GIT_ERR_IO;
    }
    free(diagnostic);
    return MAELYS_GIT_OK;
}

static void clients_clear(cloud_clients_t *clients) {
    maelys_http_client_release(clients->events);
    maelys_http_client_release(clients->commands);
    maelys_http_transport_release(clients->transport);
    maelys_http_tls_provider_release(clients->tls);
    memset(clients, 0, sizeof(*clients));
}

static maelys_git_result_t http_request(maelys_http_client_t *client,
                                        const maelys_git_agent_config_t *config,
                                        const char *method,
                                        const char *target,
                                        const char *body,
                                        const char *idempotency_key,
                                        uint64_t timeout_ms,
                                        unsigned *out_status,
                                        body_capture_t *capture,
                                        maelys_git_error_t *error) {
    char token[MG_TOKEN_MAX];
    maelys_git_result_t git_result = mg_token_load(config->token_file, token, sizeof(token), error);
    if (git_result != MAELYS_GIT_OK) return git_result;
    char authorization[MG_TOKEN_MAX + 16u];
    if (snprintf(authorization, sizeof(authorization), "Bearer %s", token) < 0) {
        memset(token, 0, sizeof(token));
        return MAELYS_GIT_ERR_LIMIT;
    }
    memset(token, 0, sizeof(token));
    maelys_http_request_t *request = NULL;
    maelys_http_exchange_t *exchange = NULL;
    body_source_t source = {
        .bytes = (const unsigned char *)(body ? body : ""),
        .length = body ? strlen(body) : 0u,
        .offset = 0u,
    };
    memset(capture, 0, sizeof(*capture));
    maelys_http_result_t result = maelys_http_request_config_create(
        method, "https", config->authority, target, &request);
    if (result == MAELYS_HTTP_OK)
        result = maelys_http_request_add_header(request, "Authorization", authorization);
    memset(authorization, 0, sizeof(authorization));
    if (result == MAELYS_HTTP_OK)
        result = maelys_http_request_add_header(request, "Accept", "application/json");
    if (result == MAELYS_HTTP_OK)
        result = maelys_http_request_add_header(request, "X-Maelys-Agent-ID", config->agent_id);
    if (result == MAELYS_HTTP_OK && idempotency_key)
        result = maelys_http_request_add_header(request, "Idempotency-Key", idempotency_key);
    if (result == MAELYS_HTTP_OK && body) {
        result = maelys_http_request_add_header(request, "Content-Type", "application/json");
        if (result == MAELYS_HTTP_OK)
            result = maelys_http_request_set_fixed_body(request, source.length, fixed_source, &source);
    }
    if (result == MAELYS_HTTP_OK)
        result = maelys_http_request_set_response_sink(request, capture_body, capture);
    if (result == MAELYS_HTTP_OK)
        result = maelys_http_request_set_redirect_policy(request, deny_redirect, NULL);
    uint64_t deadline = 0u;
    if (result == MAELYS_HTTP_OK &&
        maelys_sys_deadline_after(timeout_ms, &deadline) != MAELYS_SYS_OK)
        result = MAELYS_HTTP_ERR_IO;
    if (result == MAELYS_HTTP_OK)
        result = maelys_http_exchange_create(client, request, deadline, &exchange);
    while (result == MAELYS_HTTP_OK || result == MAELYS_HTTP_AGAIN)
        result = maelys_http_exchange_advance(exchange);
    if (result == MAELYS_HTTP_COMPLETE) *out_status = maelys_http_exchange_status(exchange);
    else {
        const char *diagnostic = exchange ? maelys_http_exchange_error(exchange) : NULL;
        mg_error_set(error, MAELYS_GIT_ERR_IO, (int)result, "HTTPS request failed: %s",
                     diagnostic ? diagnostic : maelys_http_result_string(result));
    }
    maelys_http_exchange_release(exchange);
    maelys_http_request_release(request);
    return result == MAELYS_HTTP_COMPLETE ? MAELYS_GIT_OK : MAELYS_GIT_ERR_IO;
}

static int percent_encode(const char *source, char *out, size_t capacity) {
    static const char hex[] = "0123456789ABCDEF";
    size_t used = 0u;
    for (const unsigned char *p = (const unsigned char *)source; *p; ++p) {
        int plain = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                    (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.' || *p == '~';
        size_t need = plain ? 1u : 3u;
        if (used + need >= capacity) return 0;
        if (plain) out[used++] = (char)*p;
        else { out[used++] = '%'; out[used++] = hex[*p >> 4u]; out[used++] = hex[*p & 15u]; }
    }
    out[used] = '\0';
    return 1;
}

static maelys_git_result_t flush_one(cloud_clients_t *clients,
                                     const maelys_git_agent_config_t *config,
                                     maelys_git_agent_store_t *store,
                                     maelys_git_error_t *error) {
    mg_outbox_item_t item;
    maelys_git_result_t result = mg_store_next_outbox(store, mg_now_ms(), &item, error);
    if (result == MAELYS_GIT_ERR_NOT_FOUND) return MAELYS_GIT_OK;
    if (result != MAELYS_GIT_OK) return result;
    body_capture_t capture;
    unsigned status = 0u;
    result = http_request(clients->events, config, "POST", config->event_target,
                          item.payload, item.id, config->request_timeout_ms,
                          &status, &capture, error);
    if (result == MAELYS_GIT_OK && status >= 200u && status < 300u)
        result = mg_store_ack_outbox(store, item.id, error);
    else if (result == MAELYS_GIT_OK && (status == 401u || status == 403u)) {
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0, "cloud rejected agent credentials");
        result = MAELYS_GIT_ERR_DENIED;
    } else {
        unsigned attempts = item.attempts + 1u;
        int64_t retry_at = mg_now_ms() + (int64_t)mg_retry_delay_ms(item.id, attempts, 500u, 60000u);
        maelys_git_error_t ignored;
        (void)mg_store_retry_outbox(store, item.id, attempts, retry_at, &ignored);
        if (result == MAELYS_GIT_OK) {
            mg_error_set(error, MAELYS_GIT_ERR_IO, (int)status, "cloud event endpoint returned HTTP %u", status);
            result = MAELYS_GIT_ERR_IO;
        }
    }
    mg_outbox_item_clear(&item);
    return result;
}

static char *executor_failure(const mg_agent_message_t *message, const char *description) {
    json_t *payload = json_pack("{s:s,s:s}", "code", "executor_failed",
                                "message", description ? description : "executor failed");
    char *result = payload ? mg_protocol_encode_result(message, "failed", payload, NULL) : NULL;
    json_decref(payload);
    return result;
}

static maelys_git_result_t process_command(const maelys_git_agent_config_t *config,
                                           maelys_git_agent_store_t *store,
                                           json_t *command_json,
                                           maelys_git_error_t *error) {
    /* Durable deduplication v1: preserve Jansson flags and bytes exactly. */
    char *raw = json_dumps(command_json, JSON_COMPACT | JSON_ENSURE_ASCII | JSON_SORT_KEYS);
    if (!raw) return MAELYS_GIT_ERR_IO;
    mg_agent_message_t message;
    maelys_git_result_t result = mg_protocol_parse(raw, strlen(raw), &message, error);
    if (result != MAELYS_GIT_OK) { free(raw); return result; }
    if (strcmp(message.agent_id, config->agent_id) != 0) {
        mg_protocol_message_clear(&message); free(raw);
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0, "command targets another agent");
        return MAELYS_GIT_ERR_DENIED;
    }
    mg_store_command_state_t state;
    char *stored_result = NULL;
    result = mg_store_record_command(store, &message, raw, &state, &stored_result, error);
    if (result == MAELYS_GIT_OK &&
        (state == MG_STORE_COMMAND_COMPLETE || state == MG_STORE_COMMAND_FAILED)) {
        int succeeded = 0;
        if (!stored_result) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "completed command has no stored result");
            result = MAELYS_GIT_ERR_PROTOCOL;
        } else {
            result = mg_protocol_validate_result(stored_result, strlen(stored_result),
                                                  &message, &succeeded, error);
            if (result == MAELYS_GIT_OK && succeeded != (state == MG_STORE_COMMAND_COMPLETE)) {
                mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "stored result disagrees with command state");
                result = MAELYS_GIT_ERR_PROTOCOL;
            }
            if (result == MAELYS_GIT_OK)
                result = mg_store_enqueue(store, message.message_id, "command_result",
                                          stored_result, mg_now_ms(), error);
        }
    } else if (result == MAELYS_GIT_OK && state == MG_STORE_COMMAND_RUNNING) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "command is already running");
        result = MAELYS_GIT_ERR_PROTOCOL;
    } else if (result == MAELYS_GIT_OK) {
        if (state == MG_STORE_COMMAND_NEW || state == MG_STORE_COMMAND_PENDING)
            result = mg_store_mark_running(store, message.message_id, error);
        if (result == MAELYS_GIT_OK) {
            char *response = NULL;
            maelys_git_error_t executor_error = {0};
            int succeeded = 0;
            result = mg_supervisor_execute(config, &message, raw, &response, &succeeded, &executor_error);
            if (result != MAELYS_GIT_OK) {
                response = executor_failure(&message, executor_error.message);
                result = response ? MAELYS_GIT_OK : MAELYS_GIT_ERR_IO;
            }
            if (result == MAELYS_GIT_OK) {
                result = mg_store_complete_command(store, message.message_id, succeeded,
                                                   response, mg_now_ms(), error);
                free(response);
            }
        }
    }
    free(stored_result);
    mg_protocol_message_clear(&message);
    free(raw);
    return result;
}

static maelys_git_result_t poll_commands(cloud_clients_t *clients,
                                         const maelys_git_agent_config_t *config,
                                         maelys_git_agent_store_t *store,
                                         maelys_git_error_t *error) {
    char cursor[1024];
    maelys_git_result_t result = mg_store_get_cursor(store, cursor, sizeof(cursor), error);
    if (result != MAELYS_GIT_OK) return result;
    char encoded_agent[MG_AGENT_ID_MAX * 3u];
    char encoded_cursor[sizeof(cursor) * 3u];
    if (!percent_encode(config->agent_id, encoded_agent, sizeof(encoded_agent)) ||
        !percent_encode(cursor, encoded_cursor, sizeof(encoded_cursor))) return MAELYS_GIT_ERR_LIMIT;
    char target[MG_TARGET_MAX + sizeof(encoded_agent) + sizeof(encoded_cursor) + 64u];
    int count = snprintf(target, sizeof(target), "%s?agent_id=%s&cursor=%s&wait_ms=%llu",
                         config->command_target, encoded_agent, encoded_cursor,
                         (unsigned long long)config->poll_timeout_ms);
    if (count < 0 || (size_t)count >= sizeof(target)) return MAELYS_GIT_ERR_LIMIT;
    body_capture_t capture;
    unsigned status = 0u;
    uint64_t poll_deadline = config->poll_timeout_ms + config->request_timeout_ms;
    result = http_request(clients->commands, config, "GET", target, NULL, NULL,
                          poll_deadline, &status, &capture, error);
    if (result != MAELYS_GIT_OK) return result;
    if (status == 204u) return MAELYS_GIT_OK;
    if (status == 401u || status == 403u) {
        mg_error_set(error, MAELYS_GIT_ERR_DENIED, 0, "cloud rejected agent credentials");
        return MAELYS_GIT_ERR_DENIED;
    }
    if (status != 200u) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, (int)status, "command endpoint returned HTTP %u", status);
        return MAELYS_GIT_ERR_IO;
    }
    mg_agent_poll_t poll;
    result = mg_protocol_poll_parse((const char *)capture.bytes, capture.length, &poll, error);
    if (result != MAELYS_GIT_OK) return result;
    for (size_t index = 0u; index < poll.command_count; ++index) {
        json_t *command = json_array_get(poll.deduplication_commands, index);
        result = process_command(config, store, command, error);
        if (result != MAELYS_GIT_OK) {
            char event_id[1200];
            (void)snprintf(event_id, sizeof(event_id), "poll:%s:%zu",
                           poll.cursor.data, index);
            char *raw = json_dumps(command, JSON_COMPACT | JSON_ENSURE_ASCII | JSON_SORT_KEYS);
            if (raw) {
                maelys_git_error_t ignored = {0};
                (void)mg_store_audit(store, event_id, "command_rejected", raw,
                                     mg_now_ms(), &ignored);
                free(raw);
            }
            break;
        }
    }
    if (result == MAELYS_GIT_OK)
        result = mg_store_set_cursor(store, poll.cursor.data, error);
    mg_protocol_poll_clear(&poll);
    return result;
}

maelys_git_result_t mg_cloud_run(const maelys_git_agent_config_t *config,
                                 int run_once,
                                 maelys_git_error_t *error) {
    if (!config) return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    cloud_clients_t clients;
    maelys_git_result_t result = clients_create(config, &clients, error);
    if (result != MAELYS_GIT_OK) { clients_clear(&clients); return result; }
    maelys_git_agent_store_t *store = NULL;
    result = mg_store_open(config->database_path, &store, error);
    unsigned failures = 0u;
    while (result == MAELYS_GIT_OK) {
        maelys_git_error_t cycle_error = {0};
        maelys_git_result_t flush_result = flush_one(&clients, config, store, &cycle_error);
        maelys_git_result_t poll_result = poll_commands(&clients, config, store, &cycle_error);
        if (flush_result == MAELYS_GIT_ERR_DENIED || poll_result == MAELYS_GIT_ERR_DENIED) {
            result = MAELYS_GIT_ERR_DENIED;
            if (error) *error = cycle_error;
            break;
        }
        if (flush_result != MAELYS_GIT_OK || poll_result != MAELYS_GIT_OK) {
            ++failures;
            if (run_once) {
                result = flush_result != MAELYS_GIT_OK ? flush_result : poll_result;
                if (error) *error = cycle_error;
                break;
            }
            uint64_t delay = mg_retry_delay_ms(config->agent_id, failures, 500u, 60000u);
            struct timespec pause = {(time_t)(delay / 1000u), (long)(delay % 1000u) * 1000000L};
            (void)nanosleep(&pause, NULL);
        } else {
            failures = 0u;
            if (run_once) break;
        }
    }
    mg_store_close(store);
    clients_clear(&clients);
    return result;
}

maelys_git_result_t maelys_git_agent_run_cloud(const char *config_path,
                                                int run_once,
                                                maelys_git_error_t *error) {
    maelys_git_agent_config_t *config = NULL;
    maelys_git_result_t result = mg_config_load(config_path, &config, error);
    if (result == MAELYS_GIT_OK) result = mg_cloud_run(config, run_once, error);
    mg_config_free(config);
    return result;
}
