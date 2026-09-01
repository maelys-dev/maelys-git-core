#include "internal.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    char *principal;
    char *key;
} key_entry_t;

static void free_entries(key_entry_t *entries, size_t count) {
    for (size_t i = 0u; i < count; ++i) {
        free(entries[i].principal);
        free(entries[i].key);
    }
    free(entries);
}

static int compare_entries(const void *left, const void *right) {
    const key_entry_t *a = left;
    const key_entry_t *b = right;
    int principal = strcmp(a->principal, b->principal);
    return principal ? principal : strcmp(a->key, b->key);
}

static int safe_word(const char *value) {
    if (!value || !*value) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-')) return 0;
    return 1;
}

static int safe_quoted_value(const char *value) {
    if (!value || value[0] != '/') return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (!(isalnum(*p) || *p == '/' || *p == '.' || *p == '_' || *p == '-')) return 0;
    return 1;
}

static int supported_key_type(const char *type, size_t length) {
    static const char *types[] = {
        "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"};
    for (size_t i = 0u; i < sizeof(types) / sizeof(types[0]); ++i)
        if (strlen(types[i]) == length && memcmp(type, types[i], length) == 0) return 1;
    return 0;
}

static int base64_value(unsigned char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

static int read_ssh_field(const unsigned char *blob,
                          size_t blob_length,
                          size_t *offset,
                          const unsigned char **out_data,
                          size_t *out_length) {
    if (*offset > blob_length || blob_length - *offset < 4u) return 0;
    const unsigned char *length_bytes = blob + *offset;
    size_t length = ((size_t)length_bytes[0] << 24u) |
                    ((size_t)length_bytes[1] << 16u) |
                    ((size_t)length_bytes[2] << 8u) |
                    (size_t)length_bytes[3];
    *offset += 4u;
    if (length > blob_length - *offset) return 0;
    *out_data = blob + *offset;
    *out_length = length;
    *offset += length;
    return 1;
}

static int validate_decoded_key(const char *type,
                                size_t type_length,
                                const unsigned char *decoded,
                                size_t decoded_length) {
    size_t offset = 0u;
    const unsigned char *field = NULL;
    size_t field_length = 0u;
    if (!read_ssh_field(decoded, decoded_length, &offset, &field, &field_length) ||
        field_length != type_length || memcmp(field, type, type_length) != 0)
        return 0;
    if (type_length == strlen("ssh-ed25519") && !memcmp(type, "ssh-ed25519", type_length))
        return read_ssh_field(decoded, decoded_length, &offset, &field, &field_length) &&
               field_length == 32u && offset == decoded_length;
    if (type_length == strlen("ssh-rsa") && !memcmp(type, "ssh-rsa", type_length)) {
        const unsigned char *modulus = NULL;
        size_t modulus_length = 0u;
        if (!read_ssh_field(decoded, decoded_length, &offset, &field, &field_length) ||
            field_length == 0u || field_length > sizeof(uint64_t) ||
            (field_length > 1u && field[0] == 0u && !(field[1] & 0x80u)))
            return 0;
        uint64_t exponent = 0u;
        for (size_t i = 0u; i < field_length; ++i)
            exponent = (exponent << 8u) | field[i];
        if (exponent < 3u || !(exponent & 1u) ||
            !read_ssh_field(decoded, decoded_length, &offset,
                            &modulus, &modulus_length) ||
            modulus_length == 0u || offset != decoded_length)
            return 0;
        if (modulus[0] == 0u) {
            if (modulus_length < 2u || !(modulus[1] & 0x80u)) return 0;
            ++modulus;
            --modulus_length;
        } else if (modulus[0] & 0x80u) {
            return 0;
        }
        return modulus_length >= 256u && (modulus[0] & 0x80u);
    }
    if (!strncmp(type, "ecdsa-sha2-", strlen("ecdsa-sha2-"))) {
        const char *curve = type + strlen("ecdsa-sha2-");
        size_t curve_length = type_length - strlen("ecdsa-sha2-");
        const unsigned char *point = NULL;
        size_t point_length = 0u;
        size_t expected_point_length =
            curve_length == strlen("nistp256") && !memcmp(curve, "nistp256", curve_length) ? 65u :
            curve_length == strlen("nistp384") && !memcmp(curve, "nistp384", curve_length) ? 97u :
            curve_length == strlen("nistp521") && !memcmp(curve, "nistp521", curve_length) ? 133u : 0u;
        return expected_point_length &&
               read_ssh_field(decoded, decoded_length, &offset, &field, &field_length) &&
               field_length == curve_length && !memcmp(field, curve, curve_length) &&
               read_ssh_field(decoded, decoded_length, &offset, &point, &point_length) &&
               point_length == expected_point_length && point[0] == 4u &&
               offset == decoded_length;
    }
    if (type_length == strlen("sk-ssh-ed25519@openssh.com") &&
        !memcmp(type, "sk-ssh-ed25519@openssh.com", type_length)) {
        const unsigned char *application = NULL;
        size_t application_length = 0u;
        return read_ssh_field(decoded, decoded_length, &offset, &field, &field_length) &&
               field_length == 32u &&
               read_ssh_field(decoded, decoded_length, &offset, &application, &application_length) &&
               application_length > 0u && offset == decoded_length;
    }
    if (type_length == strlen("sk-ecdsa-sha2-nistp256@openssh.com") &&
        !memcmp(type, "sk-ecdsa-sha2-nistp256@openssh.com", type_length)) {
        const unsigned char *point = NULL, *application = NULL;
        size_t point_length = 0u, application_length = 0u;
        return read_ssh_field(decoded, decoded_length, &offset, &field, &field_length) &&
               field_length == strlen("nistp256") && !memcmp(field, "nistp256", field_length) &&
               read_ssh_field(decoded, decoded_length, &offset, &point, &point_length) &&
               point_length == 65u && point[0] == 4u &&
               read_ssh_field(decoded, decoded_length, &offset, &application, &application_length) &&
               application_length > 0u && offset == decoded_length;
    }
    return 0;
}

static int validate_key_blob(const char *line) {
    const char *type_end = strchr(line, ' ');
    if (!type_end) return 0;
    size_t type_length = (size_t)(type_end - line);
    if (!supported_key_type(line, type_length)) return 0;
    const char *encoded = type_end + 1u;
    const char *encoded_end = strchr(encoded, ' ');
    if (!encoded_end) encoded_end = encoded + strlen(encoded);
    size_t encoded_length = (size_t)(encoded_end - encoded);
    if (encoded_length < 8u || encoded_length > 16384u || encoded_length % 4u == 1u)
        return 0;
    size_t decoded_capacity = encoded_length * 3u / 4u + 3u;
    unsigned char *decoded = malloc(decoded_capacity);
    if (!decoded) return 0;
    size_t decoded_length = 0u;
    unsigned int accumulator = 0u;
    unsigned int bits = 0u;
    size_t padding = 0u;
    int valid = 1;
    for (size_t i = 0u; i < encoded_length; ++i) {
        unsigned char ch = (unsigned char)encoded[i];
        if (ch == '=') {
            ++padding;
            if (padding > 2u) valid = 0;
            continue;
        }
        if (padding) { valid = 0; break; }
        int value = base64_value(ch);
        if (value < 0) { valid = 0; break; }
        accumulator = (accumulator << 6u) | (unsigned int)value;
        bits += 6u;
        if (bits >= 8u) {
            bits -= 8u;
            decoded[decoded_length++] = (unsigned char)(accumulator >> bits);
            accumulator &= bits ? ((1u << bits) - 1u) : 0u;
        }
    }
    if (padding && encoded_length % 4u != 0u) valid = 0;
    if (bits && accumulator != 0u) valid = 0;
    if (decoded_length < 5u) valid = 0;
    if (valid) valid = validate_decoded_key(line, type_length, decoded, decoded_length);
    free(decoded);
    return valid;
}

static char *read_key(const char *path, maelys_git_error_t *error) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot read key %s: %s", path, strerror(errno));
        return NULL;
    }
    char buffer[16385];
    size_t length = fread(buffer, 1u, sizeof(buffer) - 1u, file);
    int failed = ferror(file);
    int overflow = !feof(file);
    fclose(file);
    if (failed || overflow) {
        mg_error_set(error, MAELYS_GIT_ERR_LIMIT, 0, "SSH key file is too large: %s", path);
        return NULL;
    }
    buffer[length] = '\0';
    while (length && (buffer[length - 1u] == '\n' || buffer[length - 1u] == '\r'))
        buffer[--length] = '\0';
    if (!length || strchr(buffer, '\n') || strchr(buffer, '\r') || !validate_key_blob(buffer)) {
        mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "invalid SSH public key: %s", path);
        return NULL;
    }
    return strdup(buffer);
}

static maelys_git_result_t load_entries(const char *directory,
                                        key_entry_t **out_entries,
                                        size_t *out_count,
                                        maelys_git_error_t *error) {
    DIR *dir = opendir(directory);
    if (!dir) {
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot open key directory: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    key_entry_t *entries = NULL;
    size_t count = 0u, capacity = 0u;
    struct dirent *entry;
    maelys_git_result_t result = MAELYS_GIT_OK;
    while ((entry = readdir(dir)) != NULL) {
        size_t length = strlen(entry->d_name);
        if (length <= 4u || strcmp(entry->d_name + length - 4u, ".pub") != 0) continue;
        char principal[NAME_MAX + 1u];
        if (length - 4u >= sizeof(principal)) { result = MAELYS_GIT_ERR_LIMIT; break; }
        memcpy(principal, entry->d_name, length - 4u);
        principal[length - 4u] = '\0';
        if (!safe_word(principal)) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, 0, "unsafe SSH key filename: %s", entry->d_name);
            result = MAELYS_GIT_ERR_PROTOCOL;
            break;
        }
        char path[PATH_MAX];
        int written = snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        if (written < 0 || (size_t)written >= sizeof(path)) { result = MAELYS_GIT_ERR_LIMIT; break; }
        struct stat status;
        if (lstat(path, &status) != 0 || !S_ISREG(status.st_mode)) {
            mg_error_set(error, MAELYS_GIT_ERR_PROTOCOL, errno, "SSH key must be a regular file: %s", path);
            result = MAELYS_GIT_ERR_PROTOCOL;
            break;
        }
        char *key = read_key(path, error);
        if (!key) { result = error->code; break; }
        if (count == capacity) {
            size_t next = capacity ? capacity * 2u : 16u;
            key_entry_t *grown = realloc(entries, next * sizeof(*grown));
            if (!grown) { free(key); result = MAELYS_GIT_ERR_IO; break; }
            entries = grown;
            capacity = next;
        }
        entries[count].principal = strdup(principal);
        entries[count].key = key;
        if (!entries[count].principal) { free(key); result = MAELYS_GIT_ERR_IO; break; }
        ++count;
    }
    closedir(dir);
    if (result != MAELYS_GIT_OK) { free_entries(entries, count); return result; }
    qsort(entries, count, sizeof(*entries), compare_entries);
    *out_entries = entries;
    *out_count = count;
    return MAELYS_GIT_OK;
}

maelys_git_result_t maelys_git_compile_authorized_keys(
    const char *key_directory,
    const char *output_path,
    const char *shell_path,
    const char *repository_root,
    const char *manifest_path,
    int apply,
    size_t *out_key_count,
    maelys_git_error_t *error) {
    maelys_git_error_clear(error);
    if (!key_directory || !output_path || !safe_quoted_value(shell_path) ||
        !safe_quoted_value(repository_root) || !safe_quoted_value(manifest_path) || !out_key_count)
        return MAELYS_GIT_ERR_INVALID_ARGUMENT;
    key_entry_t *entries = NULL;
    size_t count = 0u;
    maelys_git_result_t result = load_entries(key_directory, &entries, &count, error);
    if (result != MAELYS_GIT_OK) return result;
    *out_key_count = count;
    if (!apply) { free_entries(entries, count); return MAELYS_GIT_OK; }

    char temporary[PATH_MAX];
    int written = snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX", output_path);
    if (written < 0 || (size_t)written >= sizeof(temporary)) {
        free_entries(entries, count);
        return MAELYS_GIT_ERR_LIMIT;
    }
    int descriptor = mkstemp(temporary);
    if (descriptor < 0) {
        free_entries(entries, count);
        mg_error_set(error, MAELYS_GIT_ERR_IO, errno, "cannot create authorized_keys transaction: %s", strerror(errno));
        return MAELYS_GIT_ERR_IO;
    }
    FILE *output = fdopen(descriptor, "w");
    if (!output) { close(descriptor); unlink(temporary); free_entries(entries, count); return MAELYS_GIT_ERR_IO; }
    for (size_t i = 0u; i < count; ++i) {
        if (fprintf(output,
                    "restrict,command=\"%s serve --user %s --root %s --manifest %s\" %s\n",
                    shell_path, entries[i].principal, repository_root, manifest_path,
                    entries[i].key) < 0) {
            result = MAELYS_GIT_ERR_IO;
            break;
        }
    }
    if (result == MAELYS_GIT_OK && fflush(output) != 0) result = MAELYS_GIT_ERR_IO;
    if (result == MAELYS_GIT_OK && fchmod(descriptor, 0600) != 0) result = MAELYS_GIT_ERR_IO;
    if (result == MAELYS_GIT_OK && fsync(descriptor) != 0) result = MAELYS_GIT_ERR_IO;
    if (fclose(output) != 0 && result == MAELYS_GIT_OK) result = MAELYS_GIT_ERR_IO;
    if (result == MAELYS_GIT_OK && rename(temporary, output_path) != 0) result = MAELYS_GIT_ERR_IO;
    if (result != MAELYS_GIT_OK) {
        unlink(temporary);
        mg_error_set(error, result, errno, "authorized_keys update failed: %s", strerror(errno));
    }
    free_entries(entries, count);
    return result;
}
