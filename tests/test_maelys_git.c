#include "maelys_git_agent.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 0; \
    } \
} while (0)

static int remove_tree(const char *path) {
    DIR *directory = opendir(path);
    if (!directory) return unlink(path) == 0;
    struct dirent *entry;
    int ok = 1;
    while ((entry = readdir(directory))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char child[4096];
        int count = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (count < 0 || (size_t)count >= sizeof(child)) { ok = 0; break; }
        struct stat status;
        if (lstat(child, &status) != 0) { ok = 0; break; }
        if (S_ISDIR(status.st_mode)) {
            if (!remove_tree(child)) ok = 0;
        } else if (unlink(child) != 0) {
            ok = 0;
        }
    }
    (void)closedir(directory);
    return rmdir(path) == 0 && ok;
}

static int test_repository_names(void) {
    CHECK(maelys_git_repository_name_is_valid("example.git"));
    CHECK(maelys_git_repository_name_is_valid("teams/platform/api.git"));
    CHECK(!maelys_git_repository_name_is_valid("../secret.git"));
    CHECK(!maelys_git_repository_name_is_valid("/absolute.git"));
    CHECK(!maelys_git_repository_name_is_valid("repo;id.git"));
    CHECK(!maelys_git_repository_name_is_valid("repo"));
    CHECK(maelys_git_ref_name_is_valid("refs/heads/main"));
    CHECK(!maelys_git_ref_name_is_valid("main"));
    CHECK(!maelys_git_ref_name_is_valid("refs/heads/../secret"));
    return 1;
}

static int test_ssh_parser(void) {
    maelys_git_error_t error;
    maelys_git_ssh_command_t command;
    CHECK(maelys_git_parse_ssh_command("git-upload-pack 'example.git'", &command, &error) == MAELYS_GIT_OK);
    CHECK(command.service == MAELYS_GIT_SERVICE_UPLOAD_PACK);
    CHECK(strcmp(command.repository, "example.git") == 0);
    CHECK(maelys_git_parse_ssh_command("git-receive-pack \"teams/a.git\"", &command, &error) == MAELYS_GIT_OK);
    CHECK(command.service == MAELYS_GIT_SERVICE_RECEIVE_PACK);
    CHECK(maelys_git_parse_ssh_command("git-upload-pack '../secret.git'", &command, &error) != MAELYS_GIT_OK);
    CHECK(maelys_git_parse_ssh_command("sh -c id", &command, &error) != MAELYS_GIT_OK);
    CHECK(maelys_git_parse_ssh_command("git-upload-pack 'example.git' extra", &command, &error) != MAELYS_GIT_OK);
    return 1;
}

static int authorize(maelys_git_policy_t *policy,
                     const char *user,
                     const char *operation,
                     const char *ref,
                     const char *path,
                     maelys_git_policy_decision_t *decision) {
    const char *paths[] = {path};
    maelys_git_policy_request_t request = {
        .request_id = "test",
        .principal = user,
        .repository = "example.git",
        .operation = operation,
        .ref_name = ref,
        .paths = path ? paths : NULL,
        .path_count = path ? 1u : 0u,
    };
    maelys_git_error_t error;
    maelys_git_result_t result = maelys_git_policy_authorize(policy, &request, decision, &error);
    if (result != MAELYS_GIT_OK) (void)fprintf(stderr, "authorize: %s\n", error.message);
    return result == MAELYS_GIT_OK;
}

static int test_policy(void) {
    maelys_git_error_t error;
    maelys_git_policy_t *policy = NULL;
    CHECK(maelys_git_policy_open(TEST_MANIFEST_FILE, &policy, &error) == MAELYS_GIT_OK);
    char policy_fingerprint[65];
    CHECK(maelys_git_policy_fingerprint(policy, policy_fingerprint, &error) == MAELYS_GIT_OK);
    CHECK(strlen(policy_fingerprint) == 64u);
    maelys_git_policy_decision_t decision;
    CHECK(authorize(policy, "alice", "read", NULL, NULL, &decision));
    CHECK(decision.allowed);
    CHECK(authorize(policy, "bob", "read", NULL, NULL, &decision));
    CHECK(decision.allowed);
    CHECK(authorize(policy, "mallory", "read", NULL, NULL, &decision));
    CHECK(!decision.allowed && !decision.explicit_deny);
    CHECK(authorize(policy, "bob", "push", "refs/heads/feature", NULL, &decision));
    CHECK(decision.allowed);
    CHECK(authorize(policy, "bob", "push", "refs/heads/main", NULL, &decision));
    CHECK(!decision.allowed && decision.explicit_deny);
    CHECK(authorize(policy, "bob", "push", "refs/heads/feature", "secrets/production.env", &decision));
    CHECK(!decision.allowed && decision.explicit_deny);
    CHECK(authorize(policy, "alice", "push", "refs/heads/main", "secrets/production.env", &decision));
    CHECK(decision.allowed);
    maelys_git_policy_close(policy);
    return 1;
}

static int test_repository_init(void) {
    char template[] = "/tmp/maelys_git_test_XXXXXX";
    char *root = mkdtemp(template);
    CHECK(root != NULL);
    maelys_git_error_t error;
    maelys_git_result_t result = maelys_git_repository_init_bare(
        "/usr/bin/git", root, "example.git", &error);
    if (result != MAELYS_GIT_OK) (void)fprintf(stderr, "repo init: %s\n", error.message);
    CHECK(result == MAELYS_GIT_OK);
    char resolved[4096];
    CHECK(maelys_git_resolve_repository(root, "example.git", resolved, sizeof(resolved), &error) == MAELYS_GIT_OK);
    CHECK(strstr(resolved, "/example.git") != NULL);
    CHECK(remove_tree(root));
    return 1;
}

static int test_agent_protocol(void) {
    maelys_git_error_t error;
    maelys_git_policy_t *policy = NULL;
    CHECK(maelys_git_policy_open(TEST_MANIFEST_FILE, &policy, &error) == MAELYS_GIT_OK);
    FILE *input = tmpfile();
    FILE *output = tmpfile();
    CHECK(input && output);
    long long now = (long long)time(NULL) * 1000LL;
    CHECK(fprintf(input, "{\"protocol\":\"maelys-git-agent/1\",\"message_id\":\"health-1\","
                         "\"agent_id\":\"agent-1\",\"type\":\"command\",\"command\":\"health\","
                         "\"issued_at_ms\":%lld,\"expires_at_ms\":%lld,\"payload\":{}}\n",
                         now, now + 60000LL) > 0);
    CHECK(fprintf(input, "{\"protocol\":\"maelys-git-agent/1\",\"message_id\":\"r1\","
                         "\"agent_id\":\"agent-1\",\"type\":\"command\",\"command\":\"authorize\","
                         "\"repository\":\"example.git\",\"principal\":\"alice\","
                         "\"issued_at_ms\":%lld,\"expires_at_ms\":%lld,"
                         "\"payload\":{\"operation\":\"read\"}}\n",
                         now, now + 60000LL) > 0);
    rewind(input);
    CHECK(maelys_git_agent_serve(policy, "/usr/bin/git", "/tmp", input, output, stderr, &error) == MAELYS_GIT_OK);
    rewind(output);
    char responses[2048];
    size_t count = fread(responses, 1u, sizeof(responses) - 1u, output);
    responses[count] = '\0';
    CHECK(strstr(responses, "\"command\":\"health\"") != NULL);
    CHECK(strstr(responses, "\"message_id\":\"r1\"") != NULL);
    CHECK(strstr(responses, "\"allowed\":true") != NULL);
    fclose(input);
    fclose(output);
    maelys_git_policy_close(policy);
    return 1;
}

static int test_post_receive_event(void) {
    FILE *input = tmpfile();
    FILE *events = tmpfile();
    CHECK(input && events);
    CHECK(fputs("0000000000000000000000000000000000000000 "
                "1111111111111111111111111111111111111111 refs/heads/main\n",
                input) >= 0);
    rewind(input);
    maelys_git_error_t error;
    CHECK(maelys_git_post_receive("example.git", "alice", input, events, &error) == MAELYS_GIT_OK);
    rewind(events);
    char event[1024];
    size_t count = fread(event, 1u, sizeof(event) - 1u, events);
    event[count] = '\0';
    CHECK(strstr(event, "\"type\":\"ref_updated\"") != NULL);
    CHECK(strstr(event, "\"principal\":\"alice\"") != NULL);
    CHECK(strstr(event, "\"ref\":\"refs/heads/main\"") != NULL);
    fclose(input);
    fclose(events);
    return 1;
}

static int test_receive_transaction(void) {
    FILE *input = tmpfile();
    CHECK(input != NULL);
    CHECK(fputs("0000000000000000000000000000000000000000 "
                "1111111111111111111111111111111111111111 refs/heads/topic\n"
                "2222222222222222222222222222222222222222 "
                "0000000000000000000000000000000000000000 refs/tags/v1\n", input) >= 0);
    rewind(input);
    maelys_git_receive_transaction_t transaction;
    maelys_git_error_t error;
    CHECK(maelys_git_receive_transaction_read(input, &transaction, &error) == MAELYS_GIT_OK);
    CHECK(transaction.update_count == 2u);
    CHECK(transaction.updates[0].ref_kind == MAELYS_GIT_REF_BRANCH);
    CHECK(transaction.updates[1].ref_kind == MAELYS_GIT_REF_TAG);
    CHECK(!strcmp(maelys_git_ref_kind_name(transaction.updates[0].ref_kind), "branch"));
    maelys_git_receive_transaction_clear(&transaction);
    fclose(input);
    return 1;
}

static int test_authorized_keys(void) {
    char template[] = "/tmp/maelys_git_keys_XXXXXX";
    char *root = mkdtemp(template);
    CHECK(root != NULL);
    char keys[4096], key[4096], output[4096], deploy[4096], deploy_item[4096];
    CHECK(snprintf(keys, sizeof(keys), "%s/keys", root) > 0);
    CHECK(snprintf(key, sizeof(key), "%s/alice.pub", keys) > 0);
    CHECK(snprintf(output, sizeof(output), "%s/authorized_keys", root) > 0);
    CHECK(mkdir(keys, 0700) == 0);
    CHECK(snprintf(deploy, sizeof(deploy), "%s/deploy", keys) > 0);
    CHECK(snprintf(deploy_item, sizeof(deploy_item), "%s/ci", deploy) > 0);
    CHECK(mkdir(deploy, 0700) == 0);
    CHECK(mkdir(deploy_item, 0700) == 0);
    FILE *file = fopen(key, "w");
    CHECK(file != NULL);
    CHECK(fputs("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFqswLrSefGZt4InrGnicUN4CuDKKMoZbafXI4nFavMT alice@test\n", file) >= 0);
    CHECK(fclose(file) == 0);
    const char *metadata_names[] = {"key.pub", "repository", "access"};
    const char *metadata_values[] = {
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFqswLrSefGZt4InrGnicUN4CuDKKMoZbafXI4nFavMT ci@test\n",
        "example.git\n", "read\n"};
    for (size_t i = 0u; i < 3u; ++i) {
        char metadata_path[4096];
        CHECK(snprintf(metadata_path, sizeof(metadata_path), "%s/%s",
                       deploy_item, metadata_names[i]) > 0);
        file = fopen(metadata_path, "w");
        CHECK(file != NULL);
        CHECK(fputs(metadata_values[i], file) >= 0);
        CHECK(fclose(file) == 0);
    }
    size_t count = 0u;
    maelys_git_error_t error;
    CHECK(maelys_git_compile_authorized_keys(keys, output, "/usr/local/bin/maelys-git-shell",
        "/srv/git", "/etc/maelys/policy.json", 0, &count, &error) == MAELYS_GIT_OK);
    CHECK(count == 2u && access(output, F_OK) != 0);
    CHECK(maelys_git_compile_authorized_keys(keys, output, "/usr/local/bin/maelys-git-shell",
        "/srv/git", "/etc/maelys/policy.json", 1, &count, &error) == MAELYS_GIT_OK);
    file = fopen(output, "r");
    CHECK(file != NULL);
    char line[2048];
    CHECK(fgets(line, sizeof(line), file) != NULL);
    CHECK(strstr(line, "restrict,command=\"") != NULL);
    CHECK(strstr(line, "--user alice") != NULL);
    CHECK(fgets(line, sizeof(line), file) != NULL);
    CHECK(strstr(line, "--user deploy-ci") != NULL);
    CHECK(strstr(line, "--restrict-repository example.git --read-only") != NULL);
    fclose(file);
    file = fopen(key, "w");
    CHECK(file != NULL);
    CHECK(fputs("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINotARealKey alice@test\n", file) >= 0);
    CHECK(fclose(file) == 0);
    CHECK(maelys_git_compile_authorized_keys(keys, output, "/usr/local/bin/maelys-git-shell",
        "/srv/git", "/etc/maelys/policy.json", 0, &count, &error) ==
        MAELYS_GIT_ERR_PROTOCOL);
    CHECK(remove_tree(root));
    return 1;
}

int main(void) {
    int passed = 0;
    passed += test_repository_names();
    passed += test_ssh_parser();
    passed += test_policy();
    passed += test_repository_init();
    passed += test_agent_protocol();
    passed += test_post_receive_event();
    passed += test_receive_transaction();
    passed += test_authorized_keys();
    if (passed != 8) return 1;
    (void)printf("ok: %d test groups passed\n", passed);
    return 0;
}
