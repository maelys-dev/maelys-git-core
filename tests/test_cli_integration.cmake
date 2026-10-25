if(NOT DEFINED MAELYS_GIT_BIN OR NOT DEFINED MAELYS_AGENT_BIN OR
   NOT DEFINED MAELYS_EXECUTOR_BIN OR NOT DEFINED MAELYS_SHELL_BIN OR
   NOT DEFINED MAELYS_HOOK_BIN OR NOT DEFINED TEST_MANIFEST)
  message(FATAL_ERROR "CLI integration paths are required")
endif()

set(test_root "${CMAKE_CURRENT_BINARY_DIR}/cli-contract-integration")
file(REMOVE_RECURSE "${test_root}")
file(MAKE_DIRECTORY "${test_root}")

function(run_json expected_code out_var err_var)
  execute_process(
    COMMAND ${ARGN}
    RESULT_VARIABLE code
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)
  if(NOT code EQUAL expected_code)
    message(FATAL_ERROR "Unexpected exit ${code}, expected ${expected_code}\nstdout=${stdout}\nstderr=${stderr}")
  endif()
  set(${out_var} "${stdout}" PARENT_SCOPE)
  set(${err_var} "${stderr}" PARENT_SCOPE)
endfunction()

run_json(0 describe_output describe_error
  "${MAELYS_GIT_BIN}" describe repo.init --format json --compact --non-interactive)
if(NOT describe_error STREQUAL "")
  message(FATAL_ERROR "describe wrote to stderr: ${describe_error}")
endif()
string(JSON describe_contract GET "${describe_output}" contract)
string(JSON describe_command GET "${describe_output}" command)
string(JSON described_usage GET "${describe_output}" data commands 0 usage)
string(JSON described_synopsis GET "${describe_output}" data commands 0 input synopsis)
string(JSON described_effect GET "${describe_output}" data commands 0 effect plan)
if(NOT describe_contract STREQUAL "agent-cli/v2" OR
   NOT describe_command STREQUAL "describe" OR
   NOT described_usage STREQUAL described_synopsis OR
   NOT described_effect STREQUAL "preview")
  message(FATAL_ERROR "describe contract drift: ${describe_output}")
endif()

run_json(1 unknown_stdout unknown_stderr
  "${MAELYS_GIT_BIN}" repos init --format json --compact)
if(NOT unknown_stdout STREQUAL "")
  message(FATAL_ERROR "failure polluted stdout: ${unknown_stdout}")
endif()
string(JSON unknown_ok GET "${unknown_stderr}" ok)
string(JSON unknown_code GET "${unknown_stderr}" error code)
if(unknown_ok OR NOT unknown_code STREQUAL "INVALID_COMMAND")
  message(FATAL_ERROR "invalid error envelope: ${unknown_stderr}")
endif()

set(repository_name "contract-test.git")
set(repository_path "${test_root}/${repository_name}")
run_json(0 plan_output plan_error
  "${MAELYS_GIT_BIN}" repo init "${test_root}" "${repository_name}"
  --format json --compact --non-interactive)
if(EXISTS "${repository_path}")
  message(FATAL_ERROR "default transaction wrote repository state")
endif()
string(JSON plan_mode GET "${plan_output}" data mode)
string(JSON plan_changed GET "${plan_output}" data changed)
if(NOT plan_mode STREQUAL "plan" OR plan_changed)
  message(FATAL_ERROR "invalid plan result: ${plan_output}")
endif()

run_json(0 apply_output apply_error
  "${MAELYS_GIT_BIN}" repo init "${test_root}" "${repository_name}"
  --apply --format json --compact --non-interactive)
if(NOT EXISTS "${repository_path}/HEAD")
  message(FATAL_ERROR "apply did not create the bare repository")
endif()
string(JSON apply_mode GET "${apply_output}" data mode)
string(JSON apply_changed GET "${apply_output}" data changed)
if(NOT apply_mode STREQUAL "apply" OR NOT apply_changed)
  message(FATAL_ERROR "invalid apply result: ${apply_output}")
endif()

set(invalid_manifest "${test_root}/invalid-manifest.json")
file(WRITE "${invalid_manifest}" "{}\n")
run_json(2 validation_output validation_error
  "${MAELYS_GIT_BIN}" validate "${invalid_manifest}" --format json --compact)
if(NOT validation_error STREQUAL "")
  message(FATAL_ERROR "validation report wrote to stderr: ${validation_error}")
endif()
string(JSON validation_ok GET "${validation_output}" ok)
string(JSON validation_valid GET "${validation_output}" data valid)
string(JSON validation_exit GET "${validation_output}" exitCode)
if(NOT validation_ok OR validation_valid OR NOT validation_exit EQUAL 2)
  message(FATAL_ERROR "invalid validation report: ${validation_output}")
endif()

file(WRITE "${test_root}/token" "test-token\n")
file(CHMOD "${test_root}/token" PERMISSIONS OWNER_READ OWNER_WRITE)
file(WRITE "${test_root}/ca.pem" "test-ca\n")
set(agent_config "${test_root}/agent.json")
run_json(0 provision_plan provision_plan_error
  "${MAELYS_AGENT_BIN}" provision --config "${agent_config}" --agent-id test-agent
  --authority forge.example.test --ca "${test_root}/ca.pem" --token "${test_root}/token"
  --database "${test_root}/agent.sqlite3" --manifest "${TEST_MANIFEST}"
  --root "${test_root}" --executor "${MAELYS_EXECUTOR_BIN}"
  --format json --compact --non-interactive)
if(EXISTS "${agent_config}")
  message(FATAL_ERROR "provision plan wrote configuration state")
endif()
run_json(0 provision_apply provision_apply_error
  "${MAELYS_AGENT_BIN}" provision --config "${agent_config}" --agent-id test-agent
  --authority forge.example.test --ca "${test_root}/ca.pem" --token "${test_root}/token"
  --database "${test_root}/agent.sqlite3" --manifest "${TEST_MANIFEST}"
  --root "${test_root}" --executor "${MAELYS_EXECUTOR_BIN}" --apply
  --format json --compact --non-interactive)
if(NOT EXISTS "${agent_config}")
  message(FATAL_ERROR "provision apply did not create configuration")
endif()

# GIT-C06: --grants writes grants_path, and the plan names it.
file(WRITE "${test_root}/grants.json" "{}")
set(grants_config "${test_root}/agent-grants.json")
foreach(step plan apply)
  set(apply_flag "")
  if(step STREQUAL "apply")
    set(apply_flag "--apply")
  endif()
  run_json(0 provision_grants provision_grants_error
    "${MAELYS_AGENT_BIN}" provision --config "${grants_config}" --agent-id test-agent
    --authority forge.example.test --ca "${test_root}/ca.pem" --token "${test_root}/token"
    --database "${test_root}/agent.sqlite3" --manifest "${TEST_MANIFEST}"
    --grants "${test_root}/grants.json" --root "${test_root}" --executor "${MAELYS_EXECUTOR_BIN}"
    ${apply_flag} --format json --compact --non-interactive)
  string(JSON provision_grants_path GET "${provision_grants}" data grants)
  if(NOT provision_grants_path STREQUAL "${test_root}/grants.json")
    message(FATAL_ERROR "provision does not name its grants: ${provision_grants}")
  endif()
endforeach()
file(READ "${grants_config}" grants_config_text)
string(JSON configured_grants GET "${grants_config_text}" grants_path)
if(NOT configured_grants STREQUAL "${test_root}/grants.json")
  message(FATAL_ERROR "provision --grants did not write grants_path: ${grants_config_text}")
endif()

# The purge of the store: a plan with the catalog's defaults, nothing kept yet.
run_json(0 prune_plan prune_plan_error
  "${MAELYS_AGENT_BIN}" grants-store prune --config "${grants_config}"
  --format json --compact --non-interactive)
string(JSON prune_mode GET "${prune_plan}" data mode)
string(JSON prune_keep GET "${prune_plan}" data keep)
string(JSON prune_age GET "${prune_plan}" data olderThanMs)
string(JSON prune_entries LENGTH "${prune_plan}" data entries)
if(NOT prune_mode STREQUAL "plan" OR NOT prune_keep EQUAL 16 OR NOT prune_age EQUAL 7776000000 OR
   NOT prune_entries EQUAL 0)
  message(FATAL_ERROR "grants-store prune plan is not the expected one: ${prune_plan}")
endif()
run_json(1 prune_bad prune_bad_error
  "${MAELYS_AGENT_BIN}" grants-store prune --config "${grants_config}" --older-than 90
  --format json --compact --non-interactive)
if(NOT prune_bad_error MATCHES "older-than")
  message(FATAL_ERROR "a duration without unit was not refused: ${prune_bad_error}")
endif()

run_json(0 shell_describe shell_describe_error
  "${MAELYS_SHELL_BIN}" describe serve --format json --compact)
string(JSON shell_mode GET "${shell_describe}" data commands 0 outputMode)
string(JSON shell_protocol GET "${shell_describe}" data commands 0 protocol)
string(JSON shell_framework GET "${shell_describe}" data framework)
if(NOT shell_mode STREQUAL "protocol-stream" OR NOT shell_protocol STREQUAL "git-smart" OR
   shell_framework STREQUAL "")
  message(FATAL_ERROR "shell stream contract missing: ${shell_describe}")
endif()

run_json(1 stream_stdout stream_stderr
  "${MAELYS_EXECUTOR_BIN}" serve --manifest "${TEST_MANIFEST}" --root "${test_root}"
  --format json)
if(NOT stream_stdout STREQUAL "" OR NOT stream_stderr MATCHES "stream command")
  message(FATAL_ERROR "stream rendering boundary failed: stdout=${stream_stdout} stderr=${stream_stderr}")
endif()

# A stream fails on stderr only: the text line by default, and the JSON
# failure envelope when MAELYS_CLI_FORMAT=json asks for it.
function(check_stream_failure label command_id expected_code text_prefix)
  set(clean_env "${CMAKE_COMMAND}" -E env --unset=MAELYS_CLI_FORMAT
    --unset=SSH_ORIGINAL_COMMAND --unset=MAELYS_GIT_PRINCIPAL)
  run_json(1 text_stdout text_stderr ${clean_env} ${ARGN})
  string(FIND "${text_stderr}" "${text_prefix}" text_at)
  if(NOT text_stdout STREQUAL "" OR NOT text_at EQUAL 0)
    message(FATAL_ERROR "${label}: text failure drift: stdout=${text_stdout} stderr=${text_stderr}")
  endif()
  run_json(1 json_stdout json_stderr ${clean_env} MAELYS_CLI_FORMAT=json ${ARGN})
  if(NOT json_stdout STREQUAL "")
    message(FATAL_ERROR "${label}: JSON failure polluted stdout: ${json_stdout}")
  endif()
  string(JSON json_contract ERROR_VARIABLE json_invalid GET "${json_stderr}" contract)
  if(json_invalid)
    message(FATAL_ERROR "${label}: stderr is not a JSON envelope: ${json_stderr}")
  endif()
  string(JSON json_command GET "${json_stderr}" command)
  string(JSON json_ok GET "${json_stderr}" ok)
  string(JSON json_exit GET "${json_stderr}" exitCode)
  string(JSON json_code GET "${json_stderr}" error code)
  string(JSON json_message GET "${json_stderr}" error message)
  string(JSON json_hint GET "${json_stderr}" error hint)
  if(NOT json_contract STREQUAL "agent-cli/v2" OR NOT json_command STREQUAL command_id OR
     json_ok OR NOT json_exit EQUAL 1 OR NOT json_code STREQUAL expected_code OR
     json_message STREQUAL "" OR json_hint STREQUAL "")
    message(FATAL_ERROR "${label}: invalid stream failure envelope: ${json_stderr}")
  endif()
endfunction()

check_stream_failure(executor serve POLICY_FAILED
  "maelys-git-executor stream error [policy_error]: policy load failed"
  "${MAELYS_EXECUTOR_BIN}" serve --manifest "${test_root}/absent-manifest.json"
  --root "${test_root}")
check_stream_failure(shell serve VALIDATION_FAILED
  "maelys-git-shell stream error [invalid_argument]: SSH_ORIGINAL_COMMAND is missing"
  "${MAELYS_SHELL_BIN}" serve --user alice --root "${test_root}"
  --manifest "${TEST_MANIFEST}")
check_stream_failure(pre-receive pre-receive VALIDATION_FAILED
  "maelys-git-hook pre-receive error [invalid_argument]: principal is missing"
  "${MAELYS_HOOK_BIN}" pre-receive --repository example.git
  --manifest "${TEST_MANIFEST}")
check_stream_failure(post-receive post-receive VALIDATION_FAILED
  "maelys-git-hook post-receive error [invalid_argument]: principal is missing"
  "${MAELYS_HOOK_BIN}" post-receive --repository example.git)

file(REMOVE_RECURSE "${test_root}")
