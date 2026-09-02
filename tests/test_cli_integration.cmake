if(NOT DEFINED MAELYS_GIT_BIN OR NOT DEFINED MAELYS_AGENT_BIN OR
   NOT DEFINED MAELYS_EXECUTOR_BIN OR NOT DEFINED MAELYS_SHELL_BIN OR
   NOT DEFINED TEST_MANIFEST)
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

file(REMOVE_RECURSE "${test_root}")
