cmake_minimum_required(VERSION 3.20)
project(maelys_git_core VERSION 0.1.0 LANGUAGES C)

find_package(Python3 QUIET COMPONENTS Interpreter)
find_program(MAELYS_MAKE_PROGRAM NAMES gmake make REQUIRED
    DOC "POSIX make used to build the sibling Maelys source trees")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(MAELYS_GIT_BUILD_TESTS "Build the Maelys Git tests" ON)
option(MAELYS_GIT_ENABLE_CLOUD_AGENT "Build the HTTPS Cloud agent" ON)
option(MAELYS_GIT_WERROR "Treat compiler warnings as errors" OFF)
option(MAELYS_GIT_DATALOG_PROFILE_LARGE "Build the policy engine with its LARGE size profile" OFF)
include(cmake/dependencies.cmake)
set(MAELYS_DATALOG_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../maelys-datalog"
    CACHE PATH "Path to the maelys-datalog source tree")
set(MAELYS_CLI_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../maelys-cli"
    CACHE PATH "Path to the maelys-cli source tree (used when no installed copy is found)")
set(MAELYS_JSON_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../maelys-json"
    CACHE PATH "Path to the maelys-json source tree")
set(MAELYS_HTTP_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../maelys-http"
    CACHE PATH "Path to the maelys-http source tree")
set(MAELYS_SYSTEM_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../maelys-system"
    CACHE PATH "Path to the maelys-system source tree")

find_package(PkgConfig REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

# ---- shared compilation contract -------------------------------------------
# One interface target carries the feature macros and the warning set so that
# every library, executable and test compiles under the same rules.
add_library(maelys_git_build_flags INTERFACE)
target_compile_definitions(maelys_git_build_flags INTERFACE _POSIX_C_SOURCE=200809L)
if(APPLE)
    target_compile_definitions(maelys_git_build_flags INTERFACE _DARWIN_C_SOURCE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(maelys_git_build_flags INTERFACE _DEFAULT_SOURCE)
endif()
target_compile_options(maelys_git_build_flags INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Wmissing-prototypes
    -Wformat=2 -Wvla -Wundef -Wpointer-arith -Wconversion)
if(MAELYS_GIT_WERROR)
    target_compile_options(maelys_git_build_flags INTERFACE -Werror)
endif()

# ---- maelys-datalog ---------------------------------------------------------
maelys_git_resolve_dependency(DATALOG MAELYS_DATALOG_SOURCE_DIR)
if(NOT EXISTS "${MAELYS_DATALOG_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "maelys-datalog was not found at ${MAELYS_DATALOG_SOURCE_DIR}; "
        "set MAELYS_DATALOG_SOURCE_DIR")
endif()
# The Datalog tree is built EXCLUDE_FROM_ALL for its library only; its own
# test registration (include(CTest)) is disabled in that scope.
set(BUILD_TESTING OFF)
set(MAELYS_DATALOG_PROFILE_LARGE ${MAELYS_GIT_DATALOG_PROFILE_LARGE} CACHE BOOL
    "Build with the LARGE Datalog size profile" FORCE)
add_subdirectory("${MAELYS_DATALOG_SOURCE_DIR}"
                 "${CMAKE_CURRENT_BINARY_DIR}/maelys-datalog"
                 EXCLUDE_FROM_ALL)
unset(BUILD_TESTING)
# The pinned Datalog sources use POSIX strnlen under strict C11.
target_compile_definitions(maelys_datalog PRIVATE _POSIX_C_SOURCE=200809L)

# ---- maelys-cli -------------------------------------------------------------
# The shared CLI framework comes from an installed CMake package
# (find_package) or, by default, from the sibling source tree added as a
# subdirectory. Both provide the dependency-free maelys::cli target; the
# embed and reference tools are located next to the sources in the
# subdirectory case. Keep the exact tested version so describe output and
# generated documentation cannot drift with an installed framework update.
find_package(maelys-cli ${MAELYS_GIT_CLI_VERSION} EXACT QUIET CONFIG)
if(maelys-cli_FOUND)
    message(STATUS "Using installed maelys-cli ${maelys-cli_VERSION}")
else()
    maelys_git_resolve_dependency(CLI MAELYS_CLI_SOURCE_DIR)
    if(NOT EXISTS "${MAELYS_CLI_SOURCE_DIR}/CMakeLists.txt")
        message(FATAL_ERROR
            "maelys-cli was not found: install it (find_package(maelys-cli)) or set "
            "MAELYS_CLI_SOURCE_DIR to its source tree")
    endif()
    # Core only: git-core manages its own JSON dependency separately.
    set(MAELYS_CLI_BUILD_DISPATCHER OFF)
    set(MAELYS_CLI_BUILD_EXTENSION OFF)
    set(MAELYS_CLI_BUILD_TESTS OFF)
    add_subdirectory("${MAELYS_CLI_SOURCE_DIR}"
                     "${CMAKE_CURRENT_BINARY_DIR}/maelys-cli"
                     EXCLUDE_FROM_ALL)
    unset(MAELYS_CLI_BUILD_DISPATCHER)
    unset(MAELYS_CLI_BUILD_EXTENSION)
    unset(MAELYS_CLI_BUILD_TESTS)
    set(MAELYS_CLI_EMBED "${MAELYS_CLI_SOURCE_DIR}/tools/maelys-cli-embed")
    set(MAELYS_CLI_REFERENCE "${MAELYS_CLI_SOURCE_DIR}/tools/generate_cli_reference.py")
    message(STATUS "Using maelys-cli source tree ${MAELYS_CLI_SOURCE_DIR}")
endif()
foreach(tool IN ITEMS MAELYS_CLI_EMBED MAELYS_CLI_REFERENCE)
    if(NOT EXISTS "${${tool}}")
        message(FATAL_ERROR "${tool} was not found at ${${tool}}")
    endif()
endforeach()

# ---- maelys-json ------------------------------------------------------------
# The one JSON library: the pinned, bounded reader of external documents and
# the writer of every document the programs produce.
maelys_git_resolve_dependency(JSON MAELYS_JSON_SOURCE_DIR)
if(NOT EXISTS "${MAELYS_JSON_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "maelys-json was not found at ${MAELYS_JSON_SOURCE_DIR}; set MAELYS_JSON_SOURCE_DIR")
endif()
set(MAELYS_JSON_BUILD_TESTS OFF)
set(MAELYS_JSON_WERROR ${MAELYS_GIT_WERROR})
add_subdirectory("${MAELYS_JSON_SOURCE_DIR}"
                 "${CMAKE_CURRENT_BINARY_DIR}/maelys-json" EXCLUDE_FROM_ALL)
unset(MAELYS_JSON_BUILD_TESTS)
unset(MAELYS_JSON_WERROR)

# ---- core library -----------------------------------------------------------
add_library(maelys_git_core STATIC
    src/common/error.c
    src/common/fs.c
    src/common/process.c
    src/common/strings.c
    src/shell/command.c
    src/policy/policy.c
    src/policy/grants.c
    src/policy/refex.c
    src/policy/program.c
    src/policy/slice.c
    src/repository/repository.c
    src/repository/lifecycle.c
    src/repository/mirror.c
    src/repository/transaction.c
    src/repository/pull_request.c
    src/repository/keys.c
    src/repository/gitolite.c
    src/hooks/pre_receive.c)
target_include_directories(maelys_git_core
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
# The engine is reached through its installed SDK headers only, and SHA-256
# comes from the public digest of the dependency-free CLI framework core.
target_link_libraries(maelys_git_core
    PUBLIC maelys_datalog
    PRIVATE maelys::cli maelys::json Threads::Threads maelys_git_build_flags)

# Authorization receipts: their only writer and reader, on maelys-json. The
# policy core builds the receipt structure and stays without JSON.
add_library(maelys_git_receipt STATIC src/receipt/receipt.c)
target_include_directories(maelys_git_receipt
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(maelys_git_receipt
    PUBLIC maelys_git_core maelys::json maelys::cli
    PRIVATE maelys_git_build_flags)

# The writer of every other JSON document: data of the command line, lines of
# the agent protocol, deduplication forms and generated configuration.
add_library(maelys_git_json STATIC src/common/json_write.c)
target_include_directories(maelys_git_json
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(maelys_git_json
    PUBLIC maelys_git_core maelys::json
    PRIVATE maelys_git_build_flags)

add_library(maelys_git_agent_core STATIC
    src/protocol/protocol.c
    src/agent/config.c
    src/agent/store.c
    src/agent/retry.c
    src/agent/executor.c
    src/agent/grants_store.c
    src/agent/agent.c)
target_include_directories(maelys_git_agent_core
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(maelys_git_agent_core
    PUBLIC maelys_git_core maelys_git_receipt maelys_git_json maelys::json
    PRIVATE SQLite::SQLite3 maelys_git_build_flags)

# ---- command-line interface -------------------------------------------------
# Output schemas are plain JSON Schema files embedded at build time; the C
# catalogs reference the generated symbols and never carry escaped JSON.
set(MAELYS_GIT_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(GLOB MAELYS_GIT_SCHEMAS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/schemas/*.json")
file(MAKE_DIRECTORY "${MAELYS_GIT_GENERATED_DIR}")
foreach(kind IN ITEMS c h)
    set(header OFF)
    if(kind STREQUAL "h")
        set(header ON)
    endif()
    add_custom_command(
        OUTPUT "${MAELYS_GIT_GENERATED_DIR}/maelys_git_schemas.${kind}"
        COMMAND ${CMAKE_COMMAND}
            -DEMBED=${MAELYS_CLI_EMBED}
            -DSCHEMAS=${CMAKE_CURRENT_SOURCE_DIR}/schemas
            -DOUTPUT=${MAELYS_GIT_GENERATED_DIR}/maelys_git_schemas.${kind}
            -DHEADER=${header}
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed.cmake"
        DEPENDS ${MAELYS_GIT_SCHEMAS} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed.cmake"
                "${MAELYS_CLI_EMBED}"
        COMMENT "Embedding CLI output schemas (${kind})"
        VERBATIM)
endforeach()

# Shared product CLI support plus the two stream-only programs. This library
# writes no JSON of its own so the SSH shell and receive hook stay lean.
add_library(maelys_git_cli STATIC
    src/cli/support.c
    src/cli/shell.c
    src/cli/hook.c
    "${MAELYS_GIT_GENERATED_DIR}/maelys_git_schemas.c"
    "${MAELYS_GIT_GENERATED_DIR}/maelys_git_schemas.h")
target_include_directories(maelys_git_cli
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src" "${MAELYS_GIT_GENERATED_DIR}")
target_link_libraries(maelys_git_cli
    PUBLIC maelys_git_core maelys_git_receipt maelys::cli
    PRIVATE maelys_git_build_flags)

# Administrative commands of `maelys-git`; maelys-json writes their data.
add_library(maelys_git_cli_admin STATIC
    src/cli/json_support.c
    src/cli/admin.c)
target_include_directories(maelys_git_cli_admin
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src" "${MAELYS_GIT_GENERATED_DIR}")
target_link_libraries(maelys_git_cli_admin
    PUBLIC maelys_git_cli maelys_git_json
    PRIVATE maelys_git_build_flags)

# Agent and executor commands.
add_library(maelys_git_cli_agent STATIC src/cli/agent.c)
target_include_directories(maelys_git_cli_agent
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src" "${MAELYS_GIT_GENERATED_DIR}")
target_link_libraries(maelys_git_cli_agent
    PUBLIC maelys_git_cli_admin maelys_git_agent_core
    PRIVATE maelys_git_build_flags)

set(MAELYS_GIT_PROGRAMS maelys-git maelys-git-agent maelys-git-executor
    maelys-git-shell maelys-git-hook)
# Wording of the generated reference belongs to the product.
set(MAELYS_GIT_REFERENCE_ARGS
    --neutral-availability run
    --title "Référence des CLI Maelys Git Core"
    --intro-file "${CMAKE_CURRENT_SOURCE_DIR}/docs/cli-reference-intro.md"
    --columns "Identifiant|Usage|Effet|Sortie|But"
    --global-label "Options globales :")

add_executable(maelys-git cmd/maelys-git/main.c)
target_link_libraries(maelys-git PRIVATE maelys_git_cli_admin maelys_git_build_flags)

add_executable(maelys-git-shell cmd/maelys-git-shell/main.c)
target_link_libraries(maelys-git-shell PRIVATE maelys_git_cli maelys_git_build_flags)

add_executable(maelys-git-hook cmd/maelys-git-hook/main.c)
target_link_libraries(maelys-git-hook PRIVATE maelys_git_cli maelys_git_build_flags)

add_executable(maelys-git-agent cmd/maelys-git-agent/main.c)
target_link_libraries(maelys-git-agent PRIVATE maelys_git_cli_agent maelys_git_build_flags)

add_executable(maelys-git-executor cmd/maelys-git-executor/main.c)
target_link_libraries(maelys-git-executor PRIVATE maelys_git_cli_agent maelys_git_build_flags)

# ---- Cloud agent ------------------------------------------------------------
if(MAELYS_GIT_ENABLE_CLOUD_AGENT)
    maelys_git_resolve_dependency(HTTP MAELYS_HTTP_SOURCE_DIR)
    maelys_git_resolve_dependency(SYSTEM MAELYS_SYSTEM_SOURCE_DIR)
    if(NOT EXISTS "${MAELYS_HTTP_SOURCE_DIR}/Makefile" OR
       NOT EXISTS "${MAELYS_SYSTEM_SOURCE_DIR}/Makefile")
        message(FATAL_ERROR "Cloud agent requires maelys-http and maelys-system source trees")
    endif()
    pkg_check_modules(MBEDTLS REQUIRED IMPORTED_TARGET mbedtls mbedx509 mbedcrypto)
    set(MAELYS_HTTP_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/maelys-http")
    set(MAELYS_SYSTEM_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/maelys-system")
    set(MAELYS_HTTP_CORE_LIB "${MAELYS_HTTP_BUILD_DIR}/libmaelys_http.a")
    set(MAELYS_HTTP_CLIENT_LIB "${MAELYS_HTTP_BUILD_DIR}/libmaelys_http_client.a")
    set(MAELYS_HTTP_TLS_LIB "${MAELYS_HTTP_BUILD_DIR}/libmaelys_http_tls_mbedtls.a")
    set(MAELYS_SYSTEM_LIB "${MAELYS_SYSTEM_BUILD_DIR}/lib/libmaelys_sys.a")
    string(TOUPPER "${CMAKE_BUILD_TYPE}" MAELYS_BUILD_TYPE_UPPER)
    set(MAELYS_DEPENDENCY_CFLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${MAELYS_BUILD_TYPE_UPPER}}")
    # Project headers precede inherited include paths, including installed
    # copies of older Maelys releases. Each build has its own dependency objects.
    # maelys-system builds its archive alone, not `all`: since 0.14.0 that
    # target also builds the keeper of owned process groups, a program this
    # repository neither links nor installs.
    # The nested make does not inherit the outer make's flags: their jobserver
    # descriptors are not passed to a custom command, and a make that finds
    # them closed warns, or fails where their numbers are reused.
    add_custom_target(maelys_agent_dependencies
        COMMAND ${CMAKE_COMMAND} -E env --unset=MAKEFLAGS --unset=MFLAGS
                "CPPFLAGS=-I${MAELYS_SYSTEM_SOURCE_DIR}/include -I${MAELYS_SYSTEM_SOURCE_DIR} $ENV{CPPFLAGS}"
                "CFLAGS=${MAELYS_DEPENDENCY_CFLAGS}"
                ${MAELYS_MAKE_PROGRAM} -C "${MAELYS_SYSTEM_SOURCE_DIR}" "${MAELYS_SYSTEM_LIB}"
                "BUILD=${MAELYS_SYSTEM_BUILD_DIR}" "CC=${CMAKE_C_COMPILER}"
        COMMAND ${CMAKE_COMMAND} -E env --unset=MAKEFLAGS --unset=MFLAGS
                "CPPFLAGS=-I${MAELYS_HTTP_SOURCE_DIR}/include -I${MAELYS_HTTP_SOURCE_DIR}/src -I${MAELYS_SYSTEM_SOURCE_DIR}/include $ENV{CPPFLAGS}"
                "CFLAGS=${MAELYS_DEPENDENCY_CFLAGS}"
                ${MAELYS_MAKE_PROGRAM} -C "${MAELYS_HTTP_SOURCE_DIR}" all check-mbedtls
                REQUIRE_MBEDTLS=1
                "BUILD=${MAELYS_HTTP_BUILD_DIR}" "SYSTEM_LIB=${MAELYS_SYSTEM_LIB}"
                "SYSTEM_DIR=${MAELYS_SYSTEM_SOURCE_DIR}" "CC=${CMAKE_C_COMPILER}"
        BYPRODUCTS "${MAELYS_HTTP_CORE_LIB}" "${MAELYS_HTTP_CLIENT_LIB}"
                   "${MAELYS_HTTP_TLS_LIB}" "${MAELYS_SYSTEM_LIB}"
        VERBATIM)
    add_library(maelys_git_agent_http STATIC
        src/agent/cloud.c
        src/agent/supervisor.c)
    add_dependencies(maelys_git_agent_http maelys_agent_dependencies)
    target_include_directories(maelys_git_agent_http PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${MAELYS_HTTP_SOURCE_DIR}/include"
        "${MAELYS_SYSTEM_SOURCE_DIR}/include")
    target_compile_definitions(maelys_git_agent_http PRIVATE MAELYS_GIT_ENABLE_CLOUD_AGENT=1)
    target_link_libraries(maelys_git_agent_http
        PUBLIC maelys_git_agent_core
        PRIVATE "${MAELYS_HTTP_TLS_LIB}" "${MAELYS_HTTP_CLIENT_LIB}"
                "${MAELYS_HTTP_CORE_LIB}" "${MAELYS_SYSTEM_LIB}"
                PkgConfig::MBEDTLS SQLite::SQLite3
                maelys_git_build_flags)
    target_compile_definitions(maelys_git_cli_agent PRIVATE MAELYS_GIT_ENABLE_CLOUD_AGENT=1)
    target_link_libraries(maelys_git_cli_agent PUBLIC maelys_git_agent_http)
endif()

# ---- tests ------------------------------------------------------------------
if(MAELYS_GIT_BUILD_TESTS)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    enable_testing()
    set(MAELYS_GIT_TEST_MANIFEST "${CMAKE_CURRENT_SOURCE_DIR}/policies/manifest.json")

    add_executable(test-maelys-git tests/test_maelys_git.c)
    target_link_libraries(test-maelys-git PRIVATE maelys_git_agent_core maelys_git_build_flags)
    target_compile_definitions(test-maelys-git PRIVATE
        TEST_MANIFEST_FILE="${MAELYS_GIT_TEST_MANIFEST}")
    add_test(NAME maelys-git-core COMMAND test-maelys-git)

    add_executable(test-maelys-git-policy-sessions tests/test_policy_sessions.c)
    target_compile_definitions(test-maelys-git-policy-sessions PRIVATE
        TEST_MANIFEST_FILE="${MAELYS_GIT_TEST_MANIFEST}")
    target_link_libraries(test-maelys-git-policy-sessions PRIVATE
        maelys_git_core Threads::Threads maelys_git_build_flags)
    add_test(NAME maelys-git-policy-sessions COMMAND test-maelys-git-policy-sessions)

    add_executable(test-maelys-git-policy-concurrent-open tests/test_policy_concurrent_open.c)
    target_compile_definitions(test-maelys-git-policy-concurrent-open PRIVATE
        TEST_MANIFEST_FILE="${MAELYS_GIT_TEST_MANIFEST}")
    target_link_libraries(test-maelys-git-policy-concurrent-open PRIVATE
        maelys_git_core Threads::Threads maelys_git_build_flags)
    add_test(NAME maelys-git-policy-concurrent-open COMMAND test-maelys-git-policy-concurrent-open)

    # Decisions of a fixed request corpus, recorded on the baseline commit named
    # in the first line of the expected file and reproduced by every build.
    set(MAELYS_GIT_POLICY_FIXTURES "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/policies")
    add_executable(test-maelys-git-policy-golden tests/test_policy_golden.c)
    target_compile_definitions(test-maelys-git-policy-golden PRIVATE
        TEST_MANIFEST_FILE="${MAELYS_GIT_TEST_MANIFEST}"
        FIXTURE_DIR="${MAELYS_GIT_POLICY_FIXTURES}"
        GOLDEN_FILE="${MAELYS_GIT_POLICY_FIXTURES}/golden.tsv"
        GOLDEN_BASELINE="851e215")
    target_link_libraries(test-maelys-git-policy-golden PRIVATE
        maelys_git_core maelys_git_build_flags)
    add_test(NAME maelys-git-policy-golden COMMAND test-maelys-git-policy-golden)

    add_executable(test-maelys-git-policy-facade tests/test_policy_facade.c)
    target_include_directories(test-maelys-git-policy-facade PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_definitions(test-maelys-git-policy-facade PRIVATE
        TEST_MANIFEST_FILE="${MAELYS_GIT_TEST_MANIFEST}"
        FIXTURE_DIR="${MAELYS_GIT_POLICY_FIXTURES}")
    target_link_libraries(test-maelys-git-policy-facade PRIVATE
        maelys_git_core maelys::cli maelys_git_build_flags)
    add_test(NAME maelys-git-policy-facade COMMAND test-maelys-git-policy-facade)

    add_executable(test-maelys-git-grants tests/test_grants.c)
    target_include_directories(test-maelys-git-grants PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(test-maelys-git-grants PRIVATE maelys_git_core maelys::cli maelys_git_build_flags)
    add_test(NAME maelys-git-grants COMMAND test-maelys-git-grants)
    set_tests_properties(maelys-git-grants PROPERTIES TIMEOUT 120)

    add_executable(test-maelys-git-slice tests/test_slice.c)
    target_include_directories(test-maelys-git-slice PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(test-maelys-git-slice PRIVATE maelys_git_core maelys::cli maelys_git_build_flags)
    add_test(NAME maelys-git-slice COMMAND test-maelys-git-slice)
    set_tests_properties(maelys-git-slice PROPERTIES TIMEOUT 120)

    add_executable(test-maelys-git-gitolite-budget tests/test_gitolite_budget.c)
    target_include_directories(test-maelys-git-gitolite-budget PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_definitions(test-maelys-git-gitolite-budget PRIVATE
        TEST_MANIFEST_FILE="${MAELYS_GIT_TEST_MANIFEST}")
    target_link_libraries(test-maelys-git-gitolite-budget PRIVATE
        maelys_git_core maelys::cli maelys_git_build_flags)
    add_test(NAME maelys-git-gitolite-budget COMMAND test-maelys-git-gitolite-budget)

    add_executable(test-maelys-git-engine-contract tests/test_engine_contract.c)
    target_link_libraries(test-maelys-git-engine-contract PRIVATE
        maelys_datalog maelys::cli maelys_git_build_flags)
    add_test(NAME maelys-git-engine-contract COMMAND test-maelys-git-engine-contract)

    add_executable(test-maelys-git-gitolite-program tests/test_gitolite_program.c)
    target_include_directories(test-maelys-git-gitolite-program PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(test-maelys-git-gitolite-program PRIVATE
        maelys_git_core maelys::cli maelys_git_build_flags)
    add_test(NAME maelys-git-gitolite-program COMMAND test-maelys-git-gitolite-program)
    # The parity oracle decides 92,911 requests in both encodings: about 75 s
    # under the sanitizers on a fast machine, beyond the CI's default of 120 s
    # on a slower runner.
    set_tests_properties(maelys-git-gitolite-program PROPERTIES TIMEOUT 300)

    add_executable(test-maelys-git-gitolite-differential tests/test_gitolite_differential.c)
    target_include_directories(test-maelys-git-gitolite-differential PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_definitions(test-maelys-git-gitolite-differential PRIVATE
        DIFFERENTIAL_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/gitolite-differential")
    target_link_libraries(test-maelys-git-gitolite-differential PRIVATE
        maelys_git_core maelys_git_build_flags)
    add_test(NAME maelys-git-gitolite-differential COMMAND test-maelys-git-gitolite-differential)

    # Git Core's migration against Gitolite's own decisions, through
    # tests/gitolite_oracle.pl. The oracle is part of the proof: without
    # Perl the test fails, it is never skipped.
    add_executable(test-maelys-git-gitolite-oracle-decide tests/gitolite_oracle_decide.c)
    target_include_directories(test-maelys-git-gitolite-oracle-decide PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(test-maelys-git-gitolite-oracle-decide PRIVATE
        maelys_git_core maelys_git_build_flags)
    find_program(MAELYS_GIT_PERL perl)
    if(MAELYS_GIT_PERL)
        add_test(NAME maelys-git-gitolite-oracle
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gitolite_oracle.py
                ${MAELYS_GIT_PERL} ${CMAKE_CURRENT_SOURCE_DIR}/tests/gitolite_oracle.pl
                $<TARGET_FILE:test-maelys-git-gitolite-oracle-decide>
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/gitolite-oracle
                ${CMAKE_CURRENT_BINARY_DIR}/gitolite-oracle)
    else()
        message(WARNING "perl not found: the Gitolite oracle test fails")
        add_test(NAME maelys-git-gitolite-oracle COMMAND ${CMAKE_COMMAND} -E false)
    endif()

    add_executable(test-maelys-git-receipt tests/test_receipt.c)
    target_include_directories(test-maelys-git-receipt PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_definitions(test-maelys-git-receipt PRIVATE
        TEST_MANIFEST_FILE="${MAELYS_GIT_TEST_MANIFEST}"
        FIXTURE_DIR="${MAELYS_GIT_POLICY_FIXTURES}"
        RECEIPT_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/receipts")
    target_link_libraries(test-maelys-git-receipt PRIVATE
        maelys_git_receipt maelys_git_build_flags)
    add_test(NAME maelys-git-receipt COMMAND test-maelys-git-receipt)

    # A consumer built against the SDK the pinned engine installs, and nothing else.
    add_test(NAME maelys-git-facade-consumer
        COMMAND ${CMAKE_COMMAND}
            -DENGINE_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}/maelys-datalog
            -DPREFIX=${CMAKE_CURRENT_BINARY_DIR}/datalog-sdk
            -DCC=${CMAKE_C_COMPILER}
            "-DCFLAGS=${CMAKE_C_FLAGS}"
            -DSOURCE=${CMAKE_CURRENT_SOURCE_DIR}/tests/test_facade_consumer.c
            -DMANIFEST=${MAELYS_GIT_POLICY_FIXTURES}/filters/manifest.json
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_facade_consumer.cmake)

    # Timing is not a test: built on demand, never run by CTest.
    add_executable(bench-maelys-git-grants EXCLUDE_FROM_ALL tests/bench_grants.c)
    target_include_directories(bench-maelys-git-grants PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(bench-maelys-git-grants PRIVATE maelys_git_core maelys_git_build_flags)
    add_executable(bench-maelys-git-authorize EXCLUDE_FROM_ALL tests/bench_authorize.c)
    target_link_libraries(bench-maelys-git-authorize PRIVATE
        maelys_git_receipt maelys_git_build_flags)
    add_executable(bench-maelys-git-slices EXCLUDE_FROM_ALL tests/bench_slices.c)
    target_include_directories(bench-maelys-git-slices PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(bench-maelys-git-slices PRIVATE maelys_git_agent_core maelys::cli maelys_git_build_flags)

    add_executable(bench-maelys-git-refex EXCLUDE_FROM_ALL tests/bench_refex.c)
    target_include_directories(bench-maelys-git-refex PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(bench-maelys-git-refex PRIVATE maelys_git_core maelys::cli maelys_git_build_flags)

    # Production code reaches the engine through its installed SDK only.
    add_test(NAME maelys-git-datalog-boundary
        COMMAND ${CMAKE_COMMAND}
            -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            -DARCHIVE=$<TARGET_FILE:maelys_git_core>
            -DSDK_INCLUDE=${MAELYS_DATALOG_SOURCE_DIR}/include
            -DNM=${CMAKE_NM}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_datalog_boundary.cmake)
    # The same check on a source that includes the compiled-program view: refused.
    add_test(NAME maelys-git-datalog-boundary-refuses-program
        COMMAND ${CMAKE_COMMAND}
            -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/datalog-boundary/program
            -DARCHIVE=$<TARGET_FILE:maelys_git_core>
            -DSDK_INCLUDE=${MAELYS_DATALOG_SOURCE_DIR}/include
            -DNM=${CMAKE_NM}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_datalog_boundary.cmake)
    set_tests_properties(maelys-git-datalog-boundary-refuses-program PROPERTIES
        PASS_REGULAR_EXPRESSION "src/program.c: forbidden engine include #include <maelys/datalog_program.h>")
    set_tests_properties(maelys-git-policy-sessions PROPERTIES TIMEOUT 120)

    add_executable(test-maelys-git-agent tests/test_agent.c)
    target_include_directories(test-maelys-git-agent PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(test-maelys-git-agent PRIVATE
        maelys_git_agent_core SQLite::SQLite3 maelys_git_build_flags)
    target_compile_definitions(test-maelys-git-agent PRIVATE
        TEST_MANIFEST_FILE="${MAELYS_GIT_TEST_MANIFEST}"
        FIXTURE_DIR="${MAELYS_GIT_POLICY_FIXTURES}")
    add_test(NAME maelys-git-agent COMMAND test-maelys-git-agent)

    add_executable(test-maelys-git-grants-streams tests/test_grants_streams.c)
    target_include_directories(test-maelys-git-grants-streams PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(test-maelys-git-grants-streams PRIVATE
        maelys_git_agent_core maelys::cli maelys_git_build_flags)
    add_test(NAME maelys-git-grants-streams COMMAND test-maelys-git-grants-streams)

    add_executable(test-maelys-git-agent-config tests/test_agent_config.c)
    target_include_directories(test-maelys-git-agent-config PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(test-maelys-git-agent-config PRIVATE
        maelys_git_agent_core maelys_git_build_flags)
    add_test(NAME maelys-git-agent-config COMMAND test-maelys-git-agent-config)
    set_tests_properties(maelys-git-agent-config PROPERTIES TIMEOUT 15)

    add_executable(test-maelys-git-agent-protocol tests/test_agent_protocol.c)
    target_include_directories(test-maelys-git-agent-protocol PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(test-maelys-git-agent-protocol PRIVATE
        maelys_git_agent_core SQLite::SQLite3 maelys_git_build_flags)
    target_compile_definitions(test-maelys-git-agent-protocol PRIVATE
        PROTOCOL_DIR="${CMAKE_CURRENT_SOURCE_DIR}/protocol")
    add_test(NAME maelys-git-agent-protocol COMMAND test-maelys-git-agent-protocol)

    add_executable(test-maelys-git-store-migration tests/test_store_migration.c)
    target_include_directories(test-maelys-git-store-migration PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_definitions(test-maelys-git-store-migration PRIVATE
        STORE_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/agent-store/v1.sqlite3")
    target_link_libraries(test-maelys-git-store-migration PRIVATE
        maelys_git_agent_core SQLite::SQLite3 maelys_git_build_flags)
    add_test(NAME maelys-git-store-migration COMMAND test-maelys-git-store-migration)
    add_test(NAME maelys-git-protocol-reader
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_protocol_reader.py
            $<TARGET_FILE:maelys-git-agent> $<TARGET_FILE:maelys-git-executor>
            ${MAELYS_GIT_TEST_MANIFEST})

    # Results that do not fit a protocol line, through the executor's stream.
    add_test(NAME maelys-git-protocol-limits
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_protocol_limits.py
            $<TARGET_FILE:maelys-git-executor> ${MAELYS_GIT_TEST_MANIFEST})

    # The JSON every program writes, against the corpus recorded at 1016d1b.
    add_executable(json-corpus-emitter tests/json_corpus_emitter.c)
    target_include_directories(json-corpus-emitter PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(json-corpus-emitter PRIVATE
        maelys_git_agent_core maelys_git_build_flags)
    add_test(NAME maelys-git-json-corpus
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_json_corpus.py
            $<TARGET_FILE:maelys-git> $<TARGET_FILE:maelys-git-agent>
            $<TARGET_FILE:maelys-git-executor> $<TARGET_FILE:json-corpus-emitter>
            ${MAELYS_GIT_TEST_MANIFEST}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/json-corpus/corpus.json)
    set_tests_properties(maelys-git-agent-protocol maelys-git-protocol-reader PROPERTIES TIMEOUT 60)

    add_executable(test-maelys-git-cli tests/test_cli.c)
    target_include_directories(test-maelys-git-cli PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_definitions(test-maelys-git-cli PRIVATE
        FIXTURE_DIR="${MAELYS_GIT_POLICY_FIXTURES}")
    target_link_libraries(test-maelys-git-cli PRIVATE
        maelys_git_cli_agent maelys_git_build_flags)
    add_test(NAME maelys-git-cli COMMAND test-maelys-git-cli)

    add_executable(test-maelys-git-process tests/test_process.c)
    target_include_directories(test-maelys-git-process PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(test-maelys-git-process PRIVATE maelys_git_core maelys_git_build_flags)
    add_test(NAME maelys-git-process-isolation COMMAND test-maelys-git-process)
    # The same checks on the wait without an exit watcher, as on a kernel
    # without pidfd_open: this process.c replaces the library's.
    add_executable(test-maelys-git-process-backoff
        tests/test_process.c src/common/process.c)
    target_include_directories(test-maelys-git-process-backoff PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_definitions(test-maelys-git-process-backoff PRIVATE MG_PROCESS_NO_EXIT_WATCHER)
    target_link_libraries(test-maelys-git-process-backoff PRIVATE maelys_git_core maelys_git_build_flags)
    add_test(NAME maelys-git-process-backoff COMMAND test-maelys-git-process-backoff)

    if(MAELYS_GIT_ENABLE_CLOUD_AGENT)
        find_program(MAELYS_OPENSSL_PROGRAM openssl REQUIRED)
        add_executable(test-maelys-git-supervisor tests/test_supervisor.c)
        target_include_directories(test-maelys-git-supervisor PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(test-maelys-git-supervisor PRIVATE
            maelys_git_agent_http SQLite::SQLite3 maelys_git_build_flags)
        target_compile_definitions(test-maelys-git-supervisor PRIVATE
            MAELYS_GIT_ENABLE_CLOUD_AGENT=1)
        add_test(NAME maelys-git-supervisor-isolation COMMAND test-maelys-git-supervisor)
        add_test(NAME maelys-git-cloud-transport
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cloud_transport.py
                $<TARGET_FILE:maelys-git-agent> $<TARGET_FILE:maelys-git-executor>
                ${MAELYS_GIT_TEST_MANIFEST} ${MAELYS_OPENSSL_PROGRAM} $<TARGET_FILE:maelys-git>)
        set_tests_properties(maelys-git-cloud-transport PROPERTIES TIMEOUT 60)
    endif()

    add_test(NAME maelys-git-cli-integration
        COMMAND ${CMAKE_COMMAND}
            -DMAELYS_GIT_BIN=$<TARGET_FILE:maelys-git>
            -DMAELYS_AGENT_BIN=$<TARGET_FILE:maelys-git-agent>
            -DMAELYS_EXECUTOR_BIN=$<TARGET_FILE:maelys-git-executor>
            -DMAELYS_SHELL_BIN=$<TARGET_FILE:maelys-git-shell>
            -DMAELYS_HOOK_BIN=$<TARGET_FILE:maelys-git-hook>
            -DTEST_MANIFEST=${MAELYS_GIT_TEST_MANIFEST}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_integration.cmake)

    add_test(NAME maelys-git-pr-integration
        COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_pr_cli.sh
            $<TARGET_FILE:maelys-git>
            ${MAELYS_GIT_TEST_MANIFEST}
            $<TARGET_FILE:maelys-git-executor>)

    # One JSON library: no identifier of the former one in the tree or in a
    # program or a static library, and explicit limits on every writer.
    set(MAELYS_GIT_JSON_GUARD_FILES
        $<TARGET_FILE:maelys-git> $<TARGET_FILE:maelys-git-agent>
        $<TARGET_FILE:maelys-git-executor> $<TARGET_FILE:maelys-git-shell>
        $<TARGET_FILE:maelys-git-hook>
        $<TARGET_FILE:maelys_git_core> $<TARGET_FILE:maelys_git_receipt>
        $<TARGET_FILE:maelys_git_json> $<TARGET_FILE:maelys_git_agent_core>
        $<TARGET_FILE:maelys_git_cli> $<TARGET_FILE:maelys_git_cli_admin>
        $<TARGET_FILE:maelys_git_cli_agent>)
    if(MAELYS_GIT_ENABLE_CLOUD_AGENT)
        list(APPEND MAELYS_GIT_JSON_GUARD_FILES $<TARGET_FILE:maelys_git_agent_http>)
    endif()
    add_test(NAME maelys-git-json-single-library
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_json_single_library.py
            ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_NM} ${MAELYS_GIT_JSON_GUARD_FILES})

    add_test(NAME maelys-git-hook-integration
        COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_hook_cli.sh
            $<TARGET_FILE:maelys-git-hook> $<TARGET_FILE:maelys-git-shell>)

    add_test(NAME maelys-git-receive-authorization
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_receive_authorization.py
            $<TARGET_FILE:maelys-git-hook> $<TARGET_FILE:maelys-git-executor>)
    set_tests_properties(maelys-git-receive-authorization PROPERTIES TIMEOUT 120)

    add_test(NAME maelys-git-gitolite-ref-domain
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gitolite_ref_domain.py
            $<TARGET_FILE:maelys-git> $<TARGET_FILE:maelys-git-hook> $<TARGET_FILE:maelys-git-executor>
            $<TARGET_FILE:maelys-git-shell>)

    add_test(NAME maelys-git-gitolite-regex-entries
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gitolite_regex_entries.py
            $<TARGET_FILE:maelys-git> $<TARGET_FILE:maelys-git-hook> $<TARGET_FILE:maelys-git-executor>
            $<TARGET_FILE:maelys-git-shell>)

    add_test(NAME maelys-git-gitolite-merge-denies
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gitolite_merge_denies.py
            $<TARGET_FILE:maelys-git> $<TARGET_FILE:maelys-git-executor>)
    set_tests_properties(maelys-git-gitolite-merge-denies PROPERTIES TIMEOUT 300)

    add_test(NAME maelys-git-gitolite-program-versions
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gitolite_program_versions.py
            $<TARGET_FILE:maelys-git> $<TARGET_FILE:maelys-git-shell> ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures)

    add_test(NAME maelys-git-audit-regressions
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_audit_regressions.py
            $<TARGET_FILE:maelys-git> $<TARGET_FILE:maelys-git-hook>
            $<TARGET_FILE:maelys-git-executor> $<TARGET_FILE:maelys-git-agent>
            $<BOOL:${MAELYS_GIT_ENABLE_CLOUD_AGENT}>)
    set_tests_properties(maelys-git-audit-regressions PROPERTIES TIMEOUT 120)

    add_test(NAME maelys-git-gitolite-integration
        COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gitolite_cli.sh
            $<TARGET_FILE:maelys-git>
            $<TARGET_FILE:maelys-git-hook>)

    add_test(NAME maelys-git-repository-lifecycle
        COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_repository_lifecycle.sh
            $<TARGET_FILE:maelys-git>)

    add_test(NAME maelys-git-repository-mirror
        COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_mirror_cli.sh
            $<TARGET_FILE:maelys-git>)

    add_test(NAME maelys-git-namespace-policy
        COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_namespace_policy.sh
            $<TARGET_FILE:maelys-git>)

    if(Python3_Interpreter_FOUND)
        # Proves that the committed reference matches what the binaries describe.
        add_test(NAME maelys-git-cli-docs
            COMMAND ${CMAKE_COMMAND}
                -DPYTHON=${Python3_EXECUTABLE}
                -DREFERENCE=${MAELYS_CLI_REFERENCE}
                -DBUILD_DIR=$<TARGET_FILE_DIR:maelys-git>
                -DDOCS_DIR=${CMAKE_CURRENT_SOURCE_DIR}/docs
                -DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-docs-check
                "-DPROGRAMS=${MAELYS_GIT_PROGRAMS}"
                "-DREFERENCE_ARGS=${MAELYS_GIT_REFERENCE_ARGS}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_cli_docs.cmake)
    endif()
endif()

# The reference is generated by the framework's own tool from `describe`, so
# it is never a second hand-written definition of the catalog.
if(Python3_Interpreter_FOUND)
    add_custom_target(generate-cli-reference
        COMMAND ${Python3_EXECUTABLE} ${MAELYS_CLI_REFERENCE}
            --build $<TARGET_FILE_DIR:maelys-git>
            --markdown ${CMAKE_CURRENT_SOURCE_DIR}/docs/cli.md
            --json ${CMAKE_CURRENT_SOURCE_DIR}/docs/cli-contract.json
            ${MAELYS_GIT_REFERENCE_ARGS} ${MAELYS_GIT_PROGRAMS}
        DEPENDS ${MAELYS_GIT_PROGRAMS} docs/cli-reference-intro.md
        VERBATIM)
endif()

include(GNUInstallDirs)
install(TARGETS maelys_git_core maelys_git_agent_core
        maelys_git_cli maelys_git_cli_admin maelys_git_cli_agent
        maelys-git-shell maelys-git-hook maelys-git-agent maelys-git-executor maelys-git
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/maelys_git.h include/maelys_git_agent.h include/maelys_git_cli.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY policies/ DESTINATION ${CMAKE_INSTALL_DATADIR}/maelys-git/policies)
install(DIRECTORY protocol/ DESTINATION ${CMAKE_INSTALL_DATADIR}/maelys-git/protocol)
install(DIRECTORY schemas/ DESTINATION ${CMAKE_INSTALL_DATADIR}/maelys-git/schemas)
install(DIRECTORY docs/ DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/maelys-git)
