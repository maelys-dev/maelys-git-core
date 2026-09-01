cmake_minimum_required(VERSION 3.20)
project(maelys_git_core VERSION 0.1.0 LANGUAGES C)

find_package(Python3 QUIET COMPONENTS Interpreter)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(MAELYS_GIT_BUILD_TESTS "Build the Maelys Git tests" ON)
option(MAELYS_GIT_ENABLE_CLOUD_AGENT "Build the HTTPS Cloud agent" ON)
set(MAELYS_DATALOG_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../maelys-datalog"
    CACHE PATH "Path to the maelys-datalog source tree")
set(MAELYS_HTTP_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../maelys-http"
    CACHE PATH "Path to the maelys-http source tree")
set(MAELYS_SYSTEM_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../maelys-system"
    CACHE PATH "Path to the maelys-system source tree")

find_package(PkgConfig REQUIRED)
pkg_check_modules(JANSSON REQUIRED IMPORTED_TARGET jansson>=2.14.1)
find_package(SQLite3 REQUIRED)

if(NOT EXISTS "${MAELYS_DATALOG_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "maelys-datalog was not found at ${MAELYS_DATALOG_SOURCE_DIR}; "
        "set MAELYS_DATALOG_SOURCE_DIR")
endif()

add_subdirectory("${MAELYS_DATALOG_SOURCE_DIR}"
                 "${CMAKE_CURRENT_BINARY_DIR}/maelys-datalog"
                 EXCLUDE_FROM_ALL)

add_library(maelys_git_core STATIC
    src/common/error.c
    src/common/process.c
    src/common/strings.c
    src/shell/command.c
    src/policy/policy.c
    src/repository/repository.c
    src/repository/transaction.c
    src/repository/pull_request.c
    src/repository/keys.c
    src/hooks/pre_receive.c)

target_include_directories(maelys_git_core
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(maelys_git_core PUBLIC maelys_datalog)
target_compile_definitions(maelys_git_core PRIVATE _POSIX_C_SOURCE=200809L)
target_compile_options(maelys_git_core PRIVATE -Wall -Wextra -Wpedantic)

add_library(maelys_git_agent_core STATIC
    src/protocol/protocol.c
    src/agent/config.c
    src/agent/store.c
    src/agent/retry.c
    src/agent/executor.c
    src/agent/agent.c)
target_include_directories(maelys_git_agent_core
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(maelys_git_agent_core
    PUBLIC maelys_git_core
    PRIVATE PkgConfig::JANSSON SQLite::SQLite3)
target_compile_definitions(maelys_git_agent_core PRIVATE _POSIX_C_SOURCE=200809L)
target_compile_options(maelys_git_agent_core PRIVATE -Wall -Wextra -Wpedantic)

add_library(maelys_git_cli STATIC
    src/cli/catalog.c
    src/cli/cli.c)
target_include_directories(maelys_git_cli
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(maelys_git_cli PUBLIC maelys_git_core PkgConfig::JANSSON)
target_compile_definitions(maelys_git_cli PRIVATE _POSIX_C_SOURCE=200809L)
target_compile_options(maelys_git_cli PRIVATE -Wall -Wextra -Wpedantic)

add_executable(maelys-git-shell cmd/maelys-git-shell/main.c)
target_link_libraries(maelys-git-shell PRIVATE maelys_git_cli)

add_executable(maelys-git-hook cmd/maelys-git-hook/main.c)
target_link_libraries(maelys-git-hook PRIVATE maelys_git_cli)

add_executable(maelys-git-agent cmd/maelys-git-agent/main.c)

add_executable(maelys-git-executor cmd/maelys-git-executor/main.c)
target_link_libraries(maelys-git-executor PRIVATE maelys_git_agent_core maelys_git_cli)

add_executable(maelys-git cmd/maelys-git/main.c)
target_link_libraries(maelys-git PRIVATE maelys_git_agent_core maelys_git_cli)

foreach(target maelys-git-shell maelys-git-hook maelys-git-agent
               maelys-git-executor maelys-git)
    target_compile_definitions(${target} PRIVATE _POSIX_C_SOURCE=200809L)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
endforeach()

if(MAELYS_GIT_ENABLE_CLOUD_AGENT)
    if(NOT EXISTS "${MAELYS_HTTP_SOURCE_DIR}/Makefile" OR
       NOT EXISTS "${MAELYS_SYSTEM_SOURCE_DIR}/Makefile")
        message(FATAL_ERROR "Cloud agent requires maelys-http and maelys-system source trees")
    endif()
    pkg_check_modules(MBEDTLS REQUIRED IMPORTED_TARGET mbedtls mbedx509 mbedcrypto)
    set(MAELYS_HTTP_CORE_LIB "${MAELYS_HTTP_SOURCE_DIR}/build/libmaelys_http.a")
    set(MAELYS_HTTP_CLIENT_LIB "${MAELYS_HTTP_SOURCE_DIR}/build/libmaelys_http_client.a")
    set(MAELYS_HTTP_TLS_LIB "${MAELYS_HTTP_SOURCE_DIR}/build/libmaelys_http_tls_mbedtls.a")
    set(MAELYS_SYSTEM_LIB "${MAELYS_SYSTEM_SOURCE_DIR}/build/release/lib/libmaelys_sys.a")
    add_custom_target(maelys_agent_dependencies
        COMMAND ${CMAKE_MAKE_PROGRAM} -C "${MAELYS_SYSTEM_SOURCE_DIR}" all
        COMMAND ${CMAKE_MAKE_PROGRAM} -C "${MAELYS_HTTP_SOURCE_DIR}" all check-mbedtls
                REQUIRE_MBEDTLS=1
                SYSTEM_DIR="${MAELYS_SYSTEM_SOURCE_DIR}"
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
    target_compile_definitions(maelys_git_agent_http PRIVATE
        _POSIX_C_SOURCE=200809L MAELYS_GIT_ENABLE_CLOUD_AGENT=1)
    target_compile_options(maelys_git_agent_http PRIVATE -Wall -Wextra -Wpedantic)
    target_link_libraries(maelys_git_agent_http
        PUBLIC maelys_git_agent_core
        PRIVATE "${MAELYS_HTTP_TLS_LIB}" "${MAELYS_HTTP_CLIENT_LIB}"
                "${MAELYS_HTTP_CORE_LIB}" "${MAELYS_SYSTEM_LIB}"
                PkgConfig::MBEDTLS PkgConfig::JANSSON SQLite::SQLite3)
    target_link_libraries(maelys-git-agent PRIVATE maelys_git_agent_http)
    target_link_libraries(maelys-git-agent PRIVATE maelys_git_cli)
    target_compile_definitions(maelys-git-agent PRIVATE MAELYS_GIT_ENABLE_CLOUD_AGENT=1)
else()
    target_link_libraries(maelys-git-agent PRIVATE maelys_git_agent_core maelys_git_cli)
endif()

if(MAELYS_GIT_BUILD_TESTS)
    enable_testing()
    add_executable(test-maelys-git tests/test_maelys_git.c)
    target_link_libraries(test-maelys-git PRIVATE maelys_git_agent_core)
    target_compile_definitions(test-maelys-git PRIVATE
        _POSIX_C_SOURCE=200809L
        TEST_MANIFEST_FILE="${CMAKE_CURRENT_SOURCE_DIR}/policies/manifest.json")
    if(APPLE)
        target_compile_definitions(test-maelys-git PRIVATE _DARWIN_C_SOURCE)
    endif()
    target_compile_options(test-maelys-git PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME maelys-git-core COMMAND test-maelys-git)

    add_executable(test-maelys-git-agent tests/test_agent.c)
    target_include_directories(test-maelys-git-agent PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(test-maelys-git-agent PRIVATE maelys_git_agent_core)
    target_link_libraries(test-maelys-git-agent PRIVATE PkgConfig::JANSSON SQLite::SQLite3)
    target_compile_definitions(test-maelys-git-agent PRIVATE
        _POSIX_C_SOURCE=200809L
        TEST_MANIFEST_FILE="${CMAKE_CURRENT_SOURCE_DIR}/policies/manifest.json")
    if(APPLE)
        target_compile_definitions(test-maelys-git-agent PRIVATE _DARWIN_C_SOURCE)
    endif()
    target_compile_options(test-maelys-git-agent PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME maelys-git-agent COMMAND test-maelys-git-agent)

    add_executable(test-maelys-git-cli tests/test_cli.c)
    target_link_libraries(test-maelys-git-cli PRIVATE maelys_git_cli PkgConfig::JANSSON)
    target_compile_definitions(test-maelys-git-cli PRIVATE _POSIX_C_SOURCE=200809L)
    target_compile_options(test-maelys-git-cli PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME maelys-git-cli COMMAND test-maelys-git-cli)

    add_test(NAME maelys-git-cli-integration
        COMMAND ${CMAKE_COMMAND}
            -DMAELYS_GIT_BIN=$<TARGET_FILE:maelys-git>
            -DMAELYS_AGENT_BIN=$<TARGET_FILE:maelys-git-agent>
            -DMAELYS_EXECUTOR_BIN=$<TARGET_FILE:maelys-git-executor>
            -DMAELYS_SHELL_BIN=$<TARGET_FILE:maelys-git-shell>
            -DTEST_MANIFEST=${CMAKE_CURRENT_SOURCE_DIR}/policies/manifest.json
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_integration.cmake)

    add_test(NAME maelys-git-pr-integration
        COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_pr_cli.sh
            $<TARGET_FILE:maelys-git>
            ${CMAKE_CURRENT_SOURCE_DIR}/policies/manifest.json)

    add_test(NAME maelys-git-hook-integration
        COMMAND /bin/sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_hook_cli.sh
            $<TARGET_FILE:maelys-git-hook>)

    if(Python3_Interpreter_FOUND)
        add_test(NAME maelys-git-cli-docs
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_cli_reference.py
                --build-dir ${CMAKE_CURRENT_BINARY_DIR}
                --output-dir ${CMAKE_CURRENT_SOURCE_DIR}/docs
                --check)
    endif()
endif()

if(Python3_Interpreter_FOUND)
    add_custom_target(generate-cli-reference
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_cli_reference.py
            --build-dir ${CMAKE_CURRENT_BINARY_DIR}
            --output-dir ${CMAKE_CURRENT_SOURCE_DIR}/docs
        DEPENDS maelys-git maelys-git-agent maelys-git-executor
                maelys-git-shell maelys-git-hook
        VERBATIM)
endif()

include(GNUInstallDirs)
install(TARGETS maelys_git_core maelys_git_agent_core maelys_git_cli maelys-git-shell
        maelys-git-hook maelys-git-agent maelys-git-executor maelys-git
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/maelys_git.h include/maelys_git_agent.h include/maelys_git_cli.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY policies/ DESTINATION ${CMAKE_INSTALL_DATADIR}/maelys-git/policies)
install(DIRECTORY protocol/ DESTINATION ${CMAKE_INSTALL_DATADIR}/maelys-git/protocol)
install(DIRECTORY docs/ DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/maelys-git)
