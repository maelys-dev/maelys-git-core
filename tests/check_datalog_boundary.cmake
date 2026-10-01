# Fails when production code reaches Maelys Datalog outside its installed SDK.
#
# usage: cmake -DSOURCE_DIR=... -DARCHIVE=... -DSDK_INCLUDE=... [-DNM=nm]
#              -P tests/check_datalog_boundary.cmake
#
# 1. src/, cmd/ and include/ may include <maelys/datalog.h>,
#    <maelys/datalog_advanced.h> and, for the policy identifier only,
#    <maelys/datalog_backend.h>; nothing else of the engine.
# 2. They may not name an internal type, a test-only macro, the retired atom
#    scanner or a compile-time engine capacity.
# 3. Every maelys_datalog_ symbol the core archive leaves undefined must be
#    declared by those headers; from the backend and program headers only
#    maelys_datalog_session_program and maelys_datalog_program_info.
foreach(variable IN ITEMS SOURCE_DIR ARCHIVE SDK_INCLUDE)
    if(NOT DEFINED ${variable})
        message(FATAL_ERROR "${variable} is required")
    endif()
endforeach()
if(NOT DEFINED NM)
    set(NM nm)
endif()

set(violations "")
file(GLOB_RECURSE sources
    "${SOURCE_DIR}/src/*.c" "${SOURCE_DIR}/src/*.h"
    "${SOURCE_DIR}/cmd/*.c" "${SOURCE_DIR}/include/*.h")
set(forbidden_tokens
    "maelys_datalog_internal_" "MAELYS_GIT_POLICY_TESTING" "yyjson"
    "common/maelys_sha256" "collect_source_atoms" "collect_manifest_atoms"
    "s_policy_atoms" "install_git_domain" "MAELYS_DATALOG_MAX_")
foreach(source IN LISTS sources)
    file(READ "${source}" text)
    file(RELATIVE_PATH name "${SOURCE_DIR}" "${source}")
    string(REGEX MATCHALL "#[ \t]*include[ \t]*[<\"][^>\"]*datalog[^>\"]*[>\"]" includes "${text}")
    foreach(include IN LISTS includes)
        if(NOT include MATCHES "<maelys/datalog(_advanced|_backend)?\\.h>")
            list(APPEND violations "${name}: forbidden engine include ${include}")
        endif()
    endforeach()
    foreach(token IN LISTS forbidden_tokens)
        string(FIND "${text}" "${token}" position)
        if(NOT position EQUAL -1)
            list(APPEND violations "${name}: forbidden token ${token}")
        endif()
    endforeach()
endforeach()

execute_process(COMMAND "${NM}" -u "${ARCHIVE}"
    OUTPUT_VARIABLE undefined ERROR_QUIET RESULT_VARIABLE status)
if(NOT status EQUAL 0)
    message(FATAL_ERROR "cannot list the undefined symbols of ${ARCHIVE}")
endif()
string(REGEX MATCHALL "maelys_datalog_[a-z0-9_]+" symbols "${undefined}")
list(REMOVE_DUPLICATES symbols)
list(LENGTH symbols symbol_count)
if(symbol_count EQUAL 0)
    list(APPEND violations "the core archive references no engine symbol: the check is not looking at the policy code")
endif()
file(READ "${SDK_INCLUDE}/maelys/datalog.h" consumer_header)
file(READ "${SDK_INCLUDE}/maelys/datalog_advanced.h" advanced_header)
set(identity_symbols maelys_datalog_session_program maelys_datalog_program_info)
foreach(symbol IN LISTS symbols)
    if(symbol IN_LIST identity_symbols)
        continue()
    endif()
    if(NOT consumer_header MATCHES "[^a-z0-9_]${symbol}\\(" AND
       NOT advanced_header MATCHES "[^a-z0-9_]${symbol}\\(")
        list(APPEND violations "libmaelys_git_core.a references ${symbol}, which the consumer SDK headers do not declare")
    endif()
endforeach()

if(violations)
    list(JOIN violations "\n  " report)
    message(FATAL_ERROR "Maelys Datalog boundary violated:\n  ${report}")
endif()
message(STATUS "Maelys Datalog boundary: ${symbol_count} engine symbols, all declared by the installed SDK")
