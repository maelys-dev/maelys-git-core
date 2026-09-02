# Embeds every schemas/*.json file into C symbols with maelys-cli-embed.
#
# usage: cmake -DEMBED=<maelys-cli-embed> -DSCHEMAS=<dir> -DOUTPUT=<file>
#              [-DHEADER=ON] -P cmake/embed.cmake
#
# schemas/repo-init.json becomes `const char maelys_git_schema_repo_init[]`.
if(NOT DEFINED EMBED OR NOT DEFINED SCHEMAS OR NOT DEFINED OUTPUT)
    message(FATAL_ERROR "EMBED, SCHEMAS and OUTPUT are required")
endif()

file(GLOB schemas "${SCHEMAS}/*.json")
list(SORT schemas)
if(NOT schemas)
    message(FATAL_ERROR "no schema found in ${SCHEMAS}")
endif()

set(symbols)
foreach(schema IN LISTS schemas)
    get_filename_component(name "${schema}" NAME_WE)
    string(REPLACE "-" "_" symbol "${name}")
    list(APPEND symbols "maelys_git_schema_${symbol}=${schema}")
endforeach()

set(flags)
if(HEADER)
    set(flags --header)
endif()

execute_process(
    COMMAND /bin/sh "${EMBED}" ${flags} ${symbols}
    OUTPUT_FILE "${OUTPUT}.tmp"
    RESULT_VARIABLE status)
if(NOT status EQUAL 0)
    file(REMOVE "${OUTPUT}.tmp")
    message(FATAL_ERROR "maelys-cli-embed failed with status ${status}")
endif()
file(RENAME "${OUTPUT}.tmp" "${OUTPUT}")
