# Regenerates the CLI reference into WORK_DIR with the framework generator and
# fails when the committed documents under DOCS_DIR differ.
#
# usage: cmake -DPYTHON=... -DREFERENCE=... -DBUILD_DIR=... -DDOCS_DIR=...
#              -DWORK_DIR=... -DPROGRAMS="a;b" -P cmake/check_cli_docs.cmake
foreach(variable IN ITEMS PYTHON REFERENCE BUILD_DIR DOCS_DIR WORK_DIR PROGRAMS)
    if(NOT DEFINED ${variable})
        message(FATAL_ERROR "${variable} is required")
    endif()
endforeach()
file(MAKE_DIRECTORY "${WORK_DIR}")
execute_process(
    COMMAND "${PYTHON}" "${REFERENCE}" --build "${BUILD_DIR}"
        --markdown "${WORK_DIR}/cli-reference.md"
        --json "${WORK_DIR}/cli-contract.json" ${PROGRAMS}
    RESULT_VARIABLE status
    OUTPUT_QUIET)
if(NOT status EQUAL 0)
    message(FATAL_ERROR "the CLI reference generator failed with status ${status}")
endif()
foreach(name IN ITEMS cli-reference.md cli-contract.json)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E compare_files "${WORK_DIR}/${name}" "${DOCS_DIR}/${name}"
        RESULT_VARIABLE differs)
    if(NOT differs EQUAL 0)
        message(FATAL_ERROR
            "docs/${name} drifted; run: cmake --build build --target generate-cli-reference")
    endif()
endforeach()
