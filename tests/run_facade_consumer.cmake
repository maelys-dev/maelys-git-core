# Installs the pinned engine SDK into a private prefix, compiles the consumer
# against that prefix alone and runs it.
#
# usage: cmake -DENGINE_BUILD_DIR=... -DPREFIX=... -DCC=... -DSOURCE=...
#              -DMANIFEST=... [-DCFLAGS="..."] -P tests/run_facade_consumer.cmake
foreach(variable IN ITEMS ENGINE_BUILD_DIR PREFIX CC SOURCE MANIFEST)
    if(NOT DEFINED ${variable})
        message(FATAL_ERROR "${variable} is required")
    endif()
endforeach()
file(REMOVE_RECURSE "${PREFIX}")
foreach(component IN ITEMS sdk sdk-static)
    execute_process(
        COMMAND "${CMAKE_COMMAND}" --install "${ENGINE_BUILD_DIR}" --prefix "${PREFIX}"
                --component ${component}
        RESULT_VARIABLE status OUTPUT_QUIET ERROR_VARIABLE diagnostic)
    if(NOT status EQUAL 0)
        message(FATAL_ERROR "cannot install the engine ${component} component: ${diagnostic}")
    endif()
endforeach()
if(NOT EXISTS "${PREFIX}/include/maelys/datalog.h" OR EXISTS "${PREFIX}/include/maelys_datalog.h")
    message(FATAL_ERROR "the installed SDK does not have the expected public headers")
endif()
file(GLOB archive "${PREFIX}/lib*/libmaelys_datalog.a")
if(NOT archive)
    message(FATAL_ERROR "the installed SDK has no static library")
endif()
separate_arguments(flags NATIVE_COMMAND "${CFLAGS}")
execute_process(
    COMMAND "${CC}" -std=c11 ${flags} "-I${PREFIX}/include" "${SOURCE}" ${archive}
            -o "${PREFIX}/facade-consumer"
    RESULT_VARIABLE status ERROR_VARIABLE diagnostic)
if(NOT status EQUAL 0)
    message(FATAL_ERROR "the consumer does not build against the installed SDK:\n${diagnostic}")
endif()
execute_process(COMMAND "${PREFIX}/facade-consumer" "${MANIFEST}" RESULT_VARIABLE status)
if(NOT status EQUAL 0)
    message(FATAL_ERROR "the installed SDK consumer failed with status ${status}")
endif()
