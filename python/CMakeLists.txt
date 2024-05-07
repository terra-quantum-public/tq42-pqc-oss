find_package(Python COMPONENTS Interpreter QUIET)
foreach(TEST_STRING "import setuptools\nimport pytest" "import pytest")
    foreach(PYTHON_NAME "python3" "python" "${Python_EXECUTABLE}")
        set(WRONG_PYTHON 1)
        unset(PYTHON_EXECUTABLE CACHE)
        find_program(PYTHON_EXECUTABLE "${PYTHON_NAME}" PATHS ENV PATH NO_DEFAULT_PATH)
        if(NOT "${PYTHON_EXECUTABLE}" MATCHES "PYTHON_EXECUTABLE-NOTFOUND")
            execute_process(COMMAND "${PYTHON_EXECUTABLE}" "-c" "${TEST_STRING}" RESULT_VARIABLE WRONG_PYTHON)
            if(NOT WRONG_PYTHON)
                break()
            endif()
        endif()
    endforeach()
    if(NOT WRONG_PYTHON)
        break()
    endif()
endforeach()

if(WRONG_PYTHON)
    message(FATAL_ERROR "PYTHON is ON but there is no suitable Python in PATH. Please make sure you have setuptools and pytest installed.")
endif()

file(COPY "${PROJECT_SOURCE_DIR}/python" DESTINATION "${PROJECT_BINARY_DIR}")
execute_process(
    COMMAND "${PYTHON_EXECUTABLE}" "-m" "pytest" "--collect-only" "--quiet"
    WORKING_DIRECTORY "${PROJECT_BINARY_DIR}/python"
    OUTPUT_VARIABLE TESTS
    COMMAND_ERROR_IS_FATAL ANY
)
string(REGEX MATCHALL "[^\n]+" TESTS_LIST "${TESTS}")
list(POP_BACK TESTS_LIST)

set(PYTHON_ENVIRONMENT "PYTHONPATH=${PROJECT_BINARY_DIR}/python;ASAN_OPTIONS=verify_asan_link_order=0")

foreach(TEST ${TESTS_LIST})
    string(REGEX MATCHALL "[^/]+" TEST_PARTS "${TEST}")
    list(POP_FRONT TEST_PARTS)
    list(JOIN TEST_PARTS "/" TEST_NAME)
    add_test("PYTHON.${TEST_NAME}" "${PYTHON_EXECUTABLE}" "-m" "pytest" "${PROJECT_BINARY_DIR}/python/${TEST}")
    set_property(TEST "PYTHON.${TEST_NAME}" PROPERTY ENVIRONMENT "${PYTHON_ENVIRONMENT}")
endforeach()

add_test(PYTHON.SETUP "${PYTHON_EXECUTABLE}" "setup.py" "build")
set_tests_properties(PYTHON.SETUP PROPERTIES
    ENVIRONMENT "${PYTHON_ENVIRONMENT}"
    WORKING_DIRECTORY "${PROJECT_BINARY_DIR}/python"
)

add_custom_target(copy_pqc_shared_python ALL
    COMMAND "${CMAKE_COMMAND}" "-E" "copy" "$<TARGET_FILE:pqc_shared>" "${PROJECT_BINARY_DIR}/python/pqc"
    DEPENDS pqc_shared
)
