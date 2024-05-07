include(FetchContent)
FetchContent_Declare(googletest URL "https://github.com/google/googletest/archive/e2239ee6043f73722e7aa812a459f54a28552929.zip")
FetchContent_MakeAvailable(googletest)

file(GLOB_RECURSE sources CONFIGURE_DEPENDS "*.cpp")

add_executable(LibPQTest ${sources})
add_executable(LibPQTest_shared ${sources})

add_executable(LibPQTest_C "aes_test.c")

target_link_libraries(LibPQTest "gtest" "pqc")
target_link_libraries(LibPQTest_shared "gtest" "pqc_shared")

# TODO FIXME separate C++ unittests.
target_include_directories(LibPQTest PRIVATE "${PROJECT_SOURCE_DIR}/src")
target_include_directories(LibPQTest_shared PRIVATE "${PROJECT_SOURCE_DIR}/src")

target_link_libraries(LibPQTest_C "pqc")

include(GoogleTest)

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/static" "${CMAKE_CURRENT_BINARY_DIR}/shared")

add_custom_target(copy_pqc_shared_test ALL
    COMMAND "${CMAKE_COMMAND}" "-E" "copy" "$<TARGET_FILE:pqc_shared>" "${CMAKE_CURRENT_BINARY_DIR}/shared"
    DEPENDS pqc_shared
)

gtest_discover_tests(LibPQTest TEST_SUFFIX ".STATIC" WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/static")
gtest_discover_tests(LibPQTest_shared TEST_SUFFIX ".SHARED" WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/shared")

add_test(AES.C.STATIC LibPQTest_C)
