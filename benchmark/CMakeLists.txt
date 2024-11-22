include(FetchContent) 

FetchContent_Declare(benchmark URL "https://github.com/google/benchmark/archive/refs/tags/v1.7.1.zip")

set(BENCHMARK_ENABLE_TESTING OFF)

FetchContent_GetProperties(benchmark)
if(NOT benchmark_POPULATED)
    FetchContent_Populate(benchmark)
    add_subdirectory("${benchmark_SOURCE_DIR}" "${benchmark_BINARY_DIR}" EXCLUDE_FROM_ALL)
endif()

add_executable(
    benchmark_aes
    benchmark_aes.cpp
)

target_link_libraries(
    benchmark_aes
    benchmark::benchmark
    pqc
)

add_executable(
    benchmark_init
    benchmark_init.cpp
)

target_link_libraries(
    benchmark_init
    benchmark::benchmark
    pqc
)
