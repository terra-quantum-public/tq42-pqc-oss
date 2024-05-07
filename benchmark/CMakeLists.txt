include(FetchContent) 

FetchContent_Declare(benchmark URL "https://github.com/google/benchmark/archive/refs/tags/v1.7.1.zip")

set(BENCHMARK_ENABLE_TESTING OFF)

FetchContent_GetProperties(benchmark)
if(NOT benchmark_POPULATED)
    FetchContent_Populate(benchmark)
    add_subdirectory("${benchmark_SOURCE_DIR}" "${benchmark_BINARY_DIR}" EXCLUDE_FROM_ALL)
endif()

add_executable(
    pqc_benchmark
    pqc_benchmark.cpp
)

target_link_libraries(
    pqc_benchmark
    benchmark::benchmark
    pqc
)
