cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)

add_executable(
  falcon_example
  falcon_example.cpp
)

target_link_libraries(
  falcon_example
  pqc
)

add_executable(
  example_mldsa
  example_mldsa.cpp
)

target_link_libraries(
  example_mldsa
  pqc
)

add_executable(
  example_slhdsa
  example_slhdsa.cpp
)

target_link_libraries(
  example_slhdsa
  pqc
)
