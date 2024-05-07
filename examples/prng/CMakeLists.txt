cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)

add_executable(
  prng_example
  prng_example.cpp
)

target_link_libraries(
  prng_example
  pqc
)