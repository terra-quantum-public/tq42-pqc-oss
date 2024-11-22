cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)


add_executable(
  example_kem
  example_kem.cpp
)

target_link_libraries(
  example_kem
  pqc
)
