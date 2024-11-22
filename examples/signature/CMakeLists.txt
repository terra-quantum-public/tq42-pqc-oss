cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)

add_executable(
  example_signature
  example_signature.cpp
)

target_link_libraries(
  example_signature
  pqc
)
