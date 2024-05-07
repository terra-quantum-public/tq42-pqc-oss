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