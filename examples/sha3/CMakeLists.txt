cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)

add_executable(
  const_size_sha3_example
  const_size_sha3_example.cpp
)

target_link_libraries(
  const_size_sha3_example
  pqc
)

add_executable(
  shake_sha3_example
  shake_sha3_example.cpp
)

target_link_libraries(
  shake_sha3_example
  pqc
)
