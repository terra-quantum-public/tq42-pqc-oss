cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)

add_executable(
  container_example_1
  container_example_1.cpp
)

target_link_libraries(
  container_example_1
  pqc
)

add_executable(
  container_example_2_to_from_byte_string
  container_example_2_to_from_byte_string.cpp
)

target_link_libraries(
  container_example_2_to_from_byte_string
  pqc
)

add_executable(
  container_example_3_write_read_to_file
  container_example_3_write_read_to_file.cpp
)

target_link_libraries(
  container_example_3_write_read_to_file
  pqc
)
