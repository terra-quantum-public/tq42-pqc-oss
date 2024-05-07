cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)

add_executable(
  asymmetric_container_example_1_falcon
  asymmetric_container_example_1_falcon.cpp
)

target_link_libraries(
  asymmetric_container_example_1_falcon
  pqc
)

add_executable(
  asymmetric_container_example_2_to_from_byte_string_falcon
  asymmetric_container_example_2_to_from_byte_string_falcon.cpp
)

target_link_libraries(
  asymmetric_container_example_2_to_from_byte_string_falcon
  pqc
)

add_executable(
  asymmetric_container_example_3_write_read_to_file_falcon
  asymmetric_container_example_3_write_read_to_file_falcon.cpp
)

target_link_libraries(
  asymmetric_container_example_3_write_read_to_file_falcon
  pqc
)


add_executable(
  asymmetric_container_example_1_mceliece
  asymmetric_container_example_1_mceliece.cpp
)

target_link_libraries(
  asymmetric_container_example_1_mceliece
  pqc
)

add_executable(
  asymmetric_container_example_2_to_from_byte_string_mceliece
  asymmetric_container_example_2_to_from_byte_string_mceliece.cpp
)

target_link_libraries(
  asymmetric_container_example_2_to_from_byte_string_mceliece
  pqc
)

add_executable(
  asymmetric_container_example_3_write_read_to_file_mceliece
  asymmetric_container_example_3_write_read_to_file_mceliece.cpp
)

target_link_libraries(
  asymmetric_container_example_3_write_read_to_file_mceliece
  pqc
)
