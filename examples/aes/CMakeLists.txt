cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)

add_executable(
  aes_cbc_example
  aes_cbc_example.cpp
)

target_link_libraries(
  aes_cbc_example
  pqc
)

add_executable(
  aes_ctr_example
  aes_ctr_example.cpp
)

target_link_libraries(
  aes_ctr_example
  pqc
)

add_executable(
  aes_ecb_example
  aes_ecb_example.cpp
)

target_link_libraries(
  aes_ecb_example
  pqc
)

add_executable(
  aes_ofb_example
  aes_ofb_example.cpp
)

target_link_libraries(
  aes_ofb_example
  pqc
)

add_executable(
  aes_gcm_example
  aes_gcm_example.cpp
)

target_link_libraries(
  aes_gcm_example
  pqc
)
