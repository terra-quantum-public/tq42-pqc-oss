cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)

add_executable(
  kem_mceliece
  kem_mceliece.cpp
)

target_link_libraries(
  kem_mceliece
  pqc
)
