cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)

add_executable(
  ssd_hdd_removal
  ssd_hdd_removal.cpp
)

target_link_libraries(
  ssd_hdd_removal
  pqc
)