cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)

add_executable(
pbkdf2_example
pbkdf2_example.cpp
) 

target_link_libraries(
pbkdf2_example
pqc
)