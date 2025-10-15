cmake_minimum_required(VERSION 3.10)
project(hw02 C)

set(CMAKE_C_STANDARD 11)

add_executable(hw02 generate_files.c)

# Trova OpenSSL e linka correttamente libcrypto
find_package(OpenSSL REQUIRED)
target_link_libraries(hw02 PRIVATE OpenSSL::Crypto)
