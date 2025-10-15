cmake_minimum_required(VERSION 3.10)
project(hw02 C)
set(CMAKE_C_STANDARD 11)

# Point everything to your local OpenSSL 3.3.1 build
set(OPENSSL_ROOT_DIR /usr/local)
set(OPENSSL_INCLUDE_DIR /usr/local/include)
set(OPENSSL_CRYPTO_LIBRARY /usr/local/lib64/libcrypto.so)
set(OPENSSL_SSL_LIBRARY /usr/local/lib64/libssl.so)
set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(hw02 generate_files.c)

# Link against both SSL and Crypto, both from /usr/local
target_link_libraries(hw02 PRIVATE ${OPENSSL_LIBRARIES})

# Ensure runtime finds your /usr/local libs
set_target_properties(hw02 PROPERTIES
        BUILD_RPATH "/usr/local/lib64"
        INSTALL_RPATH "/usr/local/lib64"
)
