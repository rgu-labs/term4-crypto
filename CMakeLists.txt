cmake_minimum_required(VERSION 4.0)

project(rgu-labs-term4-crypto LANGUAGES C CXX)

include(FetchContent)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()

include_directories(src)

add_subdirectory(src/crypto)
add_subdirectory(src/cli_test)
add_subdirectory(src/math)
add_subdirectory(src/rsa_vulnerabilities)
add_subdirectory(tests)
