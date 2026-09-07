add_executable(cli_test
    main.cpp
)

add_executable(rijndael_demo
    rijndael_demo.cpp
)

add_executable(twofish_mars_demo
    twofish_mars_demo.cpp
)

add_executable(asymmetric_demo
    asymmetric_demo.cpp
)

target_link_libraries(cli_test PRIVATE crypto)
target_link_libraries(rijndael_demo PRIVATE crypto math)
target_link_libraries(twofish_mars_demo PRIVATE crypto math)
target_link_libraries(asymmetric_demo PRIVATE crypto math)

target_include_directories(cli_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_include_directories(rijndael_demo PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_include_directories(twofish_mars_demo PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_include_directories(asymmetric_demo PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

set_target_properties(cli_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

set_target_properties(rijndael_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

set_target_properties(twofish_mars_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

set_target_properties(asymmetric_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
