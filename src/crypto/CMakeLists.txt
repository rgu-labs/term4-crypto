add_library(crypto STATIC
        internal/bits/permute.cpp
        internal/bits/substitute.cpp
        internal/bits/utils.cpp
        internal/core/feistel_network.cpp
        internal/core/feistel_network_wrapper.cpp
        symmetric/algorithms/des/des.cpp
        symmetric/algorithms/triple_des/triple_des.cpp
        symmetric/padding/padding.cpp
        symmetric/mode/modes.cpp
        symmetric/cipher_context.cpp
        stream/algorithms/rc4/encoder.cpp
        asymmetric/algorithms/rsa/key_generator.cpp
        asymmetric/algorithms/rsa/rsa.cpp
        asymmetric/algorithms/rsa/key_serializer.cpp
        symmetric/algorithms/twofish/twofish.cpp
        symmetric/algorithms/mars/mars.cpp
        symmetric/algorithms/aes/rijndael_sbox.cpp
        symmetric/algorithms/aes/rijndael.cpp
        asymmetric/algorithms/dh/dh.cpp
        asymmetric/algorithms/elgamal/elgamal.cpp
        asymmetric/algorithms/ntru/ntru.cpp
        asymmetric/algorithms/rabin/key_generator.cpp
        asymmetric/algorithms/rabin/rabin.cpp
)

target_include_directories(crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

find_package(OpenSSL REQUIRED)

target_link_libraries(crypto PUBLIC math OpenSSL::Crypto)