add_library(math STATIC
        utils.cpp
        fermat_prime_test.cpp
        solovay_strassen_prime_test.cpp
        miller_rabin_prime_test.cpp
        prime_test.cpp
        continued_fraction.cpp
        primitive_roots.cpp
        gf2n/gf2n_polynomial.cpp
)


target_include_directories(math PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(math PUBLIC gmp gmpxx)