cmake_minimum_required(VERSION 3.23)

project(toy_rsa VERSION 0.1.0 LANGUAGES C)

option(TOY_RSA_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
set(TOY_RSA_BIGINT_MAX_BITS 1024 CACHE STRING
    "Maximum multi-precision integer width in bits")

math(EXPR TOY_RSA_BIGINT_REMAINDER "${TOY_RSA_BIGINT_MAX_BITS} % 16")
if(TOY_RSA_BIGINT_MAX_BITS LESS 16 OR NOT TOY_RSA_BIGINT_REMAINDER EQUAL 0)
    message(FATAL_ERROR
        "TOY_RSA_BIGINT_MAX_BITS must be at least 16 and a multiple of 16")
endif()

add_library(toy_rsa
    src/bigint.c
    src/cbc.c
    src/des.c
    src/des_tables.c
    src/hybrid.c
    src/mmo.c
    src/montgomery.c
    src/number.c
    src/rng.c
    src/rsa.c
)

target_include_directories(toy_rsa
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(toy_rsa
    PUBLIC BIGINT_MAX_BITS=${TOY_RSA_BIGINT_MAX_BITS}
)

set_target_properties(toy_rsa PROPERTIES
    C_STANDARD 90
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
)

if(MSVC)
    target_compile_options(toy_rsa PRIVATE /W4)
    if(TOY_RSA_WARNINGS_AS_ERRORS)
        target_compile_options(toy_rsa PRIVATE /WX)
    endif()
else()
    target_compile_options(toy_rsa PRIVATE -Wall -Wextra -Wpedantic)
    if(TOY_RSA_WARNINGS_AS_ERRORS)
        target_compile_options(toy_rsa PRIVATE -Werror)
    endif()
endif()

add_library(toy_rsa_demo_common STATIC tools/demo_common.c)
target_link_libraries(toy_rsa_demo_common PUBLIC toy_rsa)
target_include_directories(toy_rsa_demo_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/tools
)
set_target_properties(toy_rsa_demo_common PROPERTIES
    C_STANDARD 90
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
)
if(MSVC)
    target_compile_options(toy_rsa_demo_common PRIVATE /W4)
    if(TOY_RSA_WARNINGS_AS_ERRORS)
        target_compile_options(toy_rsa_demo_common PRIVATE /WX)
    endif()
else()
    target_compile_options(toy_rsa_demo_common PRIVATE
        -Wall -Wextra -Wpedantic)
    if(TOY_RSA_WARNINGS_AS_ERRORS)
        target_compile_options(toy_rsa_demo_common PRIVATE -Werror)
    endif()
endif()

function(add_toy_rsa_demo target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE toy_rsa_demo_common)
    set_target_properties(${target} PROPERTIES
        C_STANDARD 90
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
    )
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

add_toy_rsa_demo(toy_des tools/des_demo.c)
add_toy_rsa_demo(toy_rsa_keygen tools/rsa_keygen_demo.c)
add_toy_rsa_demo(toy_hybrid tools/hybrid_demo.c)
set_target_properties(toy_des PROPERTIES OUTPUT_NAME des)
set_target_properties(toy_rsa_keygen PROPERTIES OUTPUT_NAME rsa-keygen)
set_target_properties(toy_hybrid PROPERTIES OUTPUT_NAME hybrid)

add_executable(benchmark_montgomery tools/benchmark.c)
target_link_libraries(benchmark_montgomery PRIVATE toy_rsa)
set_target_properties(benchmark_montgomery PROPERTIES
    C_STANDARD 90
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
)
if(MSVC)
    target_compile_options(benchmark_montgomery PRIVATE /W4)
    if(TOY_RSA_WARNINGS_AS_ERRORS)
        target_compile_options(benchmark_montgomery PRIVATE /WX)
    endif()
else()
    target_compile_options(benchmark_montgomery PRIVATE
        -Wall -Wextra -Wpedantic)
    if(TOY_RSA_WARNINGS_AS_ERRORS)
        target_compile_options(benchmark_montgomery PRIVATE -Werror)
    endif()
endif()

add_executable(benchmark_rsa tools/rsa_benchmark.c)
target_link_libraries(benchmark_rsa PRIVATE toy_rsa)
set_target_properties(benchmark_rsa PROPERTIES
    C_STANDARD 90
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
)
if(MSVC)
    target_compile_options(benchmark_rsa PRIVATE /W4)
    if(TOY_RSA_WARNINGS_AS_ERRORS)
        target_compile_options(benchmark_rsa PRIVATE /WX)
    endif()
else()
    target_compile_options(benchmark_rsa PRIVATE -Wall -Wextra -Wpedantic)
    if(TOY_RSA_WARNINGS_AS_ERRORS)
        target_compile_options(benchmark_rsa PRIVATE -Werror)
    endif()
endif()

include(CTest)

if(BUILD_TESTING)
    add_executable(test_des tests/test_des.c)
    target_link_libraries(test_des PRIVATE toy_rsa)
    set_target_properties(test_des PROPERTIES
        C_STANDARD 90
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
    )
    if(MSVC)
        target_compile_options(test_des PRIVATE /W4)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_des PRIVATE /WX)
        endif()
    else()
        target_compile_options(test_des PRIVATE -Wall -Wextra -Wpedantic)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_des PRIVATE -Werror)
        endif()
    endif()
    add_test(NAME week1_des_internals COMMAND test_des)

    add_executable(test_cbc tests/test_cbc.c)
    target_link_libraries(test_cbc PRIVATE toy_rsa)
    set_target_properties(test_cbc PROPERTIES
        C_STANDARD 90
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
    )
    if(MSVC)
        target_compile_options(test_cbc PRIVATE /W4)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_cbc PRIVATE /WX)
        endif()
    else()
        target_compile_options(test_cbc PRIVATE -Wall -Wextra -Wpedantic)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_cbc PRIVATE -Werror)
        endif()
    endif()
    add_test(NAME week2_des_and_cbc COMMAND test_cbc)

    add_executable(test_mmo tests/test_mmo.c)
    target_link_libraries(test_mmo PRIVATE toy_rsa)
    set_target_properties(test_mmo PROPERTIES
        C_STANDARD 90
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
    )
    if(MSVC)
        target_compile_options(test_mmo PRIVATE /W4)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_mmo PRIVATE /WX)
        endif()
    else()
        target_compile_options(test_mmo PRIVATE -Wall -Wextra -Wpedantic)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_mmo PRIVATE -Werror)
        endif()
    endif()
    add_test(NAME week3_mmo_digest COMMAND test_mmo)

    add_executable(test_rng tests/test_rng.c)
    target_link_libraries(test_rng PRIVATE toy_rsa)
    set_target_properties(test_rng PROPERTIES
        C_STANDARD 90
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
    )
    if(MSVC)
        target_compile_options(test_rng PRIVATE /W4)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_rng PRIVATE /WX)
        endif()
    else()
        target_compile_options(test_rng PRIVATE -Wall -Wextra -Wpedantic)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_rng PRIVATE -Werror)
        endif()
    endif()
    add_test(NAME week4_des_rng COMMAND test_rng)

    add_executable(test_bigint tests/test_bigint.c)
    target_link_libraries(test_bigint PRIVATE toy_rsa)
    set_target_properties(test_bigint PROPERTIES
        C_STANDARD 90
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
    )
    if(MSVC)
        target_compile_options(test_bigint PRIVATE /W4)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_bigint PRIVATE /WX)
        endif()
    else()
        target_compile_options(test_bigint PRIVATE -Wall -Wextra -Wpedantic)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_bigint PRIVATE -Werror)
        endif()
    endif()
    add_test(NAME week5_bigint COMMAND test_bigint)

    add_executable(test_number tests/test_number.c)
    target_link_libraries(test_number PRIVATE toy_rsa)
    set_target_properties(test_number PROPERTIES
        C_STANDARD 90
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
    )
    if(MSVC)
        target_compile_options(test_number PRIVATE /W4)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_number PRIVATE /WX)
        endif()
    else()
        target_compile_options(test_number PRIVATE -Wall -Wextra -Wpedantic)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_number PRIVATE -Werror)
        endif()
    endif()
    add_test(NAME week6_number_theory COMMAND test_number)

    add_executable(test_montgomery tests/test_montgomery.c)
    target_link_libraries(test_montgomery PRIVATE toy_rsa)
    set_target_properties(test_montgomery PROPERTIES
        C_STANDARD 90
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
    )
    if(MSVC)
        target_compile_options(test_montgomery PRIVATE /W4)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_montgomery PRIVATE /WX)
        endif()
    else()
        target_compile_options(test_montgomery PRIVATE
            -Wall -Wextra -Wpedantic)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_montgomery PRIVATE -Werror)
        endif()
    endif()
    add_test(NAME week7_montgomery COMMAND test_montgomery)

    add_executable(test_rsa tests/test_rsa.c)
    target_link_libraries(test_rsa PRIVATE toy_rsa)
    set_target_properties(test_rsa PROPERTIES
        C_STANDARD 90
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
    )
    if(MSVC)
        target_compile_options(test_rsa PRIVATE /W4)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_rsa PRIVATE /WX)
        endif()
    else()
        target_compile_options(test_rsa PRIVATE -Wall -Wextra -Wpedantic)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_rsa PRIVATE -Werror)
        endif()
    endif()
    add_test(NAME week8_rsa COMMAND test_rsa)

    add_executable(test_hybrid tests/test_hybrid.c)
    target_link_libraries(test_hybrid PRIVATE toy_rsa)
    set_target_properties(test_hybrid PROPERTIES
        C_STANDARD 90
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
    )
    if(MSVC)
        target_compile_options(test_hybrid PRIVATE /W4)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_hybrid PRIVATE /WX)
        endif()
    else()
        target_compile_options(test_hybrid PRIVATE -Wall -Wextra -Wpedantic)
        if(TOY_RSA_WARNINGS_AS_ERRORS)
            target_compile_options(test_hybrid PRIVATE -Werror)
        endif()
    endif()
    add_test(NAME week9_hybrid COMMAND test_hybrid)

    add_test(NAME all_file_samples
        COMMAND ${CMAKE_COMMAND}
            -DDES_EXE=$<TARGET_FILE:toy_des>
            -DRSA_KEYGEN_EXE=$<TARGET_FILE:toy_rsa_keygen>
            -DHYBRID_EXE=$<TARGET_FILE:toy_hybrid>
            -DSAMPLE_TEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/sample-test
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_samples.cmake
    )
endif()
