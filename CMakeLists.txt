cmake_minimum_required(VERSION 3.23)

project(toy_rsa VERSION 0.1.0 LANGUAGES C)

option(TOY_RSA_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)

add_library(toy_rsa
    src/cbc.c
    src/des.c
    src/des_tables.c
)

target_include_directories(toy_rsa
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
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
set_target_properties(toy_des PROPERTIES OUTPUT_NAME des)

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

    add_test(NAME week2_file_samples
        COMMAND ${CMAKE_COMMAND}
            -DDES_EXE=$<TARGET_FILE:toy_des>
            -DSAMPLE_TEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/sample-test
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_samples.cmake
    )
endif()
