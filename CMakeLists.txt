cmake_minimum_required(VERSION 3.23)

project(toy_rsa VERSION 0.1.0 LANGUAGES C)

option(TOY_RSA_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)

add_library(toy_rsa
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
endif()
