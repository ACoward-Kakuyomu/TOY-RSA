if(NOT DEFINED DES_EXE OR
   NOT DEFINED SAMPLE_TEST_DIR)
    message(FATAL_ERROR "sample executable paths and test directory are required")
endif()

file(REMOVE_RECURSE "${SAMPLE_TEST_DIR}")
file(MAKE_DIRECTORY "${SAMPLE_TEST_DIR}")

set(plain "${SAMPLE_TEST_DIR}/plain.txt")
set(key_entropy "${SAMPLE_TEST_DIR}/key-entropy.bin")
set(message_entropy "${SAMPLE_TEST_DIR}/message-entropy.bin")
set(des_cipher "${SAMPLE_TEST_DIR}/des.bin")
set(des_plain "${SAMPLE_TEST_DIR}/des-restored.txt")

file(WRITE "${plain}"
    "TOY-RSA sample file\nDES-CBC and hybrid round trip.\n")
file(WRITE "${key_entropy}"
    "CTest key entropy input for historical demonstration only.\n")
file(WRITE "${message_entropy}"
    "Separate CTest message entropy for historical demonstration.\n")

function(run_sample label)
    execute_process(
        COMMAND ${ARGN}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error
    )
    if(NOT result EQUAL 0)
        message(FATAL_ERROR
            "${label} failed (${result})\nstdout:\n${output}\nstderr:\n${error}")
    endif()
endfunction()

run_sample("DES encryption"
    "${DES_EXE}" encrypt 133457799BBCDFF1 0102030405060708
    "${plain}" "${des_cipher}")
run_sample("DES decryption"
    "${DES_EXE}" decrypt 133457799BBCDFF1 0102030405060708
    "${des_cipher}" "${des_plain}")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E compare_files "${plain}" "${des_plain}"
    RESULT_VARIABLE compare_result
)
if(NOT compare_result EQUAL 0)
    message(FATAL_ERROR "DES sample round trip differs")
endif()
