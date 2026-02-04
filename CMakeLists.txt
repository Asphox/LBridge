cmake_minimum_required(VERSION 3.16)
project(LBridge C CXX)

# Options
option(LBRIDGE_BUILD_TESTS "Build test executable" OFF)
option(LBRIDGE_ENABLE_SECURE "Enable ChaCha20-Poly1305 encryption" ON)
option(LBRIDGE_ENABLE_BLUETOOTH "Enable Bluetooth RFCOMM transport" OFF)

# Library source files
set(LBRIDGE_SOURCES
    src/lbridge/lbridge.c
    src/lbridge/internals/socket_backends/lbridge_backend_socket_win_unix.c
    src/lbridge/internals/socket_backends/lbridge_win_wsa_init.c
)

# Bluetooth source (optional)
if(LBRIDGE_ENABLE_BLUETOOTH)
    list(APPEND LBRIDGE_SOURCES
        src/lbridge/internals/socket_backends/lbridge_backend_bluetooth.c
    )
endif()

# mbedtls sources (only if encryption enabled)
if(LBRIDGE_ENABLE_SECURE)
    list(APPEND LBRIDGE_SOURCES
        src/lbridge/mbedtls-chachapoly/mbedtls/chacha20.c
        src/lbridge/mbedtls-chachapoly/mbedtls/chachapoly.c
        src/lbridge/mbedtls-chachapoly/mbedtls/constant_time.c
        src/lbridge/mbedtls-chachapoly/mbedtls/platform_util.c
        src/lbridge/mbedtls-chachapoly/mbedtls/poly1305.c
    )
endif()

# Static library
add_library(lbridge STATIC ${LBRIDGE_SOURCES})

# C11 standard for the library
set_target_properties(lbridge PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)

# Include directories
target_include_directories(lbridge PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lbridge
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lbridge/mbedtls-chachapoly
)

# Preprocessor definitions
target_compile_definitions(lbridge PRIVATE
    $<$<CONFIG:Debug>:_DEBUG>
    $<$<CONFIG:Release>:NDEBUG>
    $<$<PLATFORM_ID:Windows>:WIN32>
    $<$<PLATFORM_ID:Windows>:_CONSOLE>
    $<$<PLATFORM_ID:Windows>:UNICODE>
    $<$<PLATFORM_ID:Windows>:_UNICODE>
)

if(LBRIDGE_ENABLE_SECURE)
    target_compile_definitions(lbridge PUBLIC LBRIDGE_ENABLE_SECURE)
endif()

if(LBRIDGE_ENABLE_BLUETOOTH)
    target_compile_definitions(lbridge PUBLIC LBRIDGE_ENABLE_BLUETOOTH)
endif()

# Compiler flags
if(MSVC)
    target_compile_options(lbridge PRIVATE
        /W3             # Warning level 3
        /WX             # Warnings as errors
        /sdl            # SDL checks
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/GL>    # Whole program optimization
    )
else()
    target_compile_options(lbridge PRIVATE
        -Wall
        -Wextra
        -Werror         # Warnings as errors
        $<$<CONFIG:Release>:-O2>
    )
endif()

# Link libraries
if(WIN32)
    target_link_libraries(lbridge PUBLIC ws2_32 bcrypt)
    if(LBRIDGE_ENABLE_BLUETOOTH)
        target_link_libraries(lbridge PUBLIC bthprops)
    endif()
elseif(UNIX AND NOT APPLE)
    if(LBRIDGE_ENABLE_BLUETOOTH)
        # Linux: link with BlueZ Bluetooth library
        find_library(BLUETOOTH_LIB bluetooth)
        if(BLUETOOTH_LIB)
            target_link_libraries(lbridge PUBLIC ${BLUETOOTH_LIB})
        else()
            message(FATAL_ERROR "Bluetooth enabled but libbluetooth not found. Install libbluetooth-dev or disable LBRIDGE_ENABLE_BLUETOOTH.")
        endif()
    endif()
endif()

# Output directories (all configs to same folder)
set_target_properties(lbridge PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/lib"
    ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/lib"
    ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/lib"
    ARCHIVE_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/lib"
)

# Test executable
if(LBRIDGE_BUILD_TESTS)
    add_executable(lbridge_test src/unit_tests/unit_tests.cpp)

    # C++17 for test executable
    set_target_properties(lbridge_test PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )

    target_link_libraries(lbridge_test PRIVATE lbridge)

    target_compile_definitions(lbridge_test PRIVATE
        $<$<CONFIG:Debug>:_DEBUG>
        $<$<PLATFORM_ID:Windows>:WIN32>
        $<$<PLATFORM_ID:Windows>:_CONSOLE>
        $<$<PLATFORM_ID:Windows>:UNICODE>
        $<$<PLATFORM_ID:Windows>:_UNICODE>
    )

    if(MSVC)
        target_compile_options(lbridge_test PRIVATE /W3 /sdl)
    else()
        target_compile_options(lbridge_test PRIVATE -Wall -Wextra)
    endif()

    set_target_properties(lbridge_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin"
    )
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "LBridge Configuration:")
message(STATUS "  Encryption (ChaCha20-Poly1305): ${LBRIDGE_ENABLE_SECURE}")
message(STATUS "  Bluetooth RFCOMM: ${LBRIDGE_ENABLE_BLUETOOTH}")
message(STATUS "  Build tests: ${LBRIDGE_BUILD_TESTS}")
message(STATUS "")
