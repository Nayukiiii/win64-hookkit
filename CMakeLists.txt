cmake_minimum_required(VERSION 3.20)
project(win64_hookkit VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(HOOKKIT_WITH_DETOURS "Enable Microsoft Detours integration in patch_core" OFF)
option(HOOKKIT_WITH_MASM "Build x64 MASM lossless context-capture trampolines (requires ml64)" ON)

set(HOOKKIT_SOURCES
    src/system_routes.cpp
    src/hook_transaction.cpp
    src/thread_admission.cpp
    src/health.cpp
    src/session_ring.cpp
    src/patch_receipt.cpp
    src/int3_guard.cpp
)

if(HOOKKIT_WITH_MASM AND MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    enable_language(ASM_MASM)
    list(APPEND HOOKKIT_SOURCES src/context_trampoline_x64.asm)
endif()

add_library(hookkit STATIC ${HOOKKIT_SOURCES})

target_include_directories(hookkit
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(MSVC)
    target_compile_options(hookkit PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W4 /EHsc>)
endif()

option(HOOKKIT_BUILD_TESTS "Build win64-hookkit native C++17/MASM test suite" ON)
if(HOOKKIT_BUILD_TESTS)
    enable_testing()
    add_executable(hookkit_test tests/test_hookkit_native.cpp)
    target_link_libraries(hookkit_test PRIVATE hookkit)
    if(MSVC)
        target_compile_options(hookkit_test PRIVATE /W4 /EHsc)
    endif()
    add_test(NAME hookkit_test COMMAND hookkit_test)
endif()
