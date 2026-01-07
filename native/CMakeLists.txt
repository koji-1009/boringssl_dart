cmake_minimum_required(VERSION 3.10)

project(boringssl_dart C CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Windows: Fix platform detection (force AMD64 if undefined) to ensure NASM usage
if(WIN32 AND NOT CMAKE_SYSTEM_PROCESSOR)
    set(CMAKE_SYSTEM_PROCESSOR "AMD64")
endif()

# BoringSSL Configuration
set(BUILD_SHARED_LIBS OFF)
set(BUILD_TESTING OFF)
add_definitions(-DOPENSSL_SMALL)

# Size Optimization for Release builds (not on Windows - causes build issues)
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND NOT WIN32)
    # Link-Time Optimization (IPO/LTO) - significant size reduction
    include(CheckIPOSupported)
    check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
    if(ipo_supported)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()

    # Compiler flags for size optimization
    add_compile_options(-Os -fdata-sections -ffunction-sections)
    # Strip unneeded symbols on link
    if(APPLE)
        add_link_options(-Wl,-dead_strip)
    else()
        add_link_options(-Wl,--gc-sections -Wl,--strip-all)
    endif()
endif()

# Windows: Define these BEFORE add_subdirectory so BoringSSL picks them up
if(WIN32)
    add_definitions(-D_HAS_EXCEPTIONS=0 -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_CRT_SECURE_NO_WARNINGS)
    # Force BoringSSL objects to be compiled with __declspec(dllexport)
    add_definitions(-DBORINGSSL_SHARED_LIBRARY)
endif()

# iOS: Prevent bssl from being built as MACOSX_BUNDLE (causes install error)
# BoringSSL's "install(TARGETS bssl)" fails because iOS sets MACOSX_BUNDLE=ON
# for all executables, but bssl's install command lacks BUNDLE DESTINATION.
if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(CMAKE_MACOSX_BUNDLE OFF)
endif()

add_subdirectory(../third_party/boringssl boringssl EXCLUDE_FROM_ALL)

# Target Definition
add_library(boringssl_dart SHARED boringssl_dart.cc)

target_include_directories(boringssl_dart PUBLIC
    ../third_party/boringssl/include
    .
)

# Visibility & Symbol Export
set_target_properties(boringssl_dart PROPERTIES CXX_VISIBILITY_PRESET default)
set_target_properties(boringssl_dart PROPERTIES VISIBILITY_INLINES_HIDDEN 0)

# Force BoringSSL targets to export symbols
set_target_properties(ssl crypto fipsmodule PROPERTIES CXX_VISIBILITY_PRESET default)
set_target_properties(ssl crypto fipsmodule PROPERTIES C_VISIBILITY_PRESET default)
set_target_properties(ssl crypto fipsmodule PROPERTIES VISIBILITY_INLINES_HIDDEN 0)

# Platform-specific Linking
if(WIN32)
    if(MSVC)
        target_link_options(boringssl_dart PRIVATE "/WHOLEARCHIVE:$<TARGET_FILE:ssl>" "/WHOLEARCHIVE:$<TARGET_FILE:crypto>")
    endif()

    target_link_libraries(boringssl_dart PRIVATE ssl crypto ws2_32)

elseif(APPLE)
    target_link_libraries(boringssl_dart PRIVATE -Wl,-all_load ssl crypto)

else() # Linux / Unix / Android
    target_link_libraries(boringssl_dart PRIVATE -Wl,--whole-archive ssl crypto -Wl,--no-whole-archive)

    if(ANDROID)
        target_link_libraries(boringssl_dart PRIVATE "-Wl,-z,max-page-size=16384")
    endif()

    find_package(Threads REQUIRED)
    target_link_libraries(boringssl_dart PRIVATE Threads::Threads)
endif()
