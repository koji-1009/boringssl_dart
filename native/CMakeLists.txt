cmake_minimum_required(VERSION 3.10)

project(boringssl_dart C CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(WIN32 AND NOT CMAKE_SYSTEM_PROCESSOR)
    set(CMAKE_SYSTEM_PROCESSOR "AMD64")
endif()

# BoringSSL configuration
set(BUILD_SHARED_LIBS OFF)
set(BUILD_TESTING OFF)
add_definitions(-DOPENSSL_SMALL)

# Size optimization (Release, non-Windows)
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND NOT WIN32)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
    if(ipo_supported)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()

    # -fdata-sections/-ffunction-sections enable fine-grained GC by the linker
    add_compile_options(-Os -fdata-sections -ffunction-sections)
endif()

if(WIN32)
    add_definitions(-D_HAS_EXCEPTIONS=0 -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DBORINGSSL_SHARED_LIBRARY)
endif()

# Prevent bssl from being built as MACOSX_BUNDLE on iOS
if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(CMAKE_MACOSX_BUNDLE OFF)
endif()

add_subdirectory(../third_party/boringssl boringssl EXCLUDE_FROM_ALL)

# Shared library fallback (used when link hooks are unavailable, e.g. dart test).
# When link hooks ARE available, only the static ssl/crypto archives are needed
# and CLinker in hook/link.dart handles the final shared library with tree-shaking.
option(BUILD_SHARED_BORINGSSL_DART "Build boringssl_dart shared library" OFF)
if(BUILD_SHARED_BORINGSSL_DART)
    add_library(boringssl_dart SHARED boringssl_dart.cc)
    target_include_directories(boringssl_dart PUBLIC ../third_party/boringssl/include .)

    set_target_properties(boringssl_dart PROPERTIES
        CXX_VISIBILITY_PRESET default VISIBILITY_INLINES_HIDDEN 0)
    set_target_properties(ssl crypto fipsmodule PROPERTIES
        CXX_VISIBILITY_PRESET default C_VISIBILITY_PRESET default VISIBILITY_INLINES_HIDDEN 0)

    if(WIN32)
        if(MSVC)
            target_link_options(boringssl_dart PRIVATE
                "/WHOLEARCHIVE:$<TARGET_FILE:ssl>" "/WHOLEARCHIVE:$<TARGET_FILE:crypto>")
        endif()
        target_link_libraries(boringssl_dart PRIVATE ssl crypto ws2_32)
    elseif(APPLE)
        target_link_libraries(boringssl_dart PRIVATE -Wl,-all_load ssl crypto)
    else()
        target_link_libraries(boringssl_dart PRIVATE
            -Wl,--whole-archive ssl crypto -Wl,--no-whole-archive)
        if(ANDROID)
            target_link_libraries(boringssl_dart PRIVATE "-Wl,-z,max-page-size=16384")
        endif()
        find_package(Threads REQUIRED)
        target_link_libraries(boringssl_dart PRIVATE Threads::Threads)
    endif()
endif()
