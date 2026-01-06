cmake_minimum_required(VERSION 3.10)

project(boringssl_dart C CXX)

set(CMAKE_CXX_STANDARD 14) # BoringSSL requires C++14 or later
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# BoringSSL settings: Build as static libraries to link into our shared library.
set(BUILD_SHARED_LIBS OFF)
set(BUILD_TESTING OFF)

# Add BoringSSL subdirectory.
# EXCLUDE_FROM_ALL prevents building unnecessary targets (like tests/tools) by default.
add_subdirectory(../third_party/boringssl boringssl EXCLUDE_FROM_ALL)

# Define our shared library.
# We link against the static libraries 'ssl' and 'crypto' built by BoringSSL.
add_library(boringssl_dart SHARED boringssl_dart.cc)

set_target_properties(boringssl_dart PROPERTIES CXX_VISIBILITY_PRESET default)
set_target_properties(boringssl_dart PROPERTIES VISIBILITY_INLINES_HIDDEN 0)

# Include directories.
# We need to include both the source include directory and the shim header directory.
target_include_directories(boringssl_dart PUBLIC 
    ../third_party/boringssl/include
    .
)

# Force BoringSSL targets to have default visibility so they can be exported.
# fipsmodule contains core crypto functions like EVP_MD_CTX_new.
set_target_properties(ssl crypto fipsmodule PROPERTIES CXX_VISIBILITY_PRESET default)
set_target_properties(ssl crypto fipsmodule PROPERTIES C_VISIBILITY_PRESET default)
set_target_properties(ssl crypto fipsmodule PROPERTIES VISIBILITY_INLINES_HIDDEN 0)

# Link BoringSSL libraries with force-load flags to export symbols.
if(APPLE)
    target_link_libraries(boringssl_dart PRIVATE -Wl,-all_load ssl crypto)
elseif(UNIX AND NOT WIN32)
    # UNIX includes Linux and Android.
    # -Wl,-z,max-page-size=16384 is required for Android 15+ (16KB page size support).
    # It sets ELF segment alignment to 16KB. This is compatible with 4KB pages too.
    target_link_libraries(boringssl_dart PRIVATE 
        -Wl,--whole-archive ssl crypto -Wl,--no-whole-archive
        "-Wl,-z,max-page-size=16384"
    )
else()
    target_link_libraries(boringssl_dart PRIVATE ssl crypto)
endif()

# Windows specific settings for symbol export.
if(WIN32)
    set_target_properties(boringssl_dart PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    add_definitions(-D_HAS_EXCEPTIONS=0 -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_CRT_SECURE_NO_WARNINGS)
endif()