# boringssl_dart

A Proof of Concept (PoC) for building and binding BoringSSL in Dart using **Dart Hooks** (Native Assets).

## Prerequisites

*   **Dart SDK**: Version 3.10.0 or later.
*   **CMake**: Required for building BoringSSL.
*   **Git**: Required for fetching submodules.
*   **NASM** (Windows only): Required for assembly optimizations.

## Getting Started

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/koji-1009/boringssl_dart.git
    cd boringssl_dart
    ```

2.  **Sync Submodules (Important):**
    ```bash
    git submodule update --init --recursive
    ```

3.  **Run Tests:**
    ```bash
    dart pub get
    dart test
    ```

## License

MIT License.

> **Note**: BoringSSL itself is a fork of OpenSSL and is licensed under an OpenSSL/ISC-style license. See `third_party/boringssl/LICENSE`.
