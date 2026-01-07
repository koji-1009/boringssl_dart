# boringssl_dart

A Proof of Concept (PoC) for building and binding BoringSSL in Dart using **Dart Hooks** (Native Assets).

## Prerequisites

*   **Dart SDK**: Version 3.10.0 or later.
*   **CMake**: Required for building BoringSSL.
*   **Git**: Required for downloading BoringSSL source code.
*   **NASM** (Windows only): Required for assembly optimizations.

## Getting Started

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/koji-1009/boringssl_dart.git
    cd boringssl_dart
    ```

2.  **Run Tests:**
    ```bash
    dart pub get
    dart test
    ```
    (The build script will automatically clone and checkout the required BoringSSL version.)

## Configuration

The version of BoringSSL used is defined in `native/boringssl_commit.txt`. To upgrade or change the version:
1.  Update the commit hash in `native/boringssl_commit.txt`.
2.  Run `dart test` or build again.

## Development

To regenerate bindings via ffigen:
```bash
dart run ffigen.dart
```
This command will also automatically sync the BoringSSL source code to the commit specified in `native/boringssl_commit.txt`.

## License

MIT License.

> **Note**: BoringSSL itself is a fork of OpenSSL and is licensed under an OpenSSL/ISC-style license. See `third_party/boringssl/LICENSE`.
