# boringssl_dart

A Proof of Concept (PoC) for building and binding BoringSSL in Dart using **Dart Hooks** (Native Assets).

## Prerequisites

*   **Dart SDK**: Version 3.10.0 or later.
*   **CMake**: Required for building BoringSSL.

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
    The build hook automatically downloads the required BoringSSL source as a tarball.

## Configuration

The version of BoringSSL used is defined in `native/boringssl_commit.txt`. To upgrade or change the version:
1.  Update the commit hash in `native/boringssl_commit.txt`.
2.  Run `dart test` or build again.

## Architecture

### Build Hook (`hook/build.dart`)

The build hook downloads BoringSSL source from GitHub as a tarball and builds it with CMake. A `.commit` marker file tracks the downloaded version to skip redundant downloads.

### Bindings Generation (`ffigen.dart`)

```bash
dart run ffigen.dart
```

This command runs three steps:
1. **Download BoringSSL source** — fetches the tarball for the commit in `native/boringssl_commit.txt`
2. **Generate `lib/src/bindings.g.dart`** — runs ffigen to produce `@ffi.Native` bindings from BoringSSL headers
3. **Generate `hook/symbols.dart`** — extracts all C symbol names from the generated bindings

### Tree-Shaking via Link Hook (`hook/link.dart`)

> Available on the `link` branch as a reference implementation.

When `linkingEnabled` is true (app builds via Flutter), the build hook outputs static archives (`libssl.a`, `libcrypto.a`) and routes them to the link hook via `ToLinkHook`. The link hook uses `CLinker` with `LinkerOptions.treeshake(symbolsToKeep: symbols)` to produce a shared library containing only the symbols actually referenced by `@ffi.Native` in `bindings.g.dart`.

```
ffigen.dart          hook/build.dart          hook/link.dart
    |                      |                       |
    v                      v                       v
bindings.g.dart  ->  static archives  ->  CLinker.treeshake()
    |                                          |
    v                                          v
symbols.dart  ------>  symbolsToKeep  ->  shared library
```

Key points:
- `symbols.dart` is auto-generated from `bindings.g.dart`, so it stays in sync with the actual bindings without manual maintenance
- When `linkingEnabled` is false (`dart test`), the build hook falls back to building a shared library directly via CMake
- This approach achieved ~4MB reduction on an Android app bundle in testing

## License

MIT License.

> **Note**: BoringSSL itself is a fork of OpenSSL and is licensed under an OpenSSL/ISC-style license. See `third_party/boringssl/LICENSE`.
