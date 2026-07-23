# boringssl_dart

A Proof of Concept (PoC) for building and binding BoringSSL in Dart using **Dart Hooks** (Native Assets).

## Prerequisites

*   **Dart SDK**: Version 3.10.0 or later.
*   **A C/C++ toolchain**: clang (macOS/Linux/Android/iOS) or MSVC (Windows), plus `tar` — used by the build hook to compile BoringSSL. No CMake required.

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

The build hook downloads BoringSSL source from GitHub as a commit-addressed tarball into the hook's shared output directory (`.dart_tool/`), then compiles `libcrypto` directly with `CBuilder` from `package:native_toolchain_c` — **no CMake, no generator step**. The source file list is read straight from BoringSSL's checked-in `gen/sources.json` (the `bcm` + `crypto` targets and their per-`(arch, os)` `.S` assembly). A `.commit` marker file tracks the checked-out version so later builds skip the download and run offline.

On macOS, Linux, Android, and iOS the full `.S` assembly set is handed to clang — each file self-guards on architecture/OS macros, so only the matching ones assemble. On **Windows** the assembly is nasm syntax the C toolchain cannot drive, so the build compiles the pure-C `OPENSSL_NO_ASM` variant instead.

### Bindings Generation (`ffigen.dart`)

```bash
dart run ffigen.dart
```

This command runs three steps:
1. **Download BoringSSL source** — fetches the tarball for the commit in `native/boringssl_commit.txt`
2. **Generate `lib/src/bindings.g.dart`** — runs ffigen to produce `@ffi.Native` bindings from BoringSSL headers
3. **Generate `hook/symbols.dart`** — extracts all C symbol names from the generated bindings

### Tree-Shaking via Link Hook (`hook/link.dart`)

> The link hook ships on `main`; the link-hook path is exercised by the AOT smoke check in CI on every desktop platform (Linux, macOS, Windows).

When `linkingEnabled` is true (app/CLI builds, e.g. Flutter or `dart build cli`), the build hook outputs a static `libcrypto` archive and routes it to the link hook via `ToLinkHook`. The link hook uses `CLinker` with `LinkerOptions.treeshake(symbolsToKeep: symbols)` to produce a shared library containing only the symbols actually referenced by `@ffi.Native` in `bindings.g.dart`.

```
ffigen.dart          hook/build.dart          hook/link.dart
    |                      |                       |
    v                      v                       v
bindings.g.dart  ->  static archive   ->  CLinker.treeshake()
    |                (CBuilder)                    |
    v                                              v
symbols.dart  ------>  symbolsToKeep  ->  shared library
```

Key points:
- `symbols.dart` is auto-generated from `bindings.g.dart`, so it stays in sync with the actual bindings without manual maintenance
- When `linkingEnabled` is false (`dart test`), the build hook falls back to compiling `libcrypto` as a shared library directly (`CBuilder`, dynamic link mode)
- This approach achieved ~4MB reduction on an Android app bundle in testing

### Platform notes

The compiled library links the C++ standard library dynamically. On **Android** that means the app must ship `libc++_shared.so` — the Dart native-assets build does **not** bundle it automatically (verified: the app crashes at load with `dlopen failed: library "libc++_shared.so" not found` otherwise), so an Android app depending on `boringssl_dart` must add a dependency on [`package:android_libcpp_shared`](https://pub.dev/packages/android_libcpp_shared), as [`example/flutter_app`](example/flutter_app) does. Android and iOS are verified on-device by that example's `integration_test` (iOS simulator + Android emulator); macOS is verified locally and Linux/Windows in CI. Mobile is not yet in CI.

The rationale behind the build hooks — the settings carried over from the removed CMake build, the Android C++ runtime choice, the deferred `@RecordUse` narrowing, and the error-handling posture — is recorded in [`doc/design-notes.md`](doc/design-notes.md).

## License

MIT License.

> **Note**: BoringSSL itself is a fork of OpenSSL and is licensed under an OpenSSL/ISC-style license. See the [upstream `LICENSE`](https://github.com/google/boringssl/blob/master/LICENSE).
