# Design notes

`boringssl_dart` is an experimental project: it compiles BoringSSL's `libcrypto` from a pinned source commit at hook (native-assets) time and tree-shakes it to the symbols the `@ffi.Native` bindings use. This document records the non-obvious build and toolchain decisions and the reasoning behind them, so the knowledge behind the hooks is not lost to a future reader (or a future bump).

For the user-facing overview see the [README](../README.md); this is the "why".

## Build hooks: from source, no CMake

The build hook (`hook/build.dart`) fetches BoringSSL's commit-addressed tarball into the hook's shared output directory and compiles `libcrypto` directly with `CBuilder` from `package:native_toolchain_c` — **no CMake, no perl/go/nasm generator step**. The source list is read straight from BoringSSL's checked-in `gen/sources.json` (`bcm` + `crypto` targets and their per-`(arch, os)` `.S` assembly), so a BoringSSL bump is a one-line change to `native/boringssl_commit.txt`.

Two output modes:

- **Standalone** (`linkingEnabled == false`, e.g. `dart test`): the full `libcrypto` is compiled to a dynamic library and bundled directly.
- **Link-hook** (`linkingEnabled == true`, AOT `dart build`): the compile emits a static archive routed to `hook/link.dart`, which tree-shakes it with `LinkerOptions.treeshake(symbolsToKeep: symbols)` down to the bound symbols.

The generated `.S` files self-guard on architecture/OS macros (`OPENSSL_X86_64`, `__APPLE__`, `__ELF__`, …), so the whole set is handed to clang and only the matching files assemble. **Windows** has no GAS toolchain in native_toolchain_c (upstream's Windows asm is nasm), so it builds the pure-C `OPENSSL_NO_ASM` variant.

## Compile/link settings carried over from the old CMake

Folding `native/CMakeLists.txt` into a single `CBuilder`/`CLinker` call made it easy to silently drop settings that CMake applied. These must be preserved (each is pinned with a comment at its site in `hook/build.dart` / `hook/toolchain.dart`):

| Setting | Why | Scope |
| --- | --- | --- |
| `-DBORINGSSL_IMPLEMENTATION` | Internal headers gate exported symbols on it | all |
| `-DOPENSSL_SMALL` + `OptimizationLevel.oS` (`-Os`/`/Os`) | Keep the shipped `libcrypto` small — the project's whole point; native_toolchain_c defaults to `-O3` | all |
| `-D_XOPEN_SOURCE=700` | Exposes `pthread_rwlock_t` on glibc; on Apple it instead *disables* APIs BoringSSL uses; bionic needs none | Linux only |
| `-DOPENSSL_NO_ASM` | No nasm in the C toolchain | Windows only |
| `-DBORINGSSL_SHARED_LIBRARY` | Windows PE never auto-exports; without it the standalone DLL exports **no** symbols and every `@ffi.Native` lookup fails. Excluded on the link-hook path so the CLinker treeshake drives the export table via explicit `/EXPORT` instead of dllexport-ing everything | Windows standalone only |
| C++ runtime + system libs (`boringSslLinkLibraries`) | The hooks omit `language: cpp` (its global `-x c++` would break the `.S` inputs), so the C driver auto-links neither the C++ runtime BoringSSL's destructors need nor the system libs the full crypto library uses: `ws2_32` (Windows, `bio/socket*.cc`) and `pthread` (Linux, `thread_pthread.cc`) | per OS |

`boringSslLinkLibraries` throws `UnsupportedError` for an unhandled target OS rather than silently linking nothing, so a new target fails with a clear message instead of an `operator delete` / `__cxa_*` undefined-symbol error deep in the linker.

## C++ runtime on Android

`boringSslLinkLibraries(OS.android)` returns `c++_shared`, so the produced library carries a `DT_NEEDED` on `libc++_shared.so` (an NDK runtime, not a device system library). This is deliberate, and matches Android NDK guidance — it is **not** a regression from the old CMake `ANDROID_STL=c++_static`:

- BoringSSL here is a **distributed / middleware** shared library, and a Flutter app is always a **multi-native-library** process (the engine, other plugins). The NDK's rule: with more than one shared library, use `c++_shared`; linking `libc++` statically in several libraries duplicates the C++ runtime and breaks the One Definition Rule (typeinfo, exceptions, static globals). So `c++_static` would be the riskier choice here.
- The NDK's middleware advice is "use `c++_shared`, or hide libc++'s symbols with a version script." The link-hook path already does the latter: its `treeshake` exports only the crypto keep-list, so libc++ symbols are not part of the library's ABI surface.

The residual is a **packaging** requirement, not a code defect: an app must ship `libc++_shared.so`, and — verified on-device — the Dart native-assets build does **not** bundle it automatically. An Android app depending on `boringssl_dart` must add [`package:android_libcpp_shared`](https://pub.dev/packages/android_libcpp_shared), whose build hook bundles the NDK's `libc++_shared.so` per architecture; `example/flutter_app` does exactly this, and without it the on-device run fails at load with `dlopen failed: library "libc++_shared.so" not found`.

Sources:

- [Bind to native code using FFI — Flutter](https://docs.flutter.dev/platform-integration/bind-native-code)
- [C++ library support — Android NDK](https://developer.android.com/ndk/guides/cpp-support)
- [Advice for middleware vendors — Android NDK](https://developer.android.com/ndk/guides/middleware-vendors)

## Symbol keep-list and `@RecordUse` (record-use)

The tree-shake keep-list (`hook/symbols.dart`) is a flat `const List<String>` auto-generated from `lib/src/bindings.g.dart` by `ffigen.dart`, so it stays in sync with the bindings without hand-maintenance.

A further narrowing exists in principle: annotate each binding with `@RecordUse()` and, on a `record-use` AOT build, narrow the keep-list to the bindings the app actually reaches (an app that only hashes carries no RSA code). This is **deferred**: `ffigen` 20.1.1 (the pinned version) cannot emit `@RecordUse()`; that generation lands in `ffigen` 21.0.0 (unreleased, `21.0.0-wip`). When 21.0.0 ships, enabling `recordUse` regenerates the bindings with the annotations — no hand-editing — and `hook/link.dart` can switch to `input.recordedUses`. Until then every build keeps the full bound surface.

## Error handling posture

- A native failure surfaces the **human-readable** BoringSSL error string (`ERR_error_string_n`), and consuming it **drains the whole error queue unconditionally** (`ERR_get_error` + `ERR_clear_error`), so a residual error never leaks into the next call on the thread.
- Verify paths **fail closed**: a signature that does not verify returns `false` and drains the queue, never throws.
- `test/leak_test.dart` guards this under repetition: thousands of alternating valid/invalid verifications must stay stable with an empty error queue at the end.

## Platform / verification status

| Platform | Status |
| --- | --- |
| macOS | Verified locally — `dart test` + AOT link-hook smoke |
| Linux (x64/arm), Windows | CI — `dart test` + AOT smoke |
| Android, iOS | Verified on-device via `example/flutter_app` — `integration_test/crypto_test.dart` passes on an iOS simulator and an Android emulator. Not yet in CI. Android additionally requires `package:android_libcpp_shared` (see above) |
