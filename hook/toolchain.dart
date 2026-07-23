/// Shared native-toolchain helpers for the build and link hooks.
library;

import 'package:code_assets/code_assets.dart';

/// The libraries the C driver must link explicitly when producing BoringSSL's
/// `libcrypto`.
///
/// Both hooks omit `language: cpp` (its global `-x c++` would break the `.S`
/// inputs), so clang runs as a C driver and does not auto-link:
///   * the C++ runtime BoringSSL's C++ destructors reference (`operator
///     delete`), and
///   * the system libraries the full crypto library depends on — winsock
///     (`ws2_32`) on Windows for `bio/socket*.cc`, and `pthread` on Linux for
///     `thread_pthread.cc` (folded into libc on glibc >= 2.34, harmless there).
/// These are named here for both build modes; the tree-shaken link path simply
/// leaves the unreferenced ones unused. Windows/MSVC links its own C++ runtime
/// implicitly, so only the system library is named there.
///
/// Throws for an unhandled target OS rather than silently linking nothing —
/// otherwise a new target would fail deep in the linker with an
/// `operator delete` / `__cxa_*` undefined-symbol error instead of here.
List<String> boringSslLinkLibraries(OS targetOS) => switch (targetOS) {
  OS.macOS || OS.iOS => const ['c++'],
  OS.linux => const ['stdc++', 'pthread'],
  OS.android => const ['c++_shared'],
  OS.windows => const ['ws2_32'],
  _ => throw UnsupportedError(
    'boringssl_dart has no C++/system runtime mapping for target OS '
    '"$targetOS".',
  ),
};
