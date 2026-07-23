/// Link hook for boringssl_dart: receives the static `libcrypto` archive the
/// build hook routes here when linking is enabled (AOT `dart build`), and
/// tree-shakes it down to the C symbols the `@ffi.Native` bindings reference.
///
/// The keep-list (`hook/symbols.dart`) is auto-generated from
/// `lib/src/bindings.g.dart` by `ffigen.dart`, so it stays in sync with the
/// actual bindings without manual maintenance.
library;

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:logging/logging.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';

import 'symbols.dart';
import 'toolchain.dart';

void main(List<String> args) async {
  await link(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;
    final assets = input.assets.code;
    if (assets.isEmpty) return;

    final logger = Logger('boringssl_dart.link')
      ..onRecord.listen((record) => stderr.writeln(record.message));

    final targetOS = input.config.code.targetOS;

    final linker = CLinker.library(
      name: 'boringssl_dart',
      assetName: 'boringssl_dart',
      sources: [for (final asset in assets) asset.file!.toFilePath()],
      linkerOptions: LinkerOptions.treeshake(symbolsToKeep: symbols),
      // The emitted asset must be a bundled dynamic library regardless of the
      // invoker's link-mode preference: `@ffi.Native` resolves it by asset id
      // at runtime.
      linkModePreference: LinkModePreference.dynamic,
      // CLinker drives clang as a C driver, which does not auto-link the C++
      // runtime BoringSSL's destructors reference. See [boringSslLinkLibraries].
      libraries: boringSslLinkLibraries(targetOS),
    );

    await linker.run(input: input, output: output, logger: logger);
  });
}
