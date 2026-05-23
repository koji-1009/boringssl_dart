import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:logging/logging.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';

import 'symbols.dart';

void main(List<String> args) async {
  await link(args, (input, output) async {
    final logger = Logger('')
      ..level = Level.WARNING
      ..onRecord.listen((record) => stderr.writeln(record.message));

    final codeAssets = input.assets.code;
    final sources = [for (final asset in codeAssets) asset.file!.toFilePath()];

    // BoringSSL has C++ TUs that reference the libstdc++ exception
    // personality (`__gxx_personality_v0`). `CLinker` invokes clang as
    // a C driver, so libstdc++ is not pulled in automatically on Linux
    // and Android. Apple/iOS and Windows toolchains link their C++
    // runtime implicitly, so no extra flag is needed there.
    final targetOS = input.config.code.targetOS;
    final needsCxxRuntime = targetOS == OS.linux || targetOS == OS.android;

    final linker = CLinker.library(
      name: 'boringssl_dart',
      assetName: 'boringssl_dart',
      sources: sources,
      linkerOptions: LinkerOptions.treeshake(
        symbolsToKeep: symbols,
        flags: needsCxxRuntime ? const ['-lstdc++'] : null,
      ),
    );

    await linker.run(input: input, output: output, logger: logger);
  });
}
