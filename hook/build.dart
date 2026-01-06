import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    final packageName = input.packageName;
    final sourceDir = input.packageRoot.resolve('native/');
    final buildDir = input.outputDirectory.resolve('build/');

    await Directory.fromUri(buildDir).create(recursive: true);

    // Default to Release build
    const buildMode = "Release";

    final cmakeArgs = <String>[
      '-S',
      sourceDir.toFilePath(),
      '-B',
      buildDir.toFilePath(),
      '-DCMAKE_BUILD_TYPE=$buildMode',
    ];

    final targetOS = input.config.code.targetOS;
    final targetArch = input.config.code.targetArchitecture;

    if (targetOS == OS.macOS) {
      cmakeArgs.add(
        '-DCMAKE_OSX_ARCHITECTURES=${targetArch == Architecture.arm64 ? "arm64" : "x86_64"}',
      );
      cmakeArgs.add('-DCMAKE_MACOSX_BUNDLE=OFF');
    }

    final cmakeConfigResult = await Process.run('cmake', cmakeArgs);
    if (cmakeConfigResult.exitCode != 0) {
      stderr.write(cmakeConfigResult.stderr);
      throw Exception('CMake configure failed');
    }

    final cmakeBuildResult = await Process.run('cmake', [
      '--build',
      buildDir.toFilePath(),
      '--config',
      buildMode,
    ]);
    if (cmakeBuildResult.exitCode != 0) {
      stderr.write(cmakeBuildResult.stderr);
      throw Exception('CMake build failed');
    }

    final libName = targetOS.dylibFileName('boringssl_dart');

    Uri libFile = buildDir.resolve(libName);
    if (!File.fromUri(libFile).existsSync()) {
      // Handle multi-config generators
      final libFileSub = buildDir.resolve('$buildMode/$libName');
      if (File.fromUri(libFileSub).existsSync()) {
        libFile = libFileSub;
      } else {
        throw Exception('Library $libName not found in build directory');
      }
    }

    output.assets.code.add(
      CodeAsset(
        package: packageName,
        name: 'boringssl_dart',
        file: libFile,
        linkMode: DynamicLoadingBundled(),
      ),
    );
  });
}
