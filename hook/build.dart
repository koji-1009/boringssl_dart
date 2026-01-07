import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    stderr.writeln('');
    stderr.writeln('Run boringssl_dart build...');

    final packageName = input.packageName;
    final sourceDir = input.packageRoot.resolve('native/');
    final buildDir = input.outputDirectory.resolve('build/');

    // 1. Sync BoringSSL Source
    await _syncBoringSsl(input.packageRoot);

    // 2. Prepare Build Directory
    await Directory.fromUri(buildDir).create(recursive: true);

    // 3. Configure CMake
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

    stderr.writeln('Run cmake...');
    await _runCommand('cmake', cmakeArgs);

    // 4. Build
    await _runCommand('cmake', [
      '--build',
      buildDir.toFilePath(),
      '--config',
      buildMode,
    ]);

    // 5. Locate & Package Asset
    final libName = targetOS.dylibFileName('boringssl_dart');
    Uri libFile = buildDir.resolve(libName);

    // Quick check for multi-config output (e.g., build/Release/libboringssl_dart.dylib)
    if (!File.fromUri(libFile).existsSync()) {
      final libFileSub = buildDir.resolve('$buildMode/$libName');
      if (File.fromUri(libFileSub).existsSync()) {
        libFile = libFileSub;
      } else {
        throw Exception(
          'Library $libName not found in build directory $buildDir',
        );
      }
    }

    stderr.writeln('Add asset...');
    output.assets.code.add(
      CodeAsset(
        package: packageName,
        name: 'boringssl_dart',
        file: libFile,
        linkMode: DynamicLoadingBundled(),
      ),
    );

    stderr.writeln('Done boringssl_dart build');
  });
}

// Ensure BoringSSL is checked out to the version specified in native/boringssl_commit.txt
Future<void> _syncBoringSsl(Uri packageRoot) async {
  final boringsslDir = packageRoot.resolve('third_party/boringssl/');
  final commitFile = packageRoot.resolve('native/boringssl_commit.txt');

  if (!File.fromUri(commitFile).existsSync()) {
    throw Exception('Missing config: native/boringssl_commit.txt');
  }

  final targetCommit = File.fromUri(commitFile).readAsStringSync().trim();
  final boringsslPath = boringsslDir.toFilePath();

  if (!Directory.fromUri(boringsslDir).existsSync()) {
    stderr.writeln('Initializing BoringSSL repository...');
    await Directory.fromUri(boringsslDir).create(recursive: true);
    await _runCommand('git', ['init'], workingDirectory: boringsslPath);
    await _runCommand('git', [
      'remote',
      'add',
      'origin',
      'https://github.com/google/boringssl.git',
    ], workingDirectory: boringsslPath);
  }

  stderr.writeln('Fetching BoringSSL commit $targetCommit...');
  await _runCommand('git', [
    'fetch',
    '--depth',
    '1',
    '--no-tags',
    'origin',
    targetCommit,
  ], workingDirectory: boringsslPath);

  stderr.writeln('Checking out BoringSSL: $targetCommit');
  await _runCommand('git', [
    'checkout',
    targetCommit,
  ], workingDirectory: boringsslPath);
}

Future<void> _runCommand(
  String executable,
  List<String> args, {
  String? workingDirectory,
}) async {
  final result = await Process.run(
    executable,
    args,
    workingDirectory: workingDirectory,
  );
  if (result.exitCode != 0) {
    stderr.write(result.stderr);
    throw Exception(
      '$executable ${args.join(" ")} failed with exit code ${result.exitCode}',
    );
  }
}
