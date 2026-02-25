import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    final targetOS = input.config.code.targetOS;
    final targetArch = input.config.code.targetArchitecture;
    stderr.writeln(
      'boringssl_dart build ($targetOS/$targetArch)',
    );

    final packageName = input.packageName;
    final sourceDir = input.packageRoot.resolve('native/');
    final buildDir = input.outputDirectory.resolve('build/');

    await _syncBoringSsl(input.packageRoot);
    await Directory.fromUri(buildDir).create(recursive: true);

    // Configure CMake
    const buildType = 'Release';
    final cmakeArgs = <String>[
      '-S',
      sourceDir.toFilePath(),
      '-B',
      buildDir.toFilePath(),
      '-DCMAKE_BUILD_TYPE=$buildType',
    ];

    switch (targetOS) {
      case .android:
        final ndkPath = _findAndroidNdk();
        if (ndkPath == null) {
          throw Exception(
            'Android NDK not found. Set ANDROID_NDK_HOME or install NDK via Android SDK Manager.',
          );
        }
        final abi = switch (targetArch) {
          .arm64 => 'arm64-v8a',
          .arm => 'armeabi-v7a',
          .x64 => 'x86_64',
          .ia32 => 'x86',
          _ => throw Exception('Unsupported Android architecture: $targetArch'),
        };
        cmakeArgs.addAll([
          '-DCMAKE_TOOLCHAIN_FILE=$ndkPath/build/cmake/android.toolchain.cmake',
          '-DANDROID_ABI=$abi',
          '-DANDROID_PLATFORM=android-21',
          '-DANDROID_STL=c++_static',
          // https://developer.android.com/guide/practices/page-sizes
          '-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON',
        ]);
      case .iOS:
        final iosArch = targetArch == .arm64 ? 'arm64' : 'x86_64';
        final iOSConfig = input.config.code.iOS;
        final isSimulator = iOSConfig.targetSdk == IOSSdk.iPhoneSimulator;
        final sdkName = isSimulator ? 'iphonesimulator' : 'iphoneos';
        final sdkPath = await Process.run('xcrun', [
          '--sdk',
          sdkName,
          '--show-sdk-path',
        ]);
        final sysroot = sdkPath.exitCode == 0
            ? sdkPath.stdout.toString().trim()
            : null;
        cmakeArgs.addAll([
          '-DCMAKE_SYSTEM_NAME=iOS',
          '-DCMAKE_OSX_ARCHITECTURES=$iosArch',
          if (sysroot != null && sysroot.isNotEmpty)
            '-DCMAKE_OSX_SYSROOT=$sysroot',
          '-DCMAKE_OSX_DEPLOYMENT_TARGET=${iOSConfig.targetVersion}',
        ]);
      case .macOS:
        cmakeArgs.addAll([
          '-DCMAKE_OSX_ARCHITECTURES=${targetArch == .arm64 ? "arm64" : "x86_64"}',
          '-DCMAKE_MACOSX_BUNDLE=OFF',
        ]);
      case .linux:
      case .windows:
    }

    await _runCommand('cmake', cmakeArgs);
    await _runCommand('cmake', [
      '--build',
      buildDir.toFilePath(),
      '--config',
      buildType,
    ]);

    // Locate shared library
    final libName = targetOS.dylibFileName('boringssl_dart');
    Uri libFile = buildDir.resolve(libName);
    // Multi-config generators (e.g. MSVC) place output under Release/
    if (!File.fromUri(libFile).existsSync()) {
      final libFileSub = buildDir.resolve('$buildType/$libName');
      if (File.fromUri(libFileSub).existsSync()) {
        libFile = libFileSub;
      } else {
        throw Exception(
          'Library $libName not found in build directory $buildDir',
        );
      }
    }

    output.dependencies.add(
      input.packageRoot.resolve('native/boringssl_commit.txt'),
    );
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

/// Checkout BoringSSL to the commit specified in native/boringssl_commit.txt.
Future<void> _syncBoringSsl(Uri packageRoot) async {
  final boringsslDir = packageRoot.resolve('third_party/boringssl/');
  final commitFile = packageRoot.resolve('native/boringssl_commit.txt');

  if (!File.fromUri(commitFile).existsSync()) {
    throw Exception('Missing native/boringssl_commit.txt');
  }

  final targetCommit = File.fromUri(commitFile).readAsStringSync().trim();
  final boringsslPath = boringsslDir.toFilePath();

  if (!Directory.fromUri(boringsslDir).existsSync()) {
    await Directory.fromUri(boringsslDir).create(recursive: true);
    await _runCommand('git', ['init'], workingDirectory: boringsslPath);
    await _runCommand('git', [
      'remote',
      'add',
      'origin',
      'https://github.com/google/boringssl.git',
    ], workingDirectory: boringsslPath);
  }

  final headResult = await Process.run(
    'git',
    ['rev-parse', 'HEAD'],
    workingDirectory: boringsslPath,
  );
  final currentHead =
      headResult.exitCode == 0 ? headResult.stdout.toString().trim() : null;
  if (currentHead == targetCommit) return;

  await _runCommand('git', [
    'fetch',
    '--depth',
    '1',
    '--no-tags',
    'origin',
    targetCommit,
  ], workingDirectory: boringsslPath);
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
    final cmd = '$executable ${args.join(" ")}';
    final out = result.stdout.toString();
    final err = result.stderr.toString();
    if (out.isNotEmpty) stderr.write(out);
    if (err.isNotEmpty) stderr.write(err);
    throw Exception('$cmd failed with exit code ${result.exitCode}');
  }
}

/// Auto-detect Android NDK from environment or common locations.
String? _findAndroidNdk() {
  final envNdk =
      Platform.environment['ANDROID_NDK_HOME'] ??
      Platform.environment['ANDROID_NDK'];
  if (envNdk != null && envNdk.isNotEmpty && Directory(envNdk).existsSync()) {
    return envNdk;
  }

  final androidHome =
      Platform.environment['ANDROID_HOME'] ??
      Platform.environment['ANDROID_SDK_ROOT'];
  if (androidHome != null && androidHome.isNotEmpty) {
    final ndkDir = Directory('$androidHome/ndk');
    if (ndkDir.existsSync()) {
      final versions = ndkDir.listSync().whereType<Directory>().toList();
      if (versions.isNotEmpty) {
        versions.sort((a, b) => b.path.compareTo(a.path));
        return versions.first.path;
      }
    }
    final ndkBundle = Directory('$androidHome/ndk-bundle');
    if (ndkBundle.existsSync()) return ndkBundle.path;
  }

  final home = Platform.environment['HOME'] ?? '';
  for (final path in [
    '$home/Library/Android/sdk/ndk',
    '$home/Android/Sdk/ndk',
    '/usr/local/share/android-sdk/ndk',
  ]) {
    final ndkDir = Directory(path);
    if (ndkDir.existsSync()) {
      final versions = ndkDir.listSync().whereType<Directory>().toList();
      if (versions.isNotEmpty) {
        versions.sort((a, b) => b.path.compareTo(a.path));
        return versions.first.path;
      }
    }
  }

  return null;
}
