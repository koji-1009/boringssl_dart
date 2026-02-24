import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    final targetOS = input.config.code.targetOS;
    final targetArch = input.config.code.targetArchitecture;
    stderr.writeln('');
    stderr.writeln('Run boringssl_dart build ($targetOS/$targetArch)...');

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

    switch (targetOS) {
      case .android:
        // Android requires NDK toolchain for cross-compilation
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
          // 16KB page size support for Android 15+ (API 35+)
          // See: https://developer.android.com/guide/practices/page-sizes
          '-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON',
        ]);
      case .iOS:
        // iOS cross-compilation support
        final iosArch = targetArch == .arm64 ? 'arm64' : 'x86_64';

        // Get target SDK from Flutter's config (simulator or device)
        final iOSConfig = input.config.code.iOS;
        final isSimulator = iOSConfig.targetSdk == IOSSdk.iPhoneSimulator;
        final sdkName = isSimulator ? 'iphonesimulator' : 'iphoneos';

        // Get sysroot path for the target SDK
        final result = await Process.run('xcrun', [
          '--sdk',
          sdkName,
          '--show-sdk-path',
        ]);
        final sysroot = result.exitCode == 0
            ? result.stdout.toString().trim()
            : null;

        stderr.writeln('iOS SDK: $sdkName ($iosArch), sysroot: $sysroot');

        cmakeArgs.addAll([
          '-DCMAKE_SYSTEM_NAME=iOS',
          '-DCMAKE_OSX_ARCHITECTURES=$iosArch',
          if (sysroot != null && sysroot.isNotEmpty)
            '-DCMAKE_OSX_SYSROOT=$sysroot',
          // Minimum iOS deployment target
          '-DCMAKE_OSX_DEPLOYMENT_TARGET=${iOSConfig.targetVersion}',
        ]);
      case .macOS:
        cmakeArgs.add(
          '-DCMAKE_OSX_ARCHITECTURES=${targetArch == .arm64 ? "arm64" : "x86_64"}',
        );
        cmakeArgs.add('-DCMAKE_MACOSX_BUNDLE=OFF');
      case .linux:
        // Linux: ensure position-independent code for shared library
        cmakeArgs.add('-DCMAKE_POSITION_INDEPENDENT_CODE=ON');
      case .windows:
      // Windows: use appropriate generator if available
      // CMake defaults should work for most cases
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

    // Track commit file so SDK re-runs hook when commit hash changes
    output.dependencies.add(
      input.packageRoot.resolve('native/boringssl_commit.txt'),
    );

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

  // Check if already on the target commit
  final headResult = await Process.run(
    'git',
    ['rev-parse', 'HEAD'],
    workingDirectory: boringsslPath,
  );
  final currentHead =
      headResult.exitCode == 0 ? headResult.stdout.toString().trim() : null;

  if (currentHead == targetCommit) {
    stderr.writeln('BoringSSL already at $targetCommit. Skipping fetch.');
    return;
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
    stderr.writeln('=== Command failed: $executable ${args.join(" ")} ===');
    if (result.stdout.toString().isNotEmpty) {
      stderr.writeln('stdout:');
      stderr.write(result.stdout);
    }
    if (result.stderr.toString().isNotEmpty) {
      stderr.writeln('stderr:');
      stderr.write(result.stderr);
    }
    throw Exception(
      '$executable ${args.join(" ")} failed with exit code ${result.exitCode}',
    );
  }
}

/// Auto-detect Android NDK from environment or common locations.
String? _findAndroidNdk() {
  // 1. Check environment variables
  final envNdk =
      Platform.environment['ANDROID_NDK_HOME'] ??
      Platform.environment['ANDROID_NDK'];
  if (envNdk != null && envNdk.isNotEmpty && Directory(envNdk).existsSync()) {
    return envNdk;
  }

  // 2. Check ANDROID_HOME/ANDROID_SDK_ROOT for side-by-side NDK
  final androidHome =
      Platform.environment['ANDROID_HOME'] ??
      Platform.environment['ANDROID_SDK_ROOT'];
  if (androidHome != null && androidHome.isNotEmpty) {
    final ndkDir = Directory('$androidHome/ndk');
    if (ndkDir.existsSync()) {
      // Find latest NDK version
      final versions = ndkDir.listSync().whereType<Directory>().toList();
      if (versions.isNotEmpty) {
        versions.sort((a, b) => b.path.compareTo(a.path));
        return versions.first.path;
      }
    }
    // Legacy ndk-bundle location
    final ndkBundle = Directory('$androidHome/ndk-bundle');
    if (ndkBundle.existsSync()) {
      return ndkBundle.path;
    }
  }

  // 3. Check common user locations
  final home = Platform.environment['HOME'] ?? '';
  final commonPaths = [
    '$home/Library/Android/sdk/ndk',
    '$home/Android/Sdk/ndk',
    '/usr/local/share/android-sdk/ndk',
  ];
  for (final path in commonPaths) {
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
