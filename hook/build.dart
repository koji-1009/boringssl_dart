/// Build hook for boringssl_dart: compiles BoringSSL's `libcrypto` from a
/// pinned commit directly with the C/C++ toolchain — no CMake, no generator
/// step. The source list is read from BoringSSL's checked-in `gen/sources.json`
/// and handed to a single [CBuilder.library] call.
///
/// Two output modes. With linking enabled (AOT `dart build`), the compile
/// emits a static archive routed to `hook/link.dart`, which tree-shakes it to
/// the symbols the `@ffi.Native` bindings use before producing the final
/// dynamic library. Without link hooks (JIT: `dart test` / `dart run`), the
/// full `libcrypto` is emitted as a dynamic library and bundled directly.
///
/// The pinned commit lives in `native/boringssl_commit.txt` — a data file, so
/// a BoringSSL bump is a one-line change that never touches hook code. The file
/// is registered as a hook dependency, so the hook re-runs exactly when the pin
/// changes; `lib/src/version.g.dart` mirrors it. The source arrives as GitHub's
/// commit-addressed archive tarball — one plain HTTPS GET served from the
/// download path (codeload), needing no git binary — into the hook's shared
/// output directory on the first build and is reused afterwards, keyed by a
/// marker file carrying the pinned commit, so subsequent builds are offline.
library;

import 'dart:convert';
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:logging/logging.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';

import 'toolchain.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;

    final logger = Logger('boringssl_dart.build')
      ..onRecord.listen((record) => stderr.writeln(record.message));

    final targetOS = input.config.code.targetOS;
    final linkingEnabled = input.config.linkingEnabled;
    logger.info(
      'boringssl_dart build ($targetOS/${input.config.code.targetArchitecture}'
      ', mode: ${linkingEnabled ? "link hook" : "standalone"})',
    );

    final commit = _readPinnedCommit(input.packageRoot);
    // Registered as a hook dependency: the hooks runner re-runs this hook
    // (and thus the fetch) exactly when the pin file changes.
    output.dependencies.add(
      input.packageRoot.resolve('native/boringssl_commit.txt'),
    );

    // The shared output directory persists across per-config builds and is
    // owned solely by this hook; the hook runner serializes concurrent
    // invocations, so the checkout is written once and reused.
    final checkout = Directory.fromUri(
      input.outputDirectoryShared.resolve('boringssl-checkout/'),
    );
    await _ensureCheckout(checkout, commit, logger);

    // gen/sources.json is checked in at the pinned commit. Compiling `bcm`
    // (the FIPS module translation unit) + `crypto` (everything else),
    // together with their per-(arch, os) `.S` assembly, reproduces the non-FIPS
    // `crypto` library CMake builds from the same lists.
    final sources =
        jsonDecode(
              await File.fromUri(
                checkout.uri.resolve('gen/sources.json'),
              ).readAsString(),
            )
            as Map<String, Object?>;

    List<String> filesOf(String target, String key) {
      final targetMap = sources[target];
      if (targetMap is! Map<String, Object?>) {
        throw StateError(
          'gen/sources.json is missing the "$target" target (or it is not a '
          'JSON object); the pinned BoringSSL commit may have restructured it.',
        );
      }
      final files = targetMap[key];
      if (files is! List<Object?>) {
        throw StateError(
          'gen/sources.json target "$target" is missing the "$key" list; the '
          'pinned BoringSSL commit may have restructured it.',
        );
      }
      return [
        for (final path in files)
          checkout.uri.resolve(path! as String).toFilePath(),
      ];
    }

    // Windows: the .S set is GAS syntax, which native_toolchain_c's MSVC
    // toolchain cannot assemble (BoringSSL's Windows asm is nasm, which the C
    // toolchain does not drive either). Build the pure-C `OPENSSL_NO_ASM`
    // variant there instead. Every other target hands clang the full
    // per-(arch, os) .S set — each file self-guards on `OPENSSL_X86_64` /
    // `__APPLE__` / `__ELF__` etc., so only the matching files assemble and the
    // rest expand to empty objects.
    final useAsm = targetOS != OS.windows;
    final compileSources = <String>[
      ...filesOf('bcm', 'srcs'),
      ...filesOf('crypto', 'srcs'),
      if (useAsm) ...filesOf('bcm', 'asm'),
      if (useAsm) ...filesOf('crypto', 'asm'),
    ];
    _verifySources(compileSources);
    _rejectCSources(compileSources);

    final builder = CBuilder.library(
      name: 'boringssl_dart',
      assetName: 'boringssl_dart',
      sources: compileSources,
      includes: [checkout.uri.resolve('include/').toFilePath()],
      // Deliberately NOT `language: Language.cpp`: that injects a global
      // `-x c++` and forces the `.S` inputs to be parsed as C++. Leaving the
      // default (C) lets clang pick the language per file extension — `.cc`
      // compiled as C++, `.S` assembled — which is how this mixed list builds.
      std: 'c++17', // CMakeLists.txt: CMAKE_CXX_STANDARD 17 (C++17 required).
      // Match the deleted CMakeLists' size measures: -DOPENSSL_SMALL globally
      // plus -Os, which keep the shipped libcrypto small (the project's whole
      // point). native_toolchain_c defaults to -O3, so the size level is set
      // explicitly.
      optimizationLevel: OptimizationLevel.oS,
      defines: {
        // CMakeLists.txt sets -DBORINGSSL_IMPLEMENTATION on the libcrypto /
        // fipsmodule targets; internal headers gate exported symbols on it.
        'BORINGSSL_IMPLEMENTATION': null,
        // Smaller precomputed tables (AES/EC/...). CMakeLists.txt set this
        // globally; it is what keeps the from-source build compact.
        'OPENSSL_SMALL': null,
        // Linux exposes pthread_rwlock_t only under this feature flag; on Apple
        // it instead *disables* APIs BoringSSL uses, so upstream scopes it to
        // Linux (CMakeLists.txt). Android's bionic needs no such flag.
        if (targetOS == OS.linux) '_XOPEN_SOURCE': '700',
        // Pure-C fallback path on Windows (no asm).
        if (!useAsm) 'OPENSSL_NO_ASM': null,
        // Windows PE never auto-exports; without this the standalone DLL would
        // export no symbols and every @ffi.Native lookup would fail. Scoped to
        // the standalone path — in link-hook mode the CLinker treeshake drives
        // the export table via explicit /EXPORT, so dllexport-ing every symbol
        // here would defeat it (CMakeLists.txt set it on WIN32).
        if (targetOS == OS.windows && !linkingEnabled)
          'BORINGSSL_SHARED_LIBRARY': null,
        // The rest of CMakeLists.txt's WIN32 define block. Required to compile
        // under MSVC: NOMINMAX stops <windows.h> defining min()/max() macros
        // that break `std::numeric_limits<>::max()`; WIN32_LEAN_AND_MEAN stops
        // it pulling in the legacy <winsock.h>, which redefines sockaddr /
        // socket / accept against BoringSSL's <winsock2.h>. _HAS_EXCEPTIONS=0
        // matches the exception-free C++ runtime; _CRT_SECURE_NO_WARNINGS
        // silences the CRT deprecation warnings.
        if (targetOS == OS.windows) ...{
          'NOMINMAX': null,
          'WIN32_LEAN_AND_MEAN': null,
          '_HAS_EXCEPTIONS': '0',
          '_CRT_SECURE_NO_WARNINGS': null,
        },
      },
      // GNU-only compile flags (skipped on Windows/MSVC, where they are invalid
      // and there are no .S inputs). Upstream compiles libcrypto's C++ with
      // -fno-exceptions -fno-rtti to keep its C++ runtime footprint tiny; the
      // .S inputs ignore these with a harmless unused-arg warning.
      // -ffunction-sections/-fdata-sections give the link hook's --gc-sections
      // per-symbol granularity (macOS ld64 already strips per atom); without
      // them a kept symbol drags in its whole translation unit.
      flags: useAsm
          ? const [
              '-fno-exceptions',
              '-fno-rtti',
              '-ffunction-sections',
              '-fdata-sections',
            ]
          : const [],
      // The C++ runtime and the system libraries the full crypto library needs
      // (winsock on Windows, pthread on Linux). See [boringSslLinkLibraries].
      libraries: boringSslLinkLibraries(targetOS),
    );

    await builder.run(
      input: input,
      output: output,
      logger: logger,
      routing: linkingEnabled
          ? [ToLinkHook(input.packageName)]
          : const [ToAppBundle()],
      linkModePreference: linkingEnabled
          ? LinkModePreference.static
          : LinkModePreference.dynamic,
    );
  });
}

/// Fails the build if any source is a C (`.c`) file.
///
/// The single [CBuilder.library] call compiles the whole list under
/// `-std=c++17`, which clang rejects on a `.c` input ("invalid argument
/// '-std=c++17' not allowed with 'C'"). Every current bcm/crypto source is
/// `.cc`; this turns a future pin bump that introduces a `.c` source into a
/// named, actionable failure here rather than a cryptic compiler error.
void _rejectCSources(List<String> sources) {
  final cSources = sources.where((path) => path.endsWith('.c')).toList();
  if (cSources.isNotEmpty) {
    throw StateError(
      'gen/sources.json now lists ${cSources.length} C source(s), e.g. '
      '"${cSources.first}". This hook compiles the whole list as C++ '
      '(-std=c++17), which clang rejects for C. Compile C sources separately '
      'before removing this guard.',
    );
  }
}

/// Reads the pinned google/boringssl commit from `native/boringssl_commit.txt`.
///
/// The pin must be a full 40-hex-char hash: abbreviations or refs would make
/// the fetch ambiguous and the marker comparison meaningless.
String _readPinnedCommit(Uri packageRoot) {
  final pinFile = File.fromUri(
    packageRoot.resolve('native/boringssl_commit.txt'),
  );
  if (!pinFile.existsSync()) {
    throw StateError(
      'Missing ${pinFile.path}: it pins the google/boringssl commit this '
      'hook builds.',
    );
  }
  final commit = pinFile.readAsStringSync().trim();
  if (!RegExp(r'^[0-9a-f]{40}$').hasMatch(commit)) {
    throw StateError(
      '${pinFile.path} must contain a full 40-character lowercase hex git '
      'commit hash, got: "$commit"',
    );
  }
  return commit;
}

/// Fails the build if a source named by `gen/sources.json` is absent from the
/// checkout, which is how a pin bump that starts compiling something under
/// [_unusedTarballDirs] surfaces — as a named missing file here rather than a
/// compiler error deep in a several-hundred-file command line.
void _verifySources(List<String> sources) {
  final missing = sources.where((path) => !File(path).existsSync()).toList();
  if (missing.isNotEmpty) {
    throw StateError(
      'gen/sources.json names ${missing.length} file(s) missing from the '
      'checkout, e.g. "${missing.first}". If the pinned commit now compiles '
      'sources under a directory this hook skips at extraction, remove it '
      'from _unusedTarballDirs.',
    );
  }
}

/// Tarball directories skipped at extraction: upstream test corpora and the
/// vendored test frameworks, none of which `gen/sources.json` compiles.
const _unusedTarballDirs = [
  'third_party/wycheproof_testvectors',
  'third_party/googletest',
  'third_party/benchmark',
];

/// Ensures [checkout] holds the pinned BoringSSL [commit].
///
/// Idempotent: a marker file records the checked-out commit; when it already
/// matches, the (network) fetch is skipped, so builds after the first are
/// offline. Any partial/mismatched state is wiped and re-fetched. The
/// commit-addressed tarball is immutable in content, so the marker comparison
/// alone decides freshness.
Future<void> _ensureCheckout(
  Directory checkout,
  String commit,
  Logger logger,
) async {
  final marker = File.fromUri(checkout.uri.resolve('.commit'));
  if (marker.existsSync() && (await marker.readAsString()).trim() == commit) {
    logger.info('BoringSSL $commit already present; skipping fetch.');
    return;
  }

  final url = Uri.parse(
    'https://github.com/google/boringssl/archive/$commit.tar.gz',
  );
  logger.info('Fetching $url into ${checkout.path}');
  if (checkout.existsSync()) {
    checkout.deleteSync(recursive: true);
  }
  checkout.createSync(recursive: true);

  final tarball = File.fromUri(
    checkout.parent.uri.resolve('boringssl-$commit.tar.gz'),
  );
  final client = HttpClient();
  try {
    final request = await client.getUrl(url);
    final response = await request.close();
    if (response.statusCode != HttpStatus.ok) {
      throw HttpException(
        'BoringSSL tarball fetch failed: HTTP ${response.statusCode}',
        uri: url,
      );
    }
    await response.pipe(tarball.openWrite());
  } finally {
    client.close(force: true);
  }

  final tarArgs = [
    'xzf',
    tarball.path,
    '--strip-components=1',
    '-C',
    checkout.path,
    for (final excluded in _unusedTarballDirs) '--exclude=*/$excluded',
  ];
  final result = await Process.run('tar', tarArgs);
  if (result.exitCode != 0) {
    throw ProcessException(
      'tar',
      tarArgs,
      'BoringSSL tarball extraction failed:\n${result.stdout}\n${result.stderr}',
      result.exitCode,
    );
  }
  tarball.deleteSync();

  marker.writeAsStringSync('$commit\n');
  logger.info('BoringSSL $commit checked out.');
}
