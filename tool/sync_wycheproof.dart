// Syncs Wycheproof test vectors into `test/wycheproof/vectors/`, pinned by a
// full commit hash — the same commit-addressed, reproducible-fetch philosophy
// this package applies to the BoringSSL source itself (see
// `native/boringssl_commit.txt`).
//
// Run from the package root:
//
//   dart run tool/sync_wycheproof.dart
//
// Downloads a fixed list of vector files from the pinned commit, verifies each
// is valid JSON before writing, and records provenance in
// `test/wycheproof/vectors/SOURCE.txt`. The vectors are committed to git so an
// offline `dart test` after clone keeps working; they are excluded from the
// published pub package via `.pubignore`.
import 'dart:convert';
import 'dart:io';

/// Full commit hash of C2SP/wycheproof the vendored vectors are taken from.
/// Bump this (and re-run the script) to update the vectors.
const String wycheproofCommit = 'b61843a9a5115bb758134b6a1f5d5e502d445342';

const String wycheproofRepo = 'https://github.com/C2SP/wycheproof';

/// Vector files to vendor. Names are the `testvectors_v1` basenames at the
/// pinned commit. The list is intentionally broader than the currently wired
/// suites (AES-GCM, AES-CBC): the RSA/ECDSA/ECDH/KDF/MAC files are vendored now
/// so later phases add a suite without re-syncing.
const List<String> vectorFiles = [
  // AES (wired now).
  'aes_gcm_test.json',
  'aes_cbc_pkcs5_test.json',
  // RSA-OAEP.
  'rsa_oaep_2048_sha1_mgf1sha1_test.json',
  'rsa_oaep_2048_sha256_mgf1sha256_test.json',
  'rsa_oaep_2048_sha512_mgf1sha512_test.json',
  // RSA-PSS.
  'rsa_pss_2048_sha256_mgf1_32_test.json',
  'rsa_pss_4096_sha512_mgf1_32_test.json',
  // RSA PKCS#1 v1.5 signatures.
  'rsa_signature_2048_sha256_test.json',
  'rsa_signature_2048_sha512_test.json',
  // ECDSA — P1363 (raw r||s) to match this package's public signature format.
  'ecdsa_secp256r1_sha256_p1363_test.json',
  'ecdsa_secp384r1_sha384_p1363_test.json',
  'ecdsa_secp521r1_sha512_p1363_test.json',
  // ECDH.
  'ecdh_secp256r1_test.json',
  'ecdh_secp384r1_test.json',
  'ecdh_secp521r1_test.json',
  // HKDF.
  'hkdf_sha256_test.json',
  'hkdf_sha512_test.json',
  // HMAC.
  'hmac_sha1_test.json',
  'hmac_sha256_test.json',
  'hmac_sha384_test.json',
  'hmac_sha512_test.json',
  // PBKDF2.
  'pbkdf2_hmacsha256_test.json',
];

/// Primary directory in the Wycheproof repo, and the legacy fallback used only
/// when a file is missing from `testvectors_v1` at the pin.
const String primaryDir = 'testvectors_v1';
const String fallbackDir = 'testvectors';

Uri rawUri(String dir, String file) => Uri.parse(
  'https://raw.githubusercontent.com/C2SP/wycheproof/$wycheproofCommit/$dir/$file',
);

Future<void> main() async {
  final outDir = Directory('test/wycheproof/vectors');
  outDir.createSync(recursive: true);

  final client = HttpClient();
  final usedFallback = <String>[];
  var totalBytes = 0;
  try {
    for (final file in vectorFiles) {
      final result = await _download(client, file);
      if (result.dir == fallbackDir) usedFallback.add(file);
      // Fail loudly on non-JSON so a moved/renamed file is caught at sync time
      // rather than surfacing as a confusing parse error in the test runner.
      jsonDecode(result.body);
      final outFile = File('${outDir.path}/$file');
      outFile.writeAsStringSync(result.body);
      totalBytes += result.body.length;
      stdout.writeln(
        '  ${result.dir}/$file  (${result.body.length} bytes)',
      );
    }
  } finally {
    client.close();
  }

  _writeSource(outDir, usedFallback);

  stdout.writeln(
    'Synced ${vectorFiles.length} files, '
    '${(totalBytes / 1024 / 1024).toStringAsFixed(2)} MB total.',
  );
  if (usedFallback.isNotEmpty) {
    stdout.writeln('Fell back to $fallbackDir/ for: ${usedFallback.join(', ')}');
  }
}

class _Download {
  const _Download(this.dir, this.body);
  final String dir;
  final String body;
}

Future<_Download> _download(HttpClient client, String file) async {
  for (final dir in [primaryDir, fallbackDir]) {
    final uri = rawUri(dir, file);
    final request = await client.getUrl(uri);
    final response = await request.close();
    if (response.statusCode == 200) {
      final body = await response.transform(utf8.decoder).join();
      return _Download(dir, body);
    }
    // Drain the body so the connection can be reused.
    await response.drain<void>();
    if (response.statusCode != 404) {
      throw HttpException('HTTP ${response.statusCode} for $uri');
    }
  }
  throw HttpException(
    'Not found in $primaryDir/ or $fallbackDir/ at $wycheproofCommit: $file',
  );
}

void _writeSource(Directory outDir, List<String> usedFallback) {
  final buffer = StringBuffer()
    ..writeln('Wycheproof test vectors')
    ..writeln('=======================')
    ..writeln()
    ..writeln('Source: $wycheproofRepo')
    ..writeln('Commit: $wycheproofCommit')
    ..writeln('Directory: $primaryDir/ (legacy $fallbackDir/ per-file fallback)')
    ..writeln()
    ..writeln('Regenerate with:')
    ..writeln('  dart run tool/sync_wycheproof.dart')
    ..writeln()
    ..writeln('These vectors are committed so an offline `dart test` works after')
    ..writeln('clone, but are excluded from the published pub package (.pubignore).')
    ..writeln()
    ..writeln('Files:');
  for (final file in vectorFiles) {
    buffer.writeln('  $file');
  }
  if (usedFallback.isNotEmpty) {
    buffer
      ..writeln()
      ..writeln('Fetched from legacy $fallbackDir/ (absent from $primaryDir/):');
    for (final file in usedFallback) {
      buffer.writeln('  $file');
    }
  }
  File('${outDir.path}/SOURCE.txt').writeAsStringSync(buffer.toString());
}
