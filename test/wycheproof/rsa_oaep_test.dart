// RSA-OAEP decrypt Wycheproof suite.
//
// The API (`RsaOaep.decrypt`) drives BoringSSL's EVP_PKEY OAEP with a single
// hash that serves as both the OAEP digest and the MGF1 digest (BoringSSL
// defaults the MGF1 digest to the OAEP digest when it is not set separately).
// Every vendored group here uses `sha == mgfSha`, so that single-hash contract
// matches the vectors; a group requesting a distinct MGF1 hash would be
// unrepresentable and is skipped with a counted, explained skip.
//
// The OAEP label is supported: `RsaOaep.decrypt` sets it via
// EVP_PKEY_CTX_set0_rsa_oaep_label, treating an empty label as "no label"
// (the OAEP default), which is exactly the empty-label case the vectors encode.
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

import 'runner.dart';

void main() {
  final files = [
    'rsa_oaep_2048_sha1_mgf1sha1_test.json',
    'rsa_oaep_2048_sha256_mgf1sha256_test.json',
    'rsa_oaep_2048_sha512_mgf1sha512_test.json',
  ];

  var exercised = 0;
  var skipped = 0;

  for (final fileName in files) {
    final suite = WycheproofSuite.load(fileName);

    group('RSA-OAEP Wycheproof ($fileName)', () {
      for (final g in suite.groups) {
        final sha = g.field<String>('sha')!;
        final mgfSha = g.field<String>('mgfSha')!;

        // The API derives the MGF1 digest from the OAEP digest, so it cannot
        // express a group whose two hashes differ. None of the vendored
        // groups do, but guard rather than silently mis-run.
        if (sha != mgfSha) {
          skipped += g.tests.length;
          continue;
        }

        final privateKey = RsaKey.importPkcs8(g.bytes('privateKeyPkcs8'));

        for (final c in g.tests) {
          final ct = c.bytes('ct');
          final label = c.bytes('label');
          final msg = c.bytes('msg');

          exercised++;
          test(caseName(c), () {
            Uint8List decrypt() =>
                RsaOaep.decrypt(privateKey, ct, hash: sha, label: label);

            switch (c.result) {
              case 'valid':
                expect(decrypt(), equals(msg));
              case 'invalid':
                // Corrupted padding, wrong label, or a malformed ciphertext:
                // decryption must fail loudly.
                expect(decrypt, throwsA(anything));
              case 'acceptable':
                // Legal but discouraged: rejection is fine, but a recovered
                // plaintext must be correct. Only the decrypt call may sit in
                // the try/catch so a wrong result can never be swallowed.
                Uint8List? recovered;
                try {
                  recovered = decrypt();
                } catch (_) {
                  // Rejection is also an acceptable outcome.
                }
                if (recovered != null) {
                  expect(recovered, equals(msg));
                }
              default:
                fail('Unknown result: ${c.result}');
            }
            expectCleanErrorQueue();
          });
        }
      }
    });
  }

  test('RSA-OAEP coverage summary', () {
    // ignore: avoid_print
    print(
      'RSA-OAEP: $exercised cases exercised, $skipped skipped '
      '(group MGF1 hash differs from OAEP hash).',
    );
    expect(exercised, greaterThan(0));
  });
}
