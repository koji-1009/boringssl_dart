// AES-CBC (PKCS#7) Wycheproof suite.
//
// `AesCbc` uses BoringSSL's EVP_CIPHER AES-CBC with PKCS#7 padding and a
// 16-byte IV — exactly the shape of the `aes_cbc_pkcs5` vectors (PKCS#5 and
// PKCS#7 padding are identical for the 16-byte AES block). Valid vectors are
// checked in both directions; invalid ones (bad padding, truncated ciphertext)
// must make decrypt throw.
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

import 'runner.dart';

void main() {
  final suite = WycheproofSuite.load('aes_cbc_pkcs5_test.json');

  var exercised = 0;
  var skipped = 0;

  group('AES-CBC Wycheproof (${suite.algorithm})', () {
    for (final g in suite.groups) {
      // Every group in these vectors uses a 128-bit (16-byte) IV, which the API
      // requires; guard anyway so a future vector with a different IV size is
      // surfaced as a skip rather than a spurious failure.
      if (g.ivSize != 128) {
        skipped += g.tests.length;
        continue;
      }

      for (final c in g.tests) {
        final key = c.bytes('key');
        final iv = c.bytes('iv');
        final msg = c.bytes('msg');
        final ct = c.bytes('ct');

        exercised++;
        test(caseName(c), () {
          switch (c.result) {
            case 'valid':
              expect(AesCbc.decrypt(key, iv, ct), equals(msg));
              expect(AesCbc.encrypt(key, iv, msg), equals(ct));
            case 'invalid':
              // Invalid padding or a non-block-aligned ciphertext: decrypt must
              // fail. ArgumentError and Exception are both acceptable.
              expect(() => AesCbc.decrypt(key, iv, ct), throwsA(anything));
            case 'acceptable':
              // Rejection is acceptable, but a decrypt that succeeds must
              // recover the exact plaintext — only the decrypt call itself may
              // fail, never the plaintext comparison.
              Uint8List? recovered;
              try {
                recovered = AesCbc.decrypt(key, iv, ct);
              } catch (_) {
                // Rejection is also acceptable.
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

    test('coverage summary', () {
      // ignore: avoid_print
      print(
        'AES-CBC: $exercised cases exercised, $skipped skipped '
        '(of ${suite.numberOfTests} total vectors).',
      );
      expect(exercised, greaterThan(0));
    });
  });
}
