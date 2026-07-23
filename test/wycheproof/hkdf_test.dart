// HKDF Wycheproof suites (SHA-256 and SHA-512).
//
// Each case supplies input keying material (ikm), optional salt/info, a
// requested output length (size, in bytes) and the expected okm. A `valid`
// case must derive exactly `okm`; an `invalid` case requests a size beyond
// HKDF's ceiling of 255 * hashLen bytes (SHA-256: 8160, SHA-512: 16320), which
// `Hkdf.derive` rejects by throwing ArgumentError ("output length too large").
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

import 'runner.dart';

void main() {
  _runHkdfSuite('hkdf_sha256_test.json', 'SHA-256');
  _runHkdfSuite('hkdf_sha512_test.json', 'SHA-512');
}

void _runHkdfSuite(String fileName, String hashAlgorithm) {
  final suite = WycheproofSuite.load(fileName);

  var exercised = 0;
  const skipped = 0;

  group('HKDF Wycheproof (${suite.algorithm})', () {
    for (final g in suite.groups) {
      for (final c in g.tests) {
        final ikm = c.bytes('ikm');
        final salt = c.bytes('salt');
        final info = c.bytes('info');
        final size = c.field<int>('size')!;
        final okm = c.bytes('okm');

        exercised++;
        test(caseName(c), () {
          Uint8List derive() => Hkdf.derive(
            key: ikm,
            salt: salt,
            info: info,
            length: size,
            hashAlgorithm: hashAlgorithm,
          );

          switch (c.result) {
            case 'valid':
              expect(derive(), equals(okm));
            case 'invalid':
              // The only invalid cases request an output larger than the
              // 255 * hashLen ceiling; derivation must fail.
              expect(derive, throwsA(anything));
            case 'acceptable':
              // Legal but discouraged: rejection is fine, but if the API
              // accepts the input the derived key must be correct. Only the
              // derive call may sit in the catch; the result assertion runs
              // outside it so a wrong result is never swallowed.
              Uint8List? derived;
              try {
                derived = derive();
              } catch (_) {
                // Rejection is also an acceptable outcome.
              }
              if (derived != null) {
                expect(derived, equals(okm));
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
        '${suite.algorithm}: $exercised cases exercised, $skipped skipped '
        '(of ${suite.numberOfTests} total vectors).',
      );
      expect(exercised, greaterThan(0));
    });
  });
}
