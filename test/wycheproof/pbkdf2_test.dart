// PBKDF2-HMAC-SHA256 Wycheproof suite.
//
// Each case supplies a password, salt, iterationCount, requested key length
// (dkLen) and the expected derived key (dk). A `valid` case must derive exactly
// `dk`; an `invalid` case must throw.
//
// PBKDF2 cost is linear in iterationCount, so cases above a cap are skipped as a
// counted, explained skip to keep the suite's runtime sane. (This vendored file
// tops out at 80000 iterations, so in practice nothing is skipped, but the guard
// keeps the suite bounded if the vectors grow.)
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

import 'runner.dart';

/// Iteration ceiling above which a case is skipped rather than run.
const int _iterationCap = 100000;

void main() {
  final suite = WycheproofSuite.load('pbkdf2_hmacsha256_test.json');

  var exercised = 0;
  var skipped = 0;

  group('PBKDF2 Wycheproof (${suite.algorithm})', () {
    for (final g in suite.groups) {
      for (final c in g.tests) {
        final iterationCount = c.field<int>('iterationCount')!;
        if (iterationCount > _iterationCap) {
          skipped++;
          continue;
        }

        final password = c.bytes('password');
        final salt = c.bytes('salt');
        final dkLen = c.field<int>('dkLen')!;
        final dk = c.bytes('dk');

        exercised++;
        test(caseName(c), () {
          Uint8List derive() => Pbkdf2.derive(
            key: password,
            salt: salt,
            iterations: iterationCount,
            length: dkLen,
            hashAlgorithm: 'SHA-256',
          );

          switch (c.result) {
            case 'valid':
              expect(derive(), equals(dk));
            case 'invalid':
              expect(derive, throwsA(anything));
            case 'acceptable':
              // Legal but discouraged: rejection is fine, but if the API
              // accepts the input the derived key must match. Only the derive
              // call sits in the catch; the result assertion runs outside it.
              Uint8List? derived;
              try {
                derived = derive();
              } catch (_) {
                // Rejection is also an acceptable outcome.
              }
              if (derived != null) {
                expect(derived, equals(dk));
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
        'PBKDF2: $exercised cases exercised, $skipped skipped '
        '(iterationCount > $_iterationCap) '
        '(of ${suite.numberOfTests} total vectors).',
      );
      expect(exercised, greaterThan(0));
    });
  });
}
