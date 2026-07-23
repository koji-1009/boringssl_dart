// RSA-PSS verify Wycheproof suite.
//
// The API (`RsaPss.verify`) drives BoringSSL's EVP_DigestVerify with a single
// hash used for both the PSS digest and the MGF1 digest, plus an explicit salt
// length. Every vendored group uses `sha == mgfSha`, matching that single-hash
// contract; a group requesting a distinct MGF1 hash would be unrepresentable
// and is skipped with a counted, explained skip.
//
// Per doc/design-notes.md ("Error handling posture") verify fails CLOSED: an
// invalid signature returns false and drains the error queue, it does not
// throw. This suite asserts that directly — an invalid vector that threw would
// contradict the design and surface here as a failure.
import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

import 'runner.dart';

void main() {
  final files = [
    'rsa_pss_2048_sha256_mgf1_32_test.json',
    'rsa_pss_4096_sha512_mgf1_32_test.json',
  ];

  var exercised = 0;
  var skipped = 0;
  var acceptableAccepted = 0;
  var acceptableRejected = 0;

  for (final fileName in files) {
    final suite = WycheproofSuite.load(fileName);

    group('RSA-PSS Wycheproof ($fileName)', () {
      for (final g in suite.groups) {
        final sha = g.field<String>('sha')!;
        final mgfSha = g.field<String>('mgfSha')!;
        final saltLength = g.intField('sLen')!;

        // The API derives the MGF1 digest from the PSS digest, so a group whose
        // two hashes differ is unrepresentable. None of the vendored groups do.
        if (sha != mgfSha) {
          skipped += g.tests.length;
          continue;
        }

        final publicKey = RsaKey.importSpki(g.bytes('publicKeyDer'));

        for (final c in g.tests) {
          final msg = c.bytes('msg');
          final sig = c.bytes('sig');

          exercised++;
          test(caseName(c), () {
            bool verify() => RsaPss.verify(publicKey, sig, msg, saltLength, sha);

            switch (c.result) {
              case 'valid':
                expect(verify(), isTrue);
              case 'invalid':
                // Fail-closed contract: a bad signature returns false, never
                // throws.
                expect(verify(), isFalse);
              case 'acceptable':
                // Legal but discouraged encodings: either outcome is allowed;
                // record which via the coverage summary.
                if (verify()) {
                  acceptableAccepted++;
                } else {
                  acceptableRejected++;
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

  test('RSA-PSS coverage summary', () {
    // ignore: avoid_print
    print(
      'RSA-PSS: $exercised cases exercised, $skipped skipped '
      '(group MGF1 hash differs from PSS hash); '
      'acceptable: $acceptableAccepted accepted, $acceptableRejected rejected.',
    );
    expect(exercised, greaterThan(0));
  });
}
