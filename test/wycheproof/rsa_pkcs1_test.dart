// RSA-SSA PKCS#1 v1.5 verify Wycheproof suite.
//
// The API (`RsaSsaPkcs1.verify`) drives BoringSSL's EVP_DigestVerify with
// PKCS#1 v1.5 padding and the group's hash. These files carry multiple test
// groups (differing key encodings) that each expose their own `publicKeyDer`
// and `sha`, so the key is imported per group.
//
// Per doc/design-notes.md ("Error handling posture") verify fails CLOSED: an
// invalid signature returns false and drains the error queue, it does not
// throw. This suite asserts that directly. The "acceptable" vectors here are
// legacy encodings (e.g. a missing ASN.1 NULL); either outcome is allowed and
// the split is recorded in the coverage summary.
import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

import 'runner.dart';

void main() {
  final files = [
    'rsa_signature_2048_sha256_test.json',
    'rsa_signature_2048_sha512_test.json',
  ];

  var exercised = 0;
  var skipped = 0;
  var acceptableAccepted = 0;
  var acceptableRejected = 0;

  for (final fileName in files) {
    final suite = WycheproofSuite.load(fileName);

    group('RSA-PKCS1 Wycheproof ($fileName)', () {
      for (final g in suite.groups) {
        final sha = g.field<String>('sha')!;
        final publicKey = RsaKey.importSpki(g.bytes('publicKeyDer'));

        for (final c in g.tests) {
          final msg = c.bytes('msg');
          final sig = c.bytes('sig');

          exercised++;
          test(caseName(c), () {
            bool verify() => RsaSsaPkcs1.verify(publicKey, sig, msg, sha);

            switch (c.result) {
              case 'valid':
                expect(verify(), isTrue);
              case 'invalid':
                // Fail-closed contract: a bad signature returns false, never
                // throws.
                expect(verify(), isFalse);
              case 'acceptable':
                // Legacy encoding: either outcome is allowed; record which via
                // the coverage summary.
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

  test('RSA-PKCS1 coverage summary', () {
    // ignore: avoid_print
    print(
      'RSA-PKCS1: $exercised cases exercised, $skipped skipped; '
      'acceptable: $acceptableAccepted accepted, $acceptableRejected rejected.',
    );
    expect(exercised, greaterThan(0));
  });
}
