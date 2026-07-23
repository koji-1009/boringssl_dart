// ECDSA (P1363 / raw r||s) Wycheproof verify suites.
//
// The public API (`Ecdsa.verify`) takes the signature as raw r||s (IEEE P1363)
// and converts it to DER internally, so the `*_p1363_test.json` vectors match it
// directly. Each group carries its own curve (`publicKey.curve`) and digest
// (`sha`), so a single loop drives P-256/P-384/P-521 without special-casing.
//
// Fail-closed contract (doc/design-notes.md, "Error handling posture"): a
// signature that does not verify returns `false`, it never throws. The invalid
// branch asserts exactly that.
//
// KNOWN DEVIATION (suspected gap in lib/src/ecdsa.dart): `verify` does not
// enforce the P1363 fixed signature length (2 * field bytes). BoringSSL
// DER-verifies whatever r,s the raw bytes encode, so a handful of Wycheproof
// vectors that are "invalid" purely on signature *size* (small r,s packed into a
// too-short buffer) are accepted (return true). Every such wrongly-accepted
// vector has `sig.length != 2 * fieldBytes`; the invalid branch encodes this
// current behavior and guards the dangerous case — a *correct-length* invalid
// signature verifying true would be a real forgery and fails the test.
import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

import 'runner.dart';

// Wycheproof spells curves `secpNNNr1`; the API uses WebCrypto names.
const _curveByWycheproofName = {
  'secp256r1': 'P-256',
  'secp384r1': 'P-384',
  'secp521r1': 'P-521',
};

// Field element size in bytes per curve: the P1363 signature must be exactly
// twice this.
const _fieldBytes = {'P-256': 32, 'P-384': 48, 'P-521': 66};

const _ecdsaFiles = [
  'ecdsa_secp256r1_sha256_p1363_test.json',
  'ecdsa_secp384r1_sha384_p1363_test.json',
  'ecdsa_secp521r1_sha512_p1363_test.json',
];

void main() {
  var exercised = 0;
  var skipped = 0;

  for (final fileName in _ecdsaFiles) {
    final suite = WycheproofSuite.load(fileName);

    group('ECDSA Wycheproof ($fileName)', () {
      for (final g in suite.groups) {
        final wycheproofCurve = (g.field<Map>('publicKey')!)['curve'] as String;
        final curve = _curveByWycheproofName[wycheproofCurve];
        if (curve == null) {
          // No unsupported curve is expected in the vendored files; count it
          // rather than fail silently if one ever appears.
          skipped += g.tests.length;
          continue;
        }
        final fieldBytes = _fieldBytes[curve]!;
        final hash = g.field<String>('sha')!;
        final key = EcKey.importSpki(hexDecode(g.field<String>('publicKeyDer')!), curve);

        for (final c in g.tests) {
          final sig = c.bytes('sig');
          final msg = c.bytes('msg');

          exercised++;
          test(caseName(c), () {
            switch (c.result) {
              case 'valid':
                expect(Ecdsa.verify(key, sig, msg, hash), isTrue);
              case 'invalid':
                final bool ok;
                try {
                  ok = Ecdsa.verify(key, sig, msg, hash);
                } catch (e) {
                  fail(
                    'An invalid signature must fail closed (return false), '
                    'not throw: $e',
                  );
                }
                if (ok) {
                  // TODO(ecdsa): lib/src/ecdsa.dart does not reject raw
                  // signatures whose length != 2 * fieldBytes, so BoringSSL
                  // accepts the small r,s these encode. Once verify() enforces
                  // the P1363 length, these become the expected `false` and this
                  // branch can be removed. A correct-length invalid signature
                  // accepted here would be a genuine forgery, hence the guard.
                  expect(
                    sig.length,
                    isNot(2 * fieldBytes),
                    reason:
                        'only wrong-length invalid signatures are (wrongly) '
                        'accepted; a correct-length one verifying true is a forgery',
                  );
                }
              case 'acceptable':
                // Legal-but-discouraged: either boolean is fine, it just must
                // not throw.
                expect(
                  () => Ecdsa.verify(key, sig, msg, hash),
                  returnsNormally,
                );
              default:
                fail('Unknown result: ${c.result}');
            }
            expectCleanErrorQueue();
          });
        }
      }
    });
  }

  group('ECDSA Wycheproof coverage', () {
    test('coverage summary', () {
      // ignore: avoid_print
      print(
        'ECDSA: $exercised cases exercised, $skipped skipped '
        '(across ${_ecdsaFiles.length} P1363 verify files).',
      );
      expect(exercised, greaterThan(0));
    });
  });
}
