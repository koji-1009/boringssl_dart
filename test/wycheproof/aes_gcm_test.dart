// AES-GCM Wycheproof suite.
//
// The API (`AesGcm`) is built on BoringSSL's EVP_AEAD AES-GCM. Empirically
// (verified against these vectors, not assumed) that primitive is NOT restricted
// to a 12-byte nonce: it implements the full GCM construction, deriving J0 via
// GHASH for non-96-bit IVs, and roundtrips every non-96-bit-IV vector here. The
// one length it rejects is a zero-length IV — and the only zero-length-IV group
// in the vectors is marked "invalid", so it is covered by the ordinary
// invalid -> throws branch. Consequently no group is special-cased by IV size;
// every group runs the standard valid/invalid/acceptable logic. `AesGcm`'s doc
// documents exactly this contract: any non-empty IV, 12 bytes being standard.
//
// Decrypt input is `ct || tag`; `tagLength` is the tag size in bytes. All groups
// here use a 128-bit tag; a group whose tag falls outside the API's 12..16-byte
// range would be skipped (none currently do).
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

import 'runner.dart';

void main() {
  final suite = WycheproofSuite.load('aes_gcm_test.json');

  var exercised = 0;
  var skipped = 0;

  group('AES-GCM Wycheproof (${suite.algorithm})', () {
    for (final g in suite.groups) {
      final tagBytes = g.tagSize! ~/ 8;
      // The API expresses the tag length in bytes and supports 12..16.
      if (tagBytes < 12 || tagBytes > 16) {
        skipped += g.tests.length;
        continue;
      }

      for (final c in g.tests) {
        final key = c.bytes('key');
        final iv = c.bytes('iv');
        final aad = c.bytes('aad');
        final msg = c.bytes('msg');
        final ctTag = Uint8List.fromList([...c.bytes('ct'), ...c.bytes('tag')]);

        exercised++;
        test(caseName(c), () {
          Uint8List decrypt() => AesGcm.decrypt(
            key,
            iv,
            ctTag,
            additionalData: aad,
            tagLength: tagBytes,
          );

          switch (c.result) {
            case 'valid':
              expect(decrypt(), equals(msg));
              // Encryption is deterministic for a fixed key/iv/aad, so the
              // sealed output must reproduce ct || tag exactly.
              final sealed = AesGcm.encrypt(
                key,
                iv,
                msg,
                additionalData: aad,
                tagLength: tagBytes,
              );
              expect(sealed, equals(ctTag));
            case 'invalid':
              // Tampered ciphertext/tag/aad, or a rejected IV (zero-length):
              // decryption must fail. ArgumentError (an Error) and Exception are
              // both acceptable, so match broadly.
              expect(decrypt, throwsA(anything));
            case 'acceptable':
              // Legal but discouraged parameters: rejection is an acceptable
              // outcome, but if the API accepts the input, the recovered
              // plaintext must be correct — only the decrypt call itself may
              // fail, never the plaintext comparison.
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

    test('coverage summary', () {
      // ignore: avoid_print
      print(
        'AES-GCM: $exercised cases exercised, $skipped skipped '
        '(tag length outside 12..16 bytes) '
        '(of ${suite.numberOfTests} total vectors).',
      );
      expect(exercised, greaterThan(0));
    });
  });
}
