// ECDH Wycheproof suites (P-256 / P-384 / P-521, ASN encoding).
//
// Per-case shape: `public` is a DER SPKI key, `private` is the raw scalar as a
// bignum, `shared` is the expected secret. `Ecdh.computeBits` needs two EcKeys,
// so the peer key comes from `EcKey.importSpki` and the local key is rebuilt
// from the scalar. The API has no "import raw private scalar" entry, so we wrap
// the scalar in a minimal PKCS#8 (public point omitted; BoringSSL derives it)
// and feed it to `EcKey.importPkcs8` — see `_pkcs8FromScalar`.
//
// Outcomes, empirically confirmed against these vectors:
//   valid      -> import + derive succeed; secret equals the vector's `shared`.
//   invalid    -> rejected during key import or derivation (throws); the secret
//                 is never produced. Asserted via `isNull`, which also traps the
//                 red-flag case of an invalid input silently reproducing `shared`.
//   acceptable -> per the AES-GCM exemplar convention: only the derivation sits
//                 in try/catch; if it succeeds, the `equals(shared)` assertion
//                 runs OUTSIDE the catch so a wrong secret can never be swallowed.
//                 Most acceptable encodings (unnamed curve, compressed points)
//                 are rejected at import; the few that derive must match.
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

import 'runner.dart';

// Wycheproof spells curves `secpNNNr1`; the API uses WebCrypto names.
const _curveByWycheproofName = {
  'secp256r1': 'P-256',
  'secp384r1': 'P-384',
  'secp521r1': 'P-521',
};

// Shared-secret / field element length in bytes per curve. `computeBits` takes
// a bit length; the full secret is this many bytes.
const _sharedBytes = {'P-256': 32, 'P-384': 48, 'P-521': 66};

const _ecdhFiles = [
  'ecdh_secp256r1_test.json',
  'ecdh_secp384r1_test.json',
  'ecdh_secp521r1_test.json',
];

// Named-curve OIDs, DER-encoded (tag+len+content), for the PKCS#8 wrapper.
final _curveOid = {
  'P-256': _hex('06082a8648ce3d030107'), // 1.2.840.10045.3.1.7
  'P-384': _hex('06052b81040022'), //       1.3.132.0.34
  'P-521': _hex('06052b81040023'), //       1.3.132.0.35
};
// AlgorithmIdentifier OID for id-ecPublicKey (1.2.840.10045.2.1), DER-encoded.
final _ecPublicKeyOid = _hex('06072a8648ce3d0201');

void main() {
  var exercised = 0;
  var skipped = 0;

  for (final fileName in _ecdhFiles) {
    final suite = WycheproofSuite.load(fileName);

    group('ECDH Wycheproof ($fileName)', () {
      for (final g in suite.groups) {
        final curve = _curveByWycheproofName[g.field<String>('curve')!];
        if (curve == null) {
          skipped += g.tests.length;
          continue;
        }
        final secretBits = _sharedBytes[curve]! * 8;

        for (final c in g.tests) {
          final publicDer = c.bytes('public');
          final privateScalar = c.bytes('private');
          final shared = c.bytesOrNull('shared') ?? Uint8List(0);

          exercised++;
          test(caseName(c), () {
            Uint8List derive() {
              final peer = EcKey.importSpki(publicDer, curve);
              final local = EcKey.importPkcs8(
                _pkcs8FromScalar(privateScalar, curve),
                curve,
              );
              return Ecdh.computeBits(local, peer, secretBits);
            }

            switch (c.result) {
              case 'valid':
                // A valid vector must import and derive; any throw is a failure.
                expect(derive(), equals(shared));
              case 'invalid':
                Uint8List? secret;
                try {
                  secret = derive();
                } catch (_) {
                  // Rejection is the expected path; secret stays null.
                }
                // Rejection is the required outcome; a produced secret — most
                // dangerously one equal to `shared` — would mean an invalid
                // input was accepted.
                expect(
                  secret,
                  isNull,
                  reason:
                      'invalid ECDH input must be rejected, not derived into a '
                      'shared secret',
                );
              case 'acceptable':
                Uint8List? secret;
                try {
                  secret = derive();
                } catch (_) {
                  // Rejection is also acceptable; secret stays null.
                }
                if (secret != null) {
                  expect(secret, equals(shared));
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

  group('ECDH Wycheproof coverage', () {
    test('coverage summary', () {
      // ignore: avoid_print
      print(
        'ECDH: $exercised cases exercised, $skipped skipped '
        '(across ${_ecdhFiles.length} files).',
      );
      expect(exercised, greaterThan(0));
    });
  });
}

/// Wraps a raw EC private scalar in a minimal PKCS#8 `PrivateKeyInfo` so it can
/// be imported via [EcKey.importPkcs8]. The public point is intentionally
/// omitted from the inner `ECPrivateKey`; BoringSSL derives it from the scalar.
///
/// The scalar is stripped of leading zeros then left-padded to the curve's field
/// length, as SEC1 requires. An over-length scalar (an out-of-range private key)
/// is passed through verbatim so the import rejects it.
Uint8List _pkcs8FromScalar(Uint8List scalar, String curve) {
  final fieldLen = _sharedBytes[curve]!;
  var start = 0;
  while (start < scalar.length && scalar[start] == 0) {
    start++;
  }
  final stripped = scalar.sublist(start);
  final Uint8List privKey;
  if (stripped.length <= fieldLen) {
    privKey = Uint8List(fieldLen)
      ..setRange(fieldLen - stripped.length, fieldLen, stripped);
  } else {
    privKey = Uint8List.fromList(scalar);
  }

  // ECPrivateKey ::= SEQUENCE { version INTEGER(1), privateKey OCTET STRING,
  //                             [0] parameters (namedCurve OID) }
  final ecPrivateKey = _der(0x30, [
    ..._der(0x02, const [0x01]),
    ..._der(0x04, privKey),
    ..._der(0xA0, _curveOid[curve]!),
  ]);
  // PrivateKeyInfo ::= SEQUENCE { version INTEGER(0),
  //   privateKeyAlgorithm SEQUENCE { id-ecPublicKey, namedCurve },
  //   privateKey OCTET STRING (ECPrivateKey) }
  return Uint8List.fromList(
    _der(0x30, [
      ..._der(0x02, const [0x00]),
      ..._der(0x30, [..._ecPublicKeyOid, ..._curveOid[curve]!]),
      ..._der(0x04, ecPrivateKey),
    ]),
  );
}

/// Emits a DER TLV: `tag`, definite-form length, then `content`.
List<int> _der(int tag, List<int> content) {
  final out = <int>[tag];
  final len = content.length;
  if (len < 0x80) {
    out.add(len);
  } else {
    final lenBytes = <int>[];
    var l = len;
    while (l > 0) {
      lenBytes.add(l & 0xff);
      l >>= 8;
    }
    out
      ..add(0x80 | lenBytes.length)
      ..addAll(lenBytes.reversed);
  }
  return out..addAll(content);
}

Uint8List _hex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
