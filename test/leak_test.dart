/// A repeated-verify sanity loop: thousands of alternating valid/invalid
/// verifications must return stable results with no growth in the BoringSSL
/// error queue. A rejection leaves an error stacked, and a later call could
/// observe it — so a valid verification must stay valid even immediately after
/// an invalid one drained the queue. Also a coarse guard against per-call
/// native leaks (each iteration allocates and frees native scratch).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

import 'test_keys.dart';

void main() {
  test('5000 alternating ECDSA + RSA verifications stay stable', () {
    // Keys and signatures are minted once; the loop only verifies, which is
    // where fail-closed error-queue draining has to hold up under repetition.
    final ec = EcKey.generate('P-256');
    final rsaPriv = RsaKey.importPkcs8(rsaPrivateKey);
    final rsaPub = RsaKey.importSpki(rsaPublicKey);

    final message = Uint8List.fromList(utf8.encode('repeated verification'));
    final badMessage = Uint8List.fromList(utf8.encode('a different message'));
    final ecSig = Ecdsa.sign(ec, message, 'SHA-256');
    final rsaSig = RsaSsaPkcs1.sign(rsaPriv, message, 'SHA-256');

    for (var i = 0; i < 5000; i++) {
      expect(Ecdsa.verify(ec, ecSig, message, 'SHA-256'), isTrue);
      expect(Ecdsa.verify(ec, ecSig, badMessage, 'SHA-256'), isFalse);
      expect(RsaSsaPkcs1.verify(rsaPub, rsaSig, message, 'SHA-256'), isTrue);
      expect(RsaSsaPkcs1.verify(rsaPub, rsaSig, badMessage, 'SHA-256'), isFalse);
    }

    // Nothing consumed above left residue behind: after 10000 rejections the
    // thread-local error queue is drained clean.
    expect(getOpenSslErrors(), isEmpty);
  });
}
