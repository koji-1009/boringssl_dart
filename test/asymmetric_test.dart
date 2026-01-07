import 'dart:convert';
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

import 'test_keys.dart';

void main() {
  group('EC Keys', () {
    test('Generate P-256', () {
      final key = EcKey.generate('P-256');
      expect(key, isNotNull);
      final exported = key.exportCoordinates();
      expect(exported['x'], hasLength(32));
      expect(exported['y'], hasLength(32));
      expect(exported['d'], hasLength(32)); // Private key present
    });
  });

  group('ECDSA', () {
    test('Sign/Verify P-256 SHA-256', () {
      final key = EcKey.generate('P-256');
      final data = utf8.encode('hello');
      final sig = Ecdsa.sign(key, Uint8List.fromList(data), 'SHA-256');

      final isValid = Ecdsa.verify(
        key,
        sig,
        Uint8List.fromList(data),
        'SHA-256',
      );
      expect(isValid, isTrue);

      final isInvalid = Ecdsa.verify(
        key,
        sig,
        Uint8List.fromList(utf8.encode('wrong')),
        'SHA-256',
      );
      expect(isInvalid, isFalse);
    });
  });

  group('ECDH', () {
    test('Compute Bits P-256', () {
      final alice = EcKey.generate('P-256');
      final bob = EcKey.generate('P-256');

      final secretAr = Ecdh.computeBits(alice, bob, 256);
      final secretBr = Ecdh.computeBits(bob, alice, 256);

      expect(secretAr, equals(secretBr));
    });
  });

  group('RSA-PSS', () {
    test('Sign/Verify', () {
      final priv = RsaKey.importPkcs8(rsaPrivateKey);
      final pub = RsaKey.importSpki(rsaPublicKey);
      final data = utf8.encode('hello pss');

      final sig = RsaPss.sign(priv, Uint8List.fromList(data), 32, 'SHA-256');
      expect(sig.length, equals(256)); // 2048-bit key

      final isValid = RsaPss.verify(
        pub,
        sig,
        Uint8List.fromList(data),
        32,
        'SHA-256',
      );
      expect(isValid, isTrue);
    });
  });

  group('RSA-SSA-PKCS1', () {
    test('Sign/Verify', () {
      final priv = RsaKey.importPkcs8(rsaPrivateKey);
      final pub = RsaKey.importSpki(rsaPublicKey);
      final data = utf8.encode('hello pkcs1');

      final sig = RsaSsaPkcs1.sign(priv, Uint8List.fromList(data), 'SHA-256');

      final isValid = RsaSsaPkcs1.verify(
        pub,
        sig,
        Uint8List.fromList(data),
        'SHA-256',
      );
      expect(isValid, isTrue);
    });
  });
}
