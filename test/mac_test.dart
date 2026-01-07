import 'dart:convert';
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

void main() {
  group('HMAC', () {
    test('SHA-256 Sign (One-shot)', () {
      final key = utf8.encode('secret');
      final data = utf8.encode('hello world');
      final expected =
          '734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a';

      final signature = Hmac.sign(
        Uint8List.fromList(key),
        Uint8List.fromList(data),
        'SHA-256',
      );

      final hex = signature
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join('');
      expect(hex, equals(expected));
    });

    test('SHA-256 Verify (One-shot)', () {
      final key = utf8.encode('secret');
      final data = utf8.encode('hello world');
      final signature = Hmac.sign(
        Uint8List.fromList(key),
        Uint8List.fromList(data),
        'SHA-256',
      );

      final isValid = Hmac.verify(
        Uint8List.fromList(key),
        signature,
        Uint8List.fromList(data),
        'SHA-256',
      );
      expect(isValid, isTrue);

      // Tamper signature
      signature[0] ^= 0xff;
      final isInvalid = Hmac.verify(
        Uint8List.fromList(key),
        signature,
        Uint8List.fromList(data),
        'SHA-256',
      );
      expect(isInvalid, isFalse);
    });

    test('Streaming API', () {
      final key = utf8.encode('secret');
      final data1 = utf8.encode('hello ');
      final data2 = utf8.encode('world');

      final signer = HmacSigner(Uint8List.fromList(key), 'SHA-256');
      signer.update(Uint8List.fromList(data1));
      signer.update(Uint8List.fromList(data2));
      final signature = signer.finish();

      final expected = Hmac.sign(
        Uint8List.fromList(key),
        utf8.encode('hello world'),
        'SHA-256',
      );
      expect(signature, equals(expected));

      // After finish, should throw
      expect(() => signer.update(Uint8List(1)), throwsStateError);
      expect(() => signer.finish(), throwsStateError);
    });

    test('Invalid Algorithm', () {
      final key = Uint8List(16);
      final data = Uint8List(16);
      expect(
        () => Hmac.sign(key, data, 'MD5'), // MD5 not supported in our wrapper
        throwsArgumentError,
      );
    });
  });
}
