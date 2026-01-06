import 'dart:convert';
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

void main() {
  group('BoringSSL Tests', () {
    test('getRandomValues generates random bytes', () {
      const length = 16;
      final buffer = Uint8List(length);

      getRandomValues(buffer);

      bool allZero = true;
      for (var i = 0; i < length; i++) {
        if (buffer[i] != 0) {
          allZero = false;
          break;
        }
      }
      expect(allZero, isFalse, reason: 'Random bytes should not be all zero');
    });

    test('SHA-256 digest', () {
      final data = utf8.encode('hello world');
      final digest = Hash.sha256.digest(data);

      // "hello world" sha256: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
      const expected =
          'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';

      final hex = digest
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join('');
      expect(hex, equals(expected));
    });

    test('SHA-1 digest', () {
      final data = utf8.encode('hello world');
      final digest = Hash.sha1.digest(data);
      // "hello world" sha1: 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
      const expected = '2aae6c35c94fcfb415dbe95f408b9ce91ee846ed';
      final hex = digest
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join('');
      expect(hex, equals(expected));
    });

    test('SHA-384 digest', () {
      final data = utf8.encode('hello world');
      final digest = Hash.sha384.digest(data);
      // sha384: fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd
      const expected =
          'fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd';
      final hex = digest
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join('');
      expect(hex, equals(expected));
    });

    test('SHA-512 digest', () {
      final data = utf8.encode('hello world');
      final digest = Hash.sha512.digest(data);
      // sha512: 309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f
      const expected =
          '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f';
      final hex = digest
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join('');
      expect(hex, equals(expected));
    });
  });
}
