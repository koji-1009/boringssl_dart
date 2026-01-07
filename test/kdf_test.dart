import 'dart:convert';
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

void main() {
  group('HKDF', () {
    test('Derive Key (SHA-256)', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final salt = Uint8List.fromList(List.generate(16, (i) => i));
      final info = utf8.encode('info');

      final derived = Hkdf.derive(
        key: key,
        salt: salt,
        info: Uint8List.fromList(info),
        length: 32,
        hashAlgorithm: 'SHA-256',
      );
      expect(derived.length, equals(32));
      // Consistency check (determinism)
      final derived2 = Hkdf.derive(
        key: key,
        salt: salt,
        info: Uint8List.fromList(info),
        length: 32,
        hashAlgorithm: 'SHA-256',
      );
      expect(derived, equals(derived2));
    });

    test('Output too large', () {
      final key = Uint8List(32);
      // SHA-256 max is 255 * 32 = 8160 bytes
      // But let's try something absurdly large
      expect(
        () => Hkdf.derive(key: key, length: 100000, hashAlgorithm: 'SHA-256'),
        throwsA(
          isA<ArgumentError>(),
        ), // Captured the specific HKDF error mapping
      );
    });
  });

  group('PBKDF2', () {
    test('Derive Key (SHA-1)', () {
      final password = utf8.encode('password');
      final salt = utf8.encode('salt');
      final iterations = 1000;
      final length = 32;

      final derived = Pbkdf2.derive(
        key: Uint8List.fromList(password),
        salt: Uint8List.fromList(salt),
        iterations: iterations,
        length: length,
        hashAlgorithm: 'SHA-1',
      );
      expect(derived.length, equals(length));
    });

    test('Basic RFC 6070 Test Vector (SHA-1)', () {
      // P="password", S="salt", c=1, dkLen=20
      // DK=0c60c80f961f0e71f3a9b524af6012062fe037a6
      final password = utf8.encode('password');
      final salt = utf8.encode('salt');
      final derived = Pbkdf2.derive(
        key: Uint8List.fromList(password),
        salt: Uint8List.fromList(salt),
        iterations: 1,
        length: 20,
        hashAlgorithm: 'SHA-1',
      );
      final expected = '0c60c80f961f0e71f3a9b524af6012062fe037a6';
      final hex = derived
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join('');
      expect(hex, equals(expected));
    });
  });
}
