import 'dart:convert';
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

import 'test_keys.dart';

void main() {
  group('AES-CBC', () {
    test('Encrypt/Decrypt roundtrip', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final iv = Uint8List.fromList(List.generate(16, (i) => i));
      final plainText = utf8.encode('Hello BoringSSL');

      final cipherText = AesCbc.encrypt(key, iv, Uint8List.fromList(plainText));
      expect(cipherText, isNot(equals(plainText)));

      final decrypted = AesCbc.decrypt(key, iv, cipherText);
      expect(utf8.decode(decrypted), equals('Hello BoringSSL'));
    });

    test('Known Answer Test (OpenSSL)', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final iv = Uint8List.fromList(List.generate(16, (i) => i));
      final plainText = utf8.encode('Hello BoringSSL');

      // Generated using:
      // echo -n "Hello BoringSSL" | openssl enc -aes-256-cbc -K ... -iv ... -nosalt | xxd -p
      // Result: 94537efd3732b6b785eab1e698fa60df
      final expectedCipherHex = '94537efd3732b6b785eab1e698fa60df';
      final expectedCipher = Uint8List.fromList(
        List.generate(expectedCipherHex.length ~/ 2, (i) {
          return int.parse(
            expectedCipherHex.substring(i * 2, i * 2 + 2),
            radix: 16,
          );
        }),
      );

      final cipherText = AesCbc.encrypt(key, iv, Uint8List.fromList(plainText));

      expect(cipherText, equals(expectedCipher));
    });

    test('Invalid key length', () {
      final key = Uint8List(10); // Invalid
      final iv = Uint8List(16);
      final data = Uint8List(10);

      expect(
        () => AesCbc.encrypt(key, iv, data),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('AES-CTR', () {
    test('Encrypt/Decrypt roundtrip', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final iv = Uint8List.fromList(List.generate(16, (i) => i));
      final plainText = utf8.encode('Hello BoringSSL CTR');

      final cipherText = AesCtr.encrypt(key, iv, Uint8List.fromList(plainText));
      expect(cipherText, isNot(equals(plainText)));

      final decrypted = AesCtr.decrypt(key, iv, cipherText);
      expect(utf8.decode(decrypted), equals('Hello BoringSSL CTR'));
    });
  });

  group('RSA-OAEP', () {
    test('Encrypt/Decrypt roundtrip', () {
      final plainText = utf8.encode('Hello RSA-OAEP');

      final cipherText = RsaOaep.encrypt(
        rsaPublicKey,
        Uint8List.fromList(plainText),
      );
      expect(cipherText, isNot(equals(plainText)));
      expect(cipherText.length, equals(128)); // 1024 bits = 128 bytes

      final decrypted = RsaOaep.decrypt(rsaPrivateKey, cipherText);
      expect(utf8.decode(decrypted), equals('Hello RSA-OAEP'));
    });

    test('With Label', () {
      final plainText = utf8.encode('Label Test');
      final label = utf8.encode('secret-label');

      final cipherText = RsaOaep.encrypt(
        rsaPublicKey,
        Uint8List.fromList(plainText),
        label: Uint8List.fromList(label),
      );

      final decrypted = RsaOaep.decrypt(
        rsaPrivateKey,
        cipherText,
        label: Uint8List.fromList(label),
      );
      expect(utf8.decode(decrypted), equals('Label Test'));

      // Wrong label should fail
      expect(
        () => RsaOaep.decrypt(
          rsaPrivateKey,
          cipherText,
          label: Uint8List.fromList(utf8.encode('wrong')),
        ),
        throwsA(isA<Exception>()),
      );
    });
  });

  group('AES-GCM', () {
    test('Encrypt/Decrypt roundtrip', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final iv = Uint8List.fromList(List.generate(12, (i) => i));
      final plainText = utf8.encode('Hello BoringSSL GCM');
      final aad = utf8.encode('aad');

      final cipherText = AesGcm.encrypt(
        key,
        iv,
        Uint8List.fromList(plainText),
        additionalData: Uint8List.fromList(aad),
      );
      expect(cipherText, isNot(equals(plainText)));

      final decrypted = AesGcm.decrypt(
        key,
        iv,
        cipherText,
        additionalData: Uint8List.fromList(aad),
      );
      expect(utf8.decode(decrypted), equals('Hello BoringSSL GCM'));
    });

    test('Tag validation failure', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final iv = Uint8List.fromList(List.generate(12, (i) => i));
      final plainText = utf8.encode('Secret');

      final cipherText = AesGcm.encrypt(key, iv, Uint8List.fromList(plainText));

      // Tamper with the tag (last 16 bytes by default)
      cipherText[cipherText.length - 1] ^= 0xFF;

      expect(
        () => AesGcm.decrypt(key, iv, cipherText),
        throwsA(isA<Exception>()), // Decryption (auth tag check) failed
      );
    });
  });
}
