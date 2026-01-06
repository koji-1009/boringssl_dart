import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';

/// AES-CBC encryption/decryption.
class AesCbc {
  const AesCbc._();

  /// Encrypts [data] using AES-CBC.
  ///
  /// [key] must be 16, 24, or 32 bytes.
  /// [iv] must be 16 bytes.
  static Uint8List encrypt(Uint8List key, Uint8List iv, Uint8List data) {
    return _transform(key, iv, data, true);
  }

  /// Decrypts [data] using AES-CBC.
  ///
  /// [key] must be 16, 24, or 32 bytes.
  /// [iv] must be 16 bytes.
  static Uint8List decrypt(Uint8List key, Uint8List iv, Uint8List data) {
    return _transform(key, iv, data, false);
  }

  static Uint8List _transform(
    Uint8List key,
    Uint8List iv,
    Uint8List data,
    bool encrypt,
  ) {
    return using((arena) {
      final ctx = EVP_CIPHER_CTX_new();
      if (ctx == nullptr) {
        throw Exception('Failed to create cipher context');
      }

      try {
        final cipher = switch (key.length) {
          16 => EVP_aes_128_cbc(),
          24 => EVP_aes_192_cbc(),
          32 => EVP_aes_256_cbc(),
          _ => throw ArgumentError('Invalid key length: ${key.length}'),
        };

        if (iv.length != 16) {
          throw ArgumentError('IV must be 16 bytes');
        }

        final keyPtr = arena<Uint8>(key.length);
        keyPtr.asTypedList(key.length).setAll(0, key);

        final ivPtr = arena<Uint8>(iv.length);
        ivPtr.asTypedList(iv.length).setAll(0, iv);

        final enc = encrypt ? 1 : 0;
        if (EVP_CipherInit_ex(ctx, cipher, nullptr, keyPtr, ivPtr, enc) != 1) {
          throw Exception('Cipher init failed');
        }

        // Output buffer size calculation:
        // Input length + block size (for padding)
        final blockSize = 16;
        final outPtr = arena<Uint8>(data.length + blockSize);
        final outLenPtr = arena<Int>();
        final totalOut = <int>[];

        final inPtr = arena<Uint8>(data.length);
        inPtr.asTypedList(data.length).setAll(0, data);

        if (EVP_CipherUpdate(ctx, outPtr, outLenPtr, inPtr, data.length) != 1) {
          throw Exception('Cipher update failed');
        }
        totalOut.addAll(outPtr.asTypedList(outLenPtr.value));

        if (EVP_CipherFinal_ex(ctx, outPtr, outLenPtr) != 1) {
          throw Exception('Cipher final failed');
        }
        totalOut.addAll(outPtr.asTypedList(outLenPtr.value));

        return Uint8List.fromList(totalOut);
      } finally {
        EVP_CIPHER_CTX_free(ctx);
      }
    });
  }
}
