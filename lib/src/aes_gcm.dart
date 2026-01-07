import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';

/// AES-GCM encryption/decryption.
class AesGcm {
  const AesGcm._();

  /// Encrypts [data] using AES-GCM.
  ///
  /// [key] must be 16, 24, or 32 bytes.
  /// [iv] must be 12 bytes.
  /// [additionalData] (optional) is authenticated but not encrypted.
  /// [tagLength] must be between 12 and 16 bytes.
  static Uint8List encrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List data, {
    Uint8List? additionalData,
    int tagLength = 16,
  }) {
    return _transform(
      key,
      iv,
      data,
      additionalData ?? Uint8List(0),
      tagLength,
      true,
    );
  }

  /// Decrypts [data] using AES-GCM.
  ///
  /// [key] must be 16, 24, or 32 bytes.
  /// [iv] must be 12 bytes.
  /// [additionalData] must match the data used during encryption.
  /// [tagLength] must match the tag length used during encryption.
  /// The tag is expected to be appended to the end of [data].
  static Uint8List decrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List data, {
    Uint8List? additionalData,
    int tagLength = 16,
  }) {
    return _transform(
      key,
      iv,
      data,
      additionalData ?? Uint8List(0),
      tagLength,
      false,
    );
  }

  static Uint8List _transform(
    Uint8List key,
    Uint8List iv,
    Uint8List data,
    Uint8List additionalData,
    int tagLength,
    bool encrypt,
  ) {
    return using((arena) {
      final aead = switch (key.length) {
        16 => EVP_aead_aes_128_gcm(),
        32 => EVP_aead_aes_256_gcm(),
        _ => throw ArgumentError('Invalid key length: ${key.length}'),
      };

      final keyPtr = arena<Uint8>(key.length);
      keyPtr.asTypedList(key.length).setAll(0, key);

      final ctx = EVP_AEAD_CTX_new(aead, keyPtr, key.length, tagLength);

      if (ctx == nullptr) {
        throw Exception('Failed to create AEAD context');
      }

      try {
        final noncePtr = arena<Uint8>(iv.length);
        noncePtr.asTypedList(iv.length).setAll(0, iv);

        final inPtr = arena<Uint8>(data.length);
        inPtr.asTypedList(data.length).setAll(0, data);

        final adPtr = arena<Uint8>(additionalData.length);
        if (additionalData.isNotEmpty) {
          adPtr.asTypedList(additionalData.length).setAll(0, additionalData);
        }

        // Output buffer size calculation:
        // Encrypt: input + overhead (tag)
        // Decrypt: input
        final maxOutLen = encrypt ? data.length + tagLength : data.length;
        final outPtr = arena<Uint8>(maxOutLen);
        final outLenPtr = arena<Size>();

        int result;
        if (encrypt) {
          result = EVP_AEAD_CTX_seal(
            ctx,
            outPtr,
            outLenPtr,
            maxOutLen,
            noncePtr,
            iv.length,
            inPtr,
            data.length,
            additionalData.isNotEmpty ? adPtr : nullptr,
            additionalData.length,
          );
        } else {
          result = EVP_AEAD_CTX_open(
            ctx,
            outPtr,
            outLenPtr,
            maxOutLen,
            noncePtr,
            iv.length,
            inPtr,
            data.length,
            additionalData.isNotEmpty ? adPtr : nullptr,
            additionalData.length,
          );
        }

        if (result != 1) {
          throw Exception(encrypt ? 'Encryption failed' : 'Decryption failed');
        }

        return Uint8List.fromList(outPtr.asTypedList(outLenPtr.value));
      } finally {
        EVP_AEAD_CTX_free(ctx);
      }
    });
  }
}
