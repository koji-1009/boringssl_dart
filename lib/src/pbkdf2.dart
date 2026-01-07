import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';

/// PBKDF2 key derivation.
class Pbkdf2 {
  const Pbkdf2._();

  /// Derives a key using PBKDF2.
  ///
  /// [key] is the input key.
  /// [salt] is the salt.
  /// [iterations] is the number of iterations.
  /// [length] is the length of the derived key in **bytes**.
  /// [hashAlgorithm] is the hash algorithm to use.
  static Uint8List derive({
    required Uint8List key,
    required Uint8List salt,
    required int iterations,
    required int length,
    required String hashAlgorithm,
  }) {
    if (iterations <= 0) {
      throw ArgumentError('Iterations must be positive');
    }

    return using((arena) {
      final md = _getEvpMd(hashAlgorithm);

      final outPtr = arena<Uint8>(length);
      final keyPtr = arena<Uint8>(key.length);
      keyPtr.asTypedList(key.length).setAll(0, key);

      final saltPtr = arena<Uint8>(salt.length);
      saltPtr.asTypedList(salt.length).setAll(0, salt);

      final result = PKCS5_PBKDF2_HMAC(
        keyPtr.cast(),
        key.length,
        saltPtr,
        salt.length,
        iterations,
        md,
        length,
        outPtr,
      );

      if (result != 1) {
        throw Exception('PBKDF2 derivation failed');
      }

      return Uint8List.fromList(outPtr.asTypedList(length));
    });
  }

  static Pointer<EVP_MD> _getEvpMd(String algorithm) {
    return switch (algorithm) {
      'SHA-1' => EVP_sha1(),
      'SHA-256' => EVP_sha256(),
      'SHA-384' => EVP_sha384(),
      'SHA-512' => EVP_sha512(),
      _ => throw ArgumentError('Unsupported algorithm: $algorithm'),
    };
  }
}
