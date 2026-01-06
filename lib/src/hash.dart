import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';

/// A hash algorithm.
class Hash {
  const Hash(this._algorithmName);
  static const Hash sha1 = Hash('SHA-1');
  static const Hash sha256 = Hash('SHA-256');
  static const Hash sha384 = Hash('SHA-384');
  static const Hash sha512 = Hash('SHA-512');

  final String _algorithmName;

  /// Compute the hash of [data].
  Uint8List digest(List<int> data) {
    return using((arena) {
      final ctx = EVP_MD_CTX_new();
      if (ctx == nullptr) {
        throw Exception('Failed to create digest context');
      }

      try {
        final md = switch (_algorithmName) {
          'SHA-1' => EVP_sha1(),
          'SHA-256' => EVP_sha256(),
          'SHA-384' => EVP_sha384(),
          'SHA-512' => EVP_sha512(),
          _ => throw ArgumentError('Unsupported algorithm: $_algorithmName'),
        };

        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
          throw Exception('Digest init failed for $_algorithmName');
        }

        final dataPtr = arena<Uint8>(data.length);
        final dataTyped = dataPtr.asTypedList(data.length);
        dataTyped.setAll(0, data);

        if (EVP_DigestUpdate(ctx, dataPtr.cast(), data.length) != 1) {
          throw Exception('Digest update failed');
        }

        // 64 bytes is enough for SHA-512 (largest supported here)
        final outPtr = arena<Uint8>(64);
        final outLenPtr = arena<UnsignedInt>();

        if (EVP_DigestFinal_ex(ctx, outPtr, outLenPtr) != 1) {
          throw Exception('Digest final failed');
        }

        final length = outLenPtr.value;
        return Uint8List.fromList(outPtr.asTypedList(length));
      } finally {
        EVP_MD_CTX_free(ctx);
      }
    });
  }
}
