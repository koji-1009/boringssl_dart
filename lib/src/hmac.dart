import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';

/// One-shot and streaming HMAC.
class Hmac {
  const Hmac._();

  /// Computes the HMAC of [data] using [key] and [hashAlgorithm].
  ///
  /// Supported [hashAlgorithm] values: 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'.
  static Uint8List sign(Uint8List key, Uint8List data, String hashAlgorithm) {
    return using((arena) {
      final ctx = HMAC_CTX_new();
      if (ctx == nullptr) {
        throw Exception('Failed to create HMAC context');
      }

      try {
        final md = _getEvpMd(hashAlgorithm);
        final keyPtr = arena<Uint8>(key.length);
        keyPtr.asTypedList(key.length).setAll(0, key);

        if (HMAC_Init_ex(ctx, keyPtr.cast(), key.length, md, nullptr) != 1) {
          throw Exception('HMAC init failed');
        }

        final dataPtr = arena<Uint8>(data.length);
        dataPtr.asTypedList(data.length).setAll(0, data);

        if (HMAC_Update(ctx, dataPtr, data.length) != 1) {
          throw Exception('HMAC update failed');
        }

        final outLenPtr = arena<UnsignedInt>();
        // Max size for SHA-512 is 64 bytes.
        final outPtr = arena<Uint8>(64);

        if (HMAC_Final(ctx, outPtr, outLenPtr) != 1) {
          throw Exception('HMAC final failed');
        }

        return Uint8List.fromList(outPtr.asTypedList(outLenPtr.value));
      } finally {
        HMAC_CTX_free(ctx);
      }
    });
  }

  /// Verifies [signature] for [data] using [key] and [hashAlgorithm].
  static bool verify(
    Uint8List key,
    Uint8List signature,
    Uint8List data,
    String hashAlgorithm,
  ) {
    // Constant-time check is important, but BoringSSL CRYPTO_memcmp is exposed.
    // However, for simplicity in Dart, we can re-compute and compare.
    // Ideally we use CRYPTO_memcmp from bindings.
    final computed = sign(key, data, hashAlgorithm);
    if (computed.length != signature.length) return false;

    // We should use CRYPTO_memcmp for constant time comparison.
    return using((arena) {
      final sig1 = arena<Uint8>(computed.length);
      sig1.asTypedList(computed.length).setAll(0, computed);

      final sig2 = arena<Uint8>(signature.length);
      sig2.asTypedList(signature.length).setAll(0, signature);

      return CRYPTO_memcmp(sig1.cast(), sig2.cast(), computed.length) == 0;
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

/// Streaming HMAC signer.
class HmacSigner implements Finalizable {
  static final _finalizer = NativeFinalizer(
    Native.addressOf<NativeFunction<Void Function(Pointer<HMAC_CTX>)>>(
      HMAC_CTX_free,
    ).cast(),
  );

  final Pointer<HMAC_CTX> _ctx;
  bool _isClosed = false;

  HmacSigner._(this._ctx);

  /// Create a new signer.
  factory HmacSigner(Uint8List key, String hashAlgorithm) {
    final ctx = HMAC_CTX_new();
    if (ctx == nullptr) {
      throw Exception('Failed to create HMAC context');
    }
    try {
      final signer = HmacSigner._(ctx);
      _finalizer.attach(signer, ctx.cast(), detach: signer);

      using((arena) {
        final md = Hmac._getEvpMd(hashAlgorithm);
        final keyPtr = arena<Uint8>(key.length);
        keyPtr.asTypedList(key.length).setAll(0, key);

        if (HMAC_Init_ex(ctx, keyPtr.cast(), key.length, md, nullptr) != 1) {
          throw Exception('HMAC init failed');
        }
      });

      return signer;
    } catch (_) {
      HMAC_CTX_free(ctx);
      rethrow;
    }
  }

  /// Update with [data].
  void update(Uint8List data) {
    if (_isClosed) throw StateError('Signer is closed');
    using((arena) {
      final dataPtr = arena<Uint8>(data.length);
      dataPtr.asTypedList(data.length).setAll(0, data);
      if (HMAC_Update(_ctx, dataPtr, data.length) != 1) {
        throw Exception('HMAC update failed');
      }
    });
  }

  /// Finish and return signature.
  Uint8List finish() {
    if (_isClosed) throw StateError('Signer is closed');
    _isClosed = true;
    return using((arena) {
      final outLenPtr = arena<UnsignedInt>();
      final outPtr = arena<Uint8>(64); // Max size

      if (HMAC_Final(_ctx, outPtr, outLenPtr) != 1) {
        throw Exception('HMAC final failed');
      }
      return Uint8List.fromList(outPtr.asTypedList(outLenPtr.value));
    });
  }
}
