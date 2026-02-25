import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';
import 'util.dart';

/// A hash algorithm.
class Hash {
  const Hash(this._algorithmName);
  static const Hash sha1 = Hash('SHA-1');
  static const Hash sha256 = Hash('SHA-256');
  static const Hash sha384 = Hash('SHA-384');
  static const Hash sha512 = Hash('SHA-512');

  final String _algorithmName;

  /// Start a streaming hash computation.
  HashContext start() => HashContext._(_algorithmName);

  /// Compute the hash of [data].
  Uint8List digest(List<int> data) {
    return using((arena) {
      final ctx = EVP_MD_CTX_new();
      if (ctx == nullptr) {
        throw Exception('Failed to create digest context');
      }

      try {
        final md = getEvpMd(_algorithmName);

        if (EVP_DigestInit(ctx, md) != 1) {
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

        if (EVP_DigestFinal(ctx, outPtr, outLenPtr) != 1) {
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

/// Streaming hash context.
class HashContext implements Finalizable {
  static final _finalizer = NativeFinalizer(
    Native.addressOf<NativeFunction<Void Function(Pointer<EVP_MD_CTX>)>>(
      EVP_MD_CTX_free,
    ).cast(),
  );

  final Pointer<EVP_MD_CTX> _ctx;
  bool _isClosed = false;

  HashContext._(String algorithm) : _ctx = EVP_MD_CTX_new() {
    if (_ctx == nullptr) {
      throw Exception('Failed to create context');
    }
    _finalizer.attach(this, _ctx.cast(), detach: this);

    try {
      final md = getEvpMd(algorithm);
      if (EVP_DigestInit(_ctx, md) != 1) {
        throw Exception('Digest init failed');
      }
    } catch (_) {
      EVP_MD_CTX_free(_ctx);
      _finalizer.detach(this);
      rethrow;
    }
  }

  void update(List<int> data) {
    if (_isClosed) throw StateError('Context is closed');
    using((arena) {
      final ptr = arena<Uint8>(data.length);
      ptr.asTypedList(data.length).setAll(0, data);
      if (EVP_DigestUpdate(_ctx, ptr.cast(), data.length) != 1) {
        throw Exception('Update failed');
      }
    });
  }

  Uint8List finish() {
    if (_isClosed) throw StateError('Context is closed');
    _isClosed = true;
    return using((arena) {
      final out = arena<Uint8>(64);
      final len = arena<UnsignedInt>();
      if (EVP_DigestFinal(_ctx, out, len) != 1) {
        throw Exception('Final failed');
      }
      return Uint8List.fromList(out.asTypedList(len.value));
    });
  }
}
