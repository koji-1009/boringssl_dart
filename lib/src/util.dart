import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';

// CBB struct size (conservative estimate, actual size varies by platform but is < 64 bytes)
const int _cbbSize = 64;

void checkOp(bool condition, {String? message, String? fallback}) {
  if (!condition) {
    // Always extract the error to ensure we clear the error queue.
    final err = _extractError();
    message ??= err ?? fallback ?? 'unknown error';
    throw Exception(message);
  }
}

void checkOpIsOne(int retval, {String? message, String? fallback}) =>
    checkOp(retval == 1, message: message, fallback: fallback);

String? _extractError() {
  // Simple error extraction (can be expanded)
  final err = ERR_peek_error();
  if (err == 0) return null;
  ERR_clear_error();
  return 'BoringSSL Error: $err';
}

/// Helper to allocate a CBB, init it, run [fn], and return bytes.
Uint8List runCBB(void Function(Pointer<CBB> cbb) fn, {int sizeHint = 64}) {
  return using((arena) {
    // Allocate raw bytes for CBB (opaque struct)
    final cbb = arena<Uint8>(_cbbSize).cast<CBB>();
    CBB_zero(cbb);
    if (CBB_init(cbb, sizeHint) != 1) {
      throw Exception('CBB init failed');
    }
    try {
      fn(cbb);
      if (CBB_flush(cbb) != 1) {
        throw Exception('CBB flush failed');
      }
      final len = CBB_len(cbb);
      final data = CBB_data(cbb);
      return Uint8List.fromList(data.asTypedList(len));
    } finally {
      CBB_cleanup(cbb);
    }
  });
}

/// Constant-time comparison of two buffers.
bool constantTimeEq(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  return using((arena) {
    final aPtr = arena<Uint8>(a.length);
    aPtr.asTypedList(a.length).setAll(0, a);
    final bPtr = arena<Uint8>(b.length);
    bPtr.asTypedList(b.length).setAll(0, b);
    return CRYPTO_memcmp(aPtr.cast(), bPtr.cast(), a.length) == 0;
  });
}

/// Returns a list of all errors currently in the OpenSSL error queue,
/// and clears the queue.
List<String> getOpenSslErrors() {
  final errors = <String>[];
  while (true) {
    final err = ERR_get_error();
    if (err == 0) break;
    errors.add(_getErrorMessage(err));
  }
  return errors;
}

String _getErrorMessage(int err) {
  return using((arena) {
    final buf = arena<Uint8>(256);
    ERR_error_string_n(err, buf.cast(), 256);
    return buf.cast<Utf8>().toDartString();
  });
}

/// Returns the [EVP_MD] for the given algorithm name.
Pointer<EVP_MD> getEvpMd(String algorithm) {
  return switch (algorithm) {
    'SHA-1' => EVP_sha1(),
    'SHA-256' => EVP_sha256(),
    'SHA-384' => EVP_sha384(),
    'SHA-512' => EVP_sha512(),
    _ => throw ArgumentError('Unsupported algorithm: $algorithm'),
  };
}

/// Extension to copy [Uint8List] data into arena-allocated native memory.
extension ArenaDataExtension on Arena {
  Pointer<Uint8> dataAsPointer(Uint8List data) {
    final ptr = this<Uint8>(data.length);
    ptr.asTypedList(data.length).setAll(0, data);
    return ptr;
  }
}
