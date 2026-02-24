import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';
import 'util.dart';

int _errGetLib(int packedError) => (packedError >> 24) & 0xff;

/// HKDF key derivation.
class Hkdf {
  const Hkdf._();

  /// Derives a key using HKDF.
  ///
  /// [key] is the input keying material.
  /// [salt] is the salt value (optional, defaults to empty).
  /// [info] is the application specific info (optional, defaults to empty).
  /// [length] is the length of the derived key in **bytes**.
  /// [hashAlgorithm] is the hash algorithm to use (e.g. 'SHA-256').
  static Uint8List derive({
    required Uint8List key,
    Uint8List? salt,
    Uint8List? info,
    required int length,
    required String hashAlgorithm,
  }) {
    return using((arena) {
      final md = getEvpMd(hashAlgorithm);

      final outPtr = arena<Uint8>(length);
      final keyPtr = arena<Uint8>(key.length);
      keyPtr.asTypedList(key.length).setAll(0, key);

      Pointer<Uint8> saltPtr = nullptr;
      if (salt != null && salt.isNotEmpty) {
        saltPtr = arena<Uint8>(salt.length);
        saltPtr.asTypedList(salt.length).setAll(0, salt);
      }

      Pointer<Uint8> infoPtr = nullptr;
      if (info != null && info.isNotEmpty) {
        infoPtr = arena<Uint8>(info.length);
        infoPtr.asTypedList(info.length).setAll(0, info);
      }

      final result = HKDF(
        outPtr,
        length,
        md,
        keyPtr,
        key.length,
        saltPtr,
        salt?.length ?? 0,
        infoPtr,
        info?.length ?? 0,
      );

      if (result != 1) {
        final error = ERR_peek_error();
        if (_errGetLib(error) == ERR_LIB_HKDF &&
            (error & 0xfff) == HKDF_R_OUTPUT_TOO_LARGE) {
          ERR_clear_error();
          throw ArgumentError('HKDF output length too large');
        }
        // Use checkOpIsOne to handle other errors and ensure cleanup
        checkOpIsOne(result, message: 'HKDF derivation failed');
      }

      return Uint8List.fromList(outPtr.asTypedList(length));
    });
  }

}
