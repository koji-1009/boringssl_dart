import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';
import 'ec.dart';
import 'util.dart';

class Ecdh {
  const Ecdh._();

  static Uint8List computeBits(EcKey privateKey, EcKey publicKey, int length) {
    if (length <= 0) {
      throw ArgumentError('Length must be positive');
    }

    return using((arena) {
      final privEc = EVP_PKEY_get1_EC_KEY(privateKey.pkey);
      checkOp(privEc != nullptr, message: 'Private key is not an EC key');
      try {
        final pubEc = EVP_PKEY_get1_EC_KEY(publicKey.pkey);
        checkOp(pubEc != nullptr, message: 'Public key is not an EC key');
        try {
          final privGroup = EC_KEY_get0_group(privEc);
          final pubGroup = EC_KEY_get0_group(pubEc);

          if (EC_GROUP_get_curve_name(privGroup) !=
              EC_GROUP_get_curve_name(pubGroup)) {
            throw ArgumentError('Public and private key curves do not match');
          }

          final fieldSize = EC_GROUP_get_degree(privGroup);
          final maxLength =
              8 *
              ((fieldSize + 7) ~/ 8); // match webcrypto logic or simplified?
          // WebCrypto: 8 * (fieldSize / 8).ceil()
          // (fieldSize + 7) ~/ 8 is equivalent to ceil(fieldSize/8).

          if (length > maxLength) {
            throw ArgumentError('Length is too large');
          }

          final lengthInBytes = (length + 7) ~/ 8;
          final out = arena<Uint8>(lengthInBytes);

          final outLen = ECDH_compute_key(
            out.cast(),
            lengthInBytes,
            EC_KEY_get0_public_key(pubEc),
            privEc,
            nullptr,
          );

          checkOp(outLen != -1, fallback: 'ECDH failed');
          checkOp(outLen == lengthInBytes, message: 'Internal ECDH error');

          final derived = Uint8List.fromList(out.asTypedList(lengthInBytes));

          // Mask trailing bits if length is not byte-aligned.
          // Zero out the least significant bits of the last byte.
          final zeroBits = lengthInBytes * 8 - length;
          if (zeroBits > 0) {
            derived[derived.length - 1] &= ((0xff << zeroBits) & 0xff);
          }
          return derived;
        } finally {
          EC_KEY_free(pubEc);
        }
      } finally {
        EC_KEY_free(privEc);
      }
    });
  }
}
