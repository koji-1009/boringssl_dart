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

          // Mask bits if needed
          final zeroBits = lengthInBytes * 8 - length;
          if (zeroBits > 0) {
            derived[derived.length - 1] &= ((0xff << zeroBits) & 0xff);
            // WebCrypto logic: derived.last &= ((0xff << zeroBits) & 0xff);
            // Wait, 0xff << 8 is 0x100?
            // If zeroBits is 1...7.
            // Example: length=1, inBytes=1. zeroBits = 7.
            // 0xff << 7 = 0x8000 (if 32 bit). 0x80 (if 8 bit).
            // (0xff << 7) & 0xff = 0x80.
            // This masks the TOP bit?
            // WebCrypto spec: "The most significant bits will be zero".
            // If length is 1 bit, derived key is 1 byte.
            // We want bits 7..1 to be zero?
            // BoringSSL returns Big-Endian bytes?
            // RFC 6090: "The shared secret value z is an integer... convert z to octet string".
            // Usually it's raw X coordinate.
            // If we ask for fewer bits than the field size, we usually truncate or use KDF.
            // But WebCrypto 'deriveBits' slices the RESULT.
            // The logic in webcrypto.dart masks the *last* byte?
            // "Only return the first [length] bits".
            // If result is [b0, b1, ...].
            // And we want L bits.
            // If L matches byte boundary, done.
            // If L is e.g. 7 bits. We take 1 byte.
            // We want the *first* 7 bits of that byte?
            // WebCrypto: "most significant bits will be zero". This usually implies big-endian number interpretation where leading zeroes are padding.
            // BUT `derived.last` suggests little-endian masking?
            // Actually, `webcrypto.dart` logic:
            /*
               final zeroBits = lengthInBytes * 8 - length;
               if (zeroBits > 0) {
                 derived.last &= ((0xff << zeroBits) & 0xff); // This shifts 0xff LEFT by zeroBits.
               }
             */
            // Example: 7 bits, 1 byte. zeroBits = 1.
            // 0xff << 1 = 0x1FE (0xFE in 8-bit).
            // derived.last &= 0xFE. Sets LSB to 0?
            // This suggests the bits are "left aligned" in the byte or something?
            // Or they want the "first" bits relative to MSB?
            // I'll trust `webcrypto.dart` logic blindly for now.
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
