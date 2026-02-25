import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';
import 'key.dart';
import 'util.dart';

class EcKey extends CryptoKey {
  final String curve;

  EcKey(super.pkey, this.curve);

  static EcKey generate(String curve) {
    return using((arena) {
      final nid = _curveToNid(curve);
      final ecKey = EC_KEY_new_by_curve_name(nid);
      checkOp(ecKey != nullptr, message: 'Failed to create EC key');

      try {
        checkOpIsOne(
          EC_KEY_generate_key(ecKey),
          message: 'Failed to generate EC key',
        );

        final pkey = EVP_PKEY_new();
        checkOp(pkey != nullptr, message: 'Failed to create EVP_PKEY');

        // set1 up-refs, so we must free ecKey after (or let finally block do it)
        checkOpIsOne(
          EVP_PKEY_set1_EC_KEY(pkey, ecKey),
          message: 'Failed to assign EC key',
        );
        // ecKey is now shared, but we are done with our ref.
        // The finally block will free ecKey (our ref).

        return EcKey(pkey, curve);
      } finally {
        // Always free our local reference to ecKey.
        // If set1 succeeded, pkey has its own reference.
        EC_KEY_free(ecKey);
      }
    });
  }

  static EcKey importPkcs8(Uint8List keyData, String curve) {
    return using((arena) {
      final dataPtr = arena<Uint8>(keyData.length);
      dataPtr.asTypedList(keyData.length).setAll(0, keyData);

      final cbs = arena<cbs_st>();
      cbs.ref.data = dataPtr;
      cbs.ref.len = keyData.length;

      final pkeyPtr = EVP_parse_private_key(cbs.cast());
      if (pkeyPtr == nullptr) {
        throw Exception('Failed to parse private key');
      }

      final key = EcKey(pkeyPtr, curve);
      _validate(key, curve);
      return key;
    });
  }

  static EcKey importSpki(Uint8List keyData, String curve) {
    return using((arena) {
      final dataPtr = arena<Uint8>(keyData.length);
      dataPtr.asTypedList(keyData.length).setAll(0, keyData);

      final cbs = arena<cbs_st>();
      cbs.ref.data = dataPtr;
      cbs.ref.len = keyData.length;

      final pkeyPtr = EVP_parse_public_key(cbs.cast());
      if (pkeyPtr == nullptr) {
        throw Exception('Failed to parse public key');
      }

      final key = EcKey(pkeyPtr, curve);
      _validate(key, curve);
      return key;
    });
  }

  static void _validate(EcKey key, String curve) {
    using((arena) {
      if (EVP_PKEY_id(key.pkey) != EVP_PKEY_EC) {
        throw ArgumentError('Key is not an EC key');
      }

      // get1 up-refs, caller must free.
      final ecKey = EVP_PKEY_get1_EC_KEY(key.pkey);
      checkOp(ecKey != nullptr, message: 'Failed to get EC_KEY');
      try {
        final group = EC_KEY_get0_group(ecKey);
        final nid = EC_GROUP_get_curve_name(group);
        if (nid != _curveToNid(curve)) {
          throw ArgumentError('Key does not match curve $curve');
        }
      } finally {
        EC_KEY_free(ecKey);
      }
    });
  }

  static int _curveToNid(String curve) {
    return switch (curve) {
      'P-256' => NID_X9_62_prime256v1,
      'P-384' => NID_secp384r1,
      'P-521' => NID_secp521r1,
      _ => throw ArgumentError('Unsupported curve: $curve'),
    };
  }

  static EcKey importCoordinates({
    required String curve,
    required Uint8List x,
    required Uint8List y,
    Uint8List? d,
  }) {
    return using((arena) {
      final nid = _curveToNid(curve);
      final ecKey = EC_KEY_new_by_curve_name(nid);
      checkOp(ecKey != nullptr, message: 'Failed to create EC key');
      try {
        final xBn = BN_bin2bn(arena.dataAsPointer(x), x.length, nullptr);
        checkOp(xBn != nullptr, message: 'Failed to create BIGNUM x');

        final yBn = BN_bin2bn(arena.dataAsPointer(y), y.length, nullptr);
        checkOp(yBn != nullptr, message: 'Failed to create BIGNUM y');

        try {
          checkOpIsOne(
            EC_KEY_set_public_key_affine_coordinates(ecKey, xBn, yBn),
            message: 'Failed to set affine coordinates',
          );
        } finally {
          BN_free(xBn);
          BN_free(yBn);
        }

        if (d != null) {
          final dBn = BN_bin2bn(arena.dataAsPointer(d), d.length, nullptr);
          checkOp(dBn != nullptr, message: 'Failed to create BIGNUM d');
          try {
            checkOpIsOne(
              EC_KEY_set_private_key(ecKey, dBn),
              message: 'Failed to set private key',
            );
          } finally {
            BN_free(dBn);
          }
        }

        checkOpIsOne(
          EC_KEY_check_key(ecKey),
          message: 'Invalid EC key components',
        );

        final pkey = EVP_PKEY_new();
        checkOp(pkey != nullptr);
        if (EVP_PKEY_set1_EC_KEY(pkey, ecKey) != 1) {
          EVP_PKEY_free(pkey);
          throw Exception('Failed to set1 EC key');
        }
        return EcKey(pkey, curve);
      } finally {
        EC_KEY_free(ecKey);
      }
    });
  }

  Map<String, Uint8List> exportCoordinates() {
    return using((arena) {
      final ecKey = EVP_PKEY_get1_EC_KEY(pkey);
      checkOp(ecKey != nullptr, message: 'Not an EC key');
      try {
        final group = EC_KEY_get0_group(ecKey);
        final degree = EC_GROUP_get_degree(group);
        final paramLen = (degree + 7) ~/ 8;

        final xBn = BN_new();
        final yBn = BN_new();
        checkOp(xBn != nullptr && yBn != nullptr);

        try {
          final pub = EC_KEY_get0_public_key(ecKey);
          checkOp(pub != nullptr, message: 'No public key');

          checkOpIsOne(
            EC_POINT_get_affine_coordinates_GFp(group, pub, xBn, yBn, nullptr),
            message: 'Failed to get affine coordinates',
          );

          final xBytes = _bnToBytes(xBn, paramLen, arena);
          final yBytes = _bnToBytes(yBn, paramLen, arena);

          Uint8List? dBytes;
          final priv = EC_KEY_get0_private_key(ecKey);
          if (priv != nullptr) {
            dBytes = _bnToBytes(priv, paramLen, arena);
          }

          return {'x': xBytes, 'y': yBytes, if (dBytes != null) 'd': dBytes};
        } finally {
          BN_free(xBn);
          BN_free(yBn);
        }
      } finally {
        EC_KEY_free(ecKey);
      }
    });
  }

  Uint8List _bnToBytes(Pointer<BIGNUM> bn, int length, Arena arena) {
    final out = arena<Uint8>(length);
    checkOpIsOne(
      BN_bn2bin_padded(out, length, bn),
      message: 'BN conversion failed',
    );
    return Uint8List.fromList(out.asTypedList(length));
  }
}
