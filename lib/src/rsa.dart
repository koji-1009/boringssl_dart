import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';
import 'key.dart';
import 'util.dart';

class RsaKey extends CryptoKey {
  RsaKey(super.pkey);

  static RsaKey generate(int modulusBits, BigInt publicExponent) {
    return using((arena) {
      final rsa = RSA_new();
      checkOp(rsa != nullptr, message: 'Failed to create RSA');
      try {
        final e = BN_new();
        checkOp(e != nullptr);
        // BN_set_word takes int. If publicExponent > int.max?
        // WebCrypto checks for 3 or 65537 usually.
        checkOpIsOne(
          BN_set_word(e, publicExponent.toInt()),
          message: 'Failed to set exponent',
        );

        // RSA_generate_key_ex takes ownership of e? No. e is const BIGNUM* arguments usually?
        // Docs: "The BIGNUM e must be an odd number... The exponent e is not modified."
        // So we must free e.
        try {
          checkOpIsOne(
            RSA_generate_key_ex(rsa, modulusBits, e, nullptr),
            message: 'RSA generation failed',
          );
        } finally {
          BN_free(e);
        }

        final pkey = EVP_PKEY_new();
        checkOp(pkey != nullptr);
        if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
          EVP_PKEY_free(pkey);
          throw Exception('Failed to set RSA key');
        }
        return RsaKey(pkey);
      } finally {
        RSA_free(rsa);
      }
    });
  }

  static RsaKey importPkcs8(Uint8List keyData) {
    return using((arena) {
      final dataPtr = arena.dataAsPointer(keyData);
      final cbs = arena<cbs_st>();
      cbs.ref.data = dataPtr;
      cbs.ref.len = keyData.length;

      final pkeyPtr = EVP_parse_private_key(cbs.cast());
      if (pkeyPtr == nullptr) {
        throw Exception('Failed to parse private key');
      }

      final key = RsaKey(pkeyPtr);
      // Validate correct ID
      if (EVP_PKEY_id(key.pkey) != EVP_PKEY_RSA) {
        throw ArgumentError('Not an RSA key');
      }
      return key;
    });
  }

  /// Import RSA private key from PKCS#1 (raw RSA) format.
  static RsaKey importPkcs1(Uint8List keyData) {
    return using((arena) {
      final dataPtr = arena.dataAsPointer(keyData);
      final dataPtrPtr = arena<Pointer<Uint8>>();
      dataPtrPtr.value = dataPtr;

      final rsa = d2i_RSAPrivateKey(nullptr, dataPtrPtr, keyData.length);
      if (rsa == nullptr) {
        throw Exception('Failed to parse PKCS#1 private key');
      }

      final pkey = EVP_PKEY_new();
      if (pkey == nullptr) {
        RSA_free(rsa);
        throw Exception('Failed to create EVP_PKEY');
      }

      if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        throw Exception('Failed to assign RSA key to PKEY');
      }

      RSA_free(rsa); // EVP_PKEY_set1_RSA increments ref count
      return RsaKey(pkey);
    });
  }

  static RsaKey importSpki(Uint8List keyData) {
    return using((arena) {
      final dataPtr = arena.dataAsPointer(keyData);
      final cbs = arena<cbs_st>();
      cbs.ref.data = dataPtr;
      cbs.ref.len = keyData.length;

      final pkeyPtr = EVP_parse_public_key(cbs.cast());
      if (pkeyPtr == nullptr) {
        throw Exception('Failed to parse public key');
      }

      final key = RsaKey(pkeyPtr);
      if (EVP_PKEY_id(key.pkey) != EVP_PKEY_RSA) {
        throw ArgumentError('Not an RSA key');
      }
      return key;
    });
  }

  static RsaKey importComponents({
    required Uint8List n,
    required Uint8List e,
    Uint8List? d,
    Uint8List? p,
    Uint8List? q,
    Uint8List? dp,
    Uint8List? dq,
    Uint8List? qi,
  }) {
    // Manually manage BIGNUMs because set0 functions take ownership.
    // If set0 succeeds, we don't free. If it fails, we free.
    // Helper to create BN from bytes.
    Pointer<BIGNUM> bn(Uint8List bytes) {
      // BN_bin2bn allocates new BN.
      final ptr = using((arena) {
        return BN_bin2bn(arena.dataAsPointer(bytes), bytes.length, nullptr);
      });
      if (ptr == nullptr) throw Exception('BN allocation failed');
      return ptr;
    }

    final rsa = RSA_new();
    checkOp(rsa != nullptr);
    try {
      final nBn = bn(n);
      final eBn = bn(e);
      final dBn = d != null ? bn(d) : nullptr;

      if (RSA_set0_key(rsa, nBn, eBn, dBn) != 1) {
        BN_free(nBn);
        BN_free(eBn);
        if (dBn != nullptr) BN_free(dBn);
        throw Exception('Failed to set RSA factors');
      }
      // nBn, eBn, dBn are now owned by rsa.

      if (p != null && q != null) {
        final pBn = bn(p);
        final qBn = bn(q);
        if (RSA_set0_factors(rsa, pBn, qBn) != 1) {
          BN_free(pBn);
          BN_free(qBn);
          throw Exception('Failed to set factors');
        }
      }

      if (dp != null && dq != null && qi != null) {
        final dpBn = bn(dp);
        final dqBn = bn(dq);
        final qiBn = bn(qi);
        if (RSA_set0_crt_params(rsa, dpBn, dqBn, qiBn) != 1) {
          BN_free(dpBn);
          BN_free(dqBn);
          BN_free(qiBn);
          throw Exception('Failed to set CRT params');
        }
      }

      checkOpIsOne(RSA_check_key(rsa), message: 'Invalid RSA key');

      final pkey = EVP_PKEY_new();
      checkOp(pkey != nullptr);
      if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        throw Exception('Failed to set PKEY');
      }
      return RsaKey(pkey);
    } finally {
      RSA_free(rsa);
    }
  }

  Map<String, Uint8List> exportComponents({bool includePrivate = false}) {
    return using((arena) {
      final rsa = EVP_PKEY_get1_RSA(pkey);
      checkOp(rsa != nullptr, message: 'Not an RSA key');
      try {
        final n = arena<Pointer<BIGNUM>>();
        final e = arena<Pointer<BIGNUM>>();
        final d = arena<Pointer<BIGNUM>>();

        RSA_get0_key(rsa, n, e, d);

        final out = <String, Uint8List>{};
        if (n.value != nullptr) out['n'] = _bnBytes(n.value, arena);
        if (e.value != nullptr) out['e'] = _bnBytes(e.value, arena);

        if (includePrivate && d.value != nullptr) {
          out['d'] = _bnBytes(d.value, arena);

          final p = arena<Pointer<BIGNUM>>();
          final q = arena<Pointer<BIGNUM>>();
          RSA_get0_factors(rsa, p, q);

          final dp = arena<Pointer<BIGNUM>>();
          final dq = arena<Pointer<BIGNUM>>();
          final qi = arena<Pointer<BIGNUM>>();
          RSA_get0_crt_params(rsa, dp, dq, qi);

          if (p.value != nullptr) out['p'] = _bnBytes(p.value, arena);
          if (q.value != nullptr) out['q'] = _bnBytes(q.value, arena);
          if (dp.value != nullptr) out['dp'] = _bnBytes(dp.value, arena);
          if (dq.value != nullptr) out['dq'] = _bnBytes(dq.value, arena);
          if (qi.value != nullptr) out['qi'] = _bnBytes(qi.value, arena);
        }

        return out;
      } finally {
        RSA_free(rsa);
      }
    });
  }

  Uint8List _bnBytes(Pointer<BIGNUM> bn, Arena arena) {
    final len = BN_num_bytes(bn);
    final out = arena<Uint8>(len);
    checkOpIsOne(
      BN_bn2bin_padded(out, len, bn),
      message: 'BN conversion failed',
    );
    return Uint8List.fromList(out.asTypedList(len));
  }
}

extension on Arena {
  Pointer<Uint8> dataAsPointer(Uint8List data) {
    final ptr = this<Uint8>(data.length);
    ptr.asTypedList(data.length).setAll(0, data);
    return ptr;
  }
}
