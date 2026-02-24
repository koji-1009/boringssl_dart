import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';
import 'rsa.dart';
import 'util.dart';

class RsaSsaPkcs1 {
  const RsaSsaPkcs1._();

  static Uint8List sign(RsaKey key, Uint8List data, String hash) {
    return using((arena) {
      final md = getEvpMd(hash);
      final pkey = key.pkey;
      final ctx = EVP_MD_CTX_new();
      checkOp(ctx != nullptr, message: 'Failed to create MD context');
      try {
        final pctx = arena<Pointer<EVP_PKEY_CTX>>();
        checkOpIsOne(
          EVP_DigestSignInit(ctx, pctx, md, nullptr, pkey),
          message: 'Sign init failed',
        );

        // Config Padding
        checkOpIsOne(
          EVP_PKEY_CTX_set_rsa_padding(pctx.value, RSA_PKCS1_PADDING),
        );

        final dataPtr = arena.dataAsPointer(data);
        checkOpIsOne(EVP_DigestSignUpdate(ctx, dataPtr.cast(), data.length));

        final lenPtr = arena<Size>();
        checkOpIsOne(EVP_DigestSignFinal(ctx, nullptr, lenPtr));

        final sig = arena<Uint8>(lenPtr.value);
        checkOpIsOne(EVP_DigestSignFinal(ctx, sig, lenPtr));

        return Uint8List.fromList(sig.asTypedList(lenPtr.value));
      } finally {
        EVP_MD_CTX_free(ctx);
      }
    });
  }

  static bool verify(
    RsaKey key,
    Uint8List signature,
    Uint8List data,
    String hash,
  ) {
    return using((arena) {
      final md = getEvpMd(hash);
      final pkey = key.pkey;
      final ctx = EVP_MD_CTX_new();
      checkOp(ctx != nullptr, message: 'Failed to create MD context');
      try {
        final pctx = arena<Pointer<EVP_PKEY_CTX>>();
        checkOpIsOne(
          EVP_DigestVerifyInit(ctx, pctx, md, nullptr, pkey),
          message: 'Verify init failed',
        );

        checkOpIsOne(
          EVP_PKEY_CTX_set_rsa_padding(pctx.value, RSA_PKCS1_PADDING),
        );

        final dataPtr = arena.dataAsPointer(data);
        checkOpIsOne(EVP_DigestVerifyUpdate(ctx, dataPtr.cast(), data.length));

        final sigPtr = arena.dataAsPointer(signature);
        final result = EVP_DigestVerifyFinal(ctx, sigPtr, signature.length);
        if (result == 1) return true;

        ERR_clear_error();
        return false;
      } finally {
        EVP_MD_CTX_free(ctx);
      }
    });
  }

}

