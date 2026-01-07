import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';
import 'rsa.dart';
import 'util.dart';

/// RSA-OAEP encryption/decryption.
class RsaOaep {
  const RsaOaep._();

  /// Encrypts [data] using RSA-OAEP.
  ///
  /// [publicKey] must be an RsaKey (with public key components).
  /// [hash] is the hash function to use for OAEP (default SHA-256).
  /// [label] is optional label data.
  static Uint8List encrypt(
    RsaKey publicKey,
    Uint8List data, {
    String hash = 'SHA-256',
    Uint8List? label,
  }) {
    return _transform(publicKey, data, true, hash, label);
  }

  /// Decrypts [data] using RSA-OAEP.
  ///
  /// [privateKey] must be an RsaKey (with private key components).
  /// [hash] is the hash function to use for OAEP (default SHA-256).
  /// [label] must match the label used during encryption.
  static Uint8List decrypt(
    RsaKey privateKey,
    Uint8List data, {
    String hash = 'SHA-256',
    Uint8List? label,
  }) {
    return _transform(privateKey, data, false, hash, label);
  }

  static Uint8List _transform(
    RsaKey key,
    Uint8List data,
    bool encrypt,
    String hashAlgorithm,
    Uint8List? label,
  ) {
    return using((arena) {
      // Use existing EVP_PKEY from RsaKey
      final pkey = key.pkey;
      // We do NOT free pkey here, as it belongs to RsaKey.

      final ctx = EVP_PKEY_CTX_new(pkey, nullptr);
      checkOp(ctx != nullptr, message: 'Failed to create PKEY context');

      try {
        if (encrypt) {
          checkOpIsOne(
            EVP_PKEY_encrypt_init(ctx),
            message: 'Encrypt init failed',
          );
        } else {
          checkOpIsOne(
            EVP_PKEY_decrypt_init(ctx),
            message: 'Decrypt init failed',
          );
        }

        // Set Padding to OAEP
        checkOpIsOne(
          EVP_PKEY_CTX_set_rsa_padding(ctx, 4 /* RSA_PKCS1_OAEP_PADDING */),
          message: 'Failed to set padding',
        );

        // Set OAEP Hash
        Pointer<EVP_MD> md = switch (hashAlgorithm) {
          'SHA-1' => EVP_sha1(),
          'SHA-256' => EVP_sha256(),
          'SHA-384' => EVP_sha384(),
          'SHA-512' => EVP_sha512(),
          _ => throw ArgumentError('Unsupported algorithm: $hashAlgorithm'),
        };

        checkOpIsOne(
          EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md),
          message: 'Failed to set OAEP hash',
        );

        // Set Label if provided
        if (label != null && label.isNotEmpty) {
          // Use OPENSSL_malloc to transfer ownership to BoringSSL.
          final labelPtr = OPENSSL_malloc(label.length).cast<Uint8>();
          checkOp(
            labelPtr != nullptr,
            message: 'Failed to allocate label memory',
          );

          labelPtr.asTypedList(label.length).setAll(0, label);

          if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, labelPtr, label.length) !=
              1) {
            OPENSSL_free(
              labelPtr.cast<Void>(),
            ); // Free if ownership not transferred
            checkOp(false, message: 'Failed to set OAEP label');
          }
          // On success, labelPtr ownership is transferred to ctx.
        }

        final outLenPtr = arena<Size>();
        final inPtr = arena<Uint8>(data.length);
        inPtr.asTypedList(data.length).setAll(0, data);

        // Determine buffer length
        int result;
        if (encrypt) {
          checkOpIsOne(
            EVP_PKEY_encrypt(ctx, nullptr, outLenPtr, inPtr, data.length),
            message: 'Failed to get encrypt output length',
          );
        } else {
          checkOpIsOne(
            EVP_PKEY_decrypt(ctx, nullptr, outLenPtr, inPtr, data.length),
            message: 'Failed to get decrypt output length',
          );
        }

        final outPtr = arena<Uint8>(outLenPtr.value);

        if (encrypt) {
          result = EVP_PKEY_encrypt(ctx, outPtr, outLenPtr, inPtr, data.length);
        } else {
          result = EVP_PKEY_decrypt(ctx, outPtr, outLenPtr, inPtr, data.length);
        }

        checkOpIsOne(
          result,
          message: encrypt ? 'Encryption failed' : 'Decryption failed',
        );

        return Uint8List.fromList(outPtr.asTypedList(outLenPtr.value));
      } finally {
        EVP_PKEY_CTX_free(ctx);
        // Do NOT free pkey.
      }
    });
  }
}
