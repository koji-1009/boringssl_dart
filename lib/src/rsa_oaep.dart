import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';

/// RSA-OAEP encryption/decryption.
class RsaOaep {
  const RsaOaep._();

  /// Encrypts [data] using RSA-OAEP.
  ///
  /// [publicKey] must be a DER-encoded SubjectPublicKeyInfo (SPKI).
  /// [hash] is the hash function to use for OAEP (default SHA-256).
  /// [label] is optional label data.
  static Uint8List encrypt(
    Uint8List publicKey,
    Uint8List data, {
    String hash = 'SHA-256',
    Uint8List? label,
  }) {
    return _transform(publicKey, data, true, hash, label);
  }

  /// Decrypts [data] using RSA-OAEP.
  ///
  /// [privateKey] must be a DER-encoded RSAPrivateKey (PKCS#1).
  /// [hash] is the hash function to use for OAEP (default SHA-256).
  /// [label] must match the label used during encryption.
  static Uint8List decrypt(
    Uint8List privateKey,
    Uint8List data, {
    String hash = 'SHA-256',
    Uint8List? label,
  }) {
    return _transform(privateKey, data, false, hash, label);
  }

  static Uint8List _transform(
    Uint8List keyBytes,
    Uint8List data,
    bool encrypt,
    String hashAlgorithm,
    Uint8List? label,
  ) {
    return using((arena) {
      final keyPtr = arena<Uint8>(keyBytes.length);
      keyPtr.asTypedList(keyBytes.length).setAll(0, keyBytes);
      final keyPtrPtr = arena<Pointer<Uint8>>();
      keyPtrPtr.value = keyPtr;

      Pointer<EVP_PKEY> pkey;

      if (encrypt) {
        // Parse Public Key (SPKI)
        // d2i_RSA_PUBKEY reads SPKI and returns RSA*.
        final rsa = d2i_RSA_PUBKEY(nullptr, keyPtrPtr, keyBytes.length);
        if (rsa == nullptr) {
          throw Exception('Failed to parse public key');
        }
        pkey = EVP_PKEY_new();
        if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
          RSA_free(rsa);
          EVP_PKEY_free(pkey);
          throw Exception('Failed to assign RSA key to PKEY');
        }
      } else {
        // Parse Private Key (PKCS#1)
        final rsa = d2i_RSAPrivateKey(nullptr, keyPtrPtr, keyBytes.length);
        if (rsa == nullptr) {
          throw Exception('Failed to parse private key');
        }
        pkey = EVP_PKEY_new();
        if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
          RSA_free(rsa);
          EVP_PKEY_free(pkey);
          throw Exception('Failed to assign RSA key to PKEY');
        }
      }

      final ctx = EVP_PKEY_CTX_new(pkey, nullptr);
      if (ctx == nullptr) {
        EVP_PKEY_free(pkey);
        throw Exception('Failed to create PKEY context');
      }

      try {
        if (encrypt) {
          if (EVP_PKEY_encrypt_init(ctx) != 1) {
            throw Exception('Encrypt init failed');
          }
        } else {
          if (EVP_PKEY_decrypt_init(ctx) != 1) {
            throw Exception('Decrypt init failed');
          }
        }

        // Set Padding to OAEP
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, 4 /* RSA_PKCS1_OAEP_PADDING */) !=
            1) {
          throw Exception('Failed to set padding');
        }

        // Set OAEP Hash
        Pointer<EVP_MD> md = switch (hashAlgorithm) {
          'SHA-1' => EVP_sha1(),
          'SHA-256' => EVP_sha256(),
          'SHA-384' => EVP_sha384(),
          'SHA-512' => EVP_sha512(),
          _ => throw ArgumentError('Unsupported algorithm: $hashAlgorithm'),
        };

        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) != 1) {
          throw Exception('Failed to set OAEP hash');
        }

        // Set Label if provided
        if (label != null && label.isNotEmpty) {
          // Use OPENSSL_malloc to transfer ownership to BoringSSL.
          final labelPtr = OPENSSL_malloc(label.length).cast<Uint8>();
          if (labelPtr == nullptr) {
            throw Exception('Failed to allocate label memory');
          }

          labelPtr.asTypedList(label.length).setAll(0, label);

          if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, labelPtr, label.length) !=
              1) {
            OPENSSL_free(
              labelPtr.cast<Void>(),
            ); // Free if ownership not transferred
            throw Exception('Failed to set OAEP label');
          }
          // On success, labelPtr ownership is transferred to ctx.
        }

        final outLenPtr = arena<Size>();
        final inPtr = arena<Uint8>(data.length);
        inPtr.asTypedList(data.length).setAll(0, data);

        // Determine buffer length
        int result;
        if (encrypt) {
          if (EVP_PKEY_encrypt(ctx, nullptr, outLenPtr, inPtr, data.length) !=
              1) {
            throw Exception('Failed to get encrypt output length');
          }
        } else {
          if (EVP_PKEY_decrypt(ctx, nullptr, outLenPtr, inPtr, data.length) !=
              1) {
            throw Exception('Failed to get decrypt output length');
          }
        }

        final outPtr = arena<Uint8>(outLenPtr.value);

        if (encrypt) {
          result = EVP_PKEY_encrypt(ctx, outPtr, outLenPtr, inPtr, data.length);
        } else {
          result = EVP_PKEY_decrypt(ctx, outPtr, outLenPtr, inPtr, data.length);
        }

        if (result != 1) {
          throw Exception(encrypt ? 'Encryption failed' : 'Decryption failed');
        }

        return Uint8List.fromList(outPtr.asTypedList(outLenPtr.value));
      } finally {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
      }
    });
  }
}
