import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';
import 'ec.dart';
import 'util.dart';

class Ecdsa {
  const Ecdsa._();

  static Uint8List sign(EcKey key, Uint8List data, String hash) {
    return using((arena) {
      final ctx = EVP_MD_CTX_new();
      checkOp(ctx != nullptr, message: 'Failed to create MD context');
      try {
        final md = getEvpMd(hash);
        final pkey = key.pkey;

        checkOpIsOne(
          EVP_DigestSignInit(ctx, nullptr, md, nullptr, pkey),
          message: 'Sign init failed',
        );

        final dataPtr = arena.dataAsPointer(data);
        checkOpIsOne(
          EVP_DigestSignUpdate(ctx, dataPtr.cast(), data.length),
          message: 'Sign update failed',
        );

        // Determine size
        final lenPtr = arena<Size>();

        checkOpIsOne(
          EVP_DigestSignFinal(ctx, nullptr, lenPtr),
          message: 'Sign final (size) failed',
        );

        final sig = arena<Uint8>(lenPtr.value);
        checkOpIsOne(
          EVP_DigestSignFinal(ctx, sig, lenPtr),
          message: 'Sign final failed',
        );

        final derSig = Uint8List.fromList(sig.asTypedList(lenPtr.value));
        return _derToRaw(derSig, key, arena);
      } finally {
        EVP_MD_CTX_free(ctx);
      }
    });
  }

  static bool verify(
    EcKey key,
    Uint8List signature,
    Uint8List data,
    String hash,
  ) {
    return using((arena) {
      // Convert Raw R+S to DER
      final derSig = _rawToDer(signature, key, arena);
      if (derSig == null) return false;

      final ctx = EVP_MD_CTX_new();
      checkOp(ctx != nullptr, message: 'Failed to create MD context');
      try {
        final md = getEvpMd(hash);
        final pkey = key.pkey;

        checkOpIsOne(
          EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pkey),
          message: 'Verify init failed',
        );

        final dataPtr = arena.dataAsPointer(data);
        checkOpIsOne(
          EVP_DigestVerifyUpdate(ctx, dataPtr.cast(), data.length),
          message: 'Verify update failed',
        );

        final sigPtr = arena.dataAsPointer(derSig);
        final result = EVP_DigestVerifyFinal(ctx, sigPtr, derSig.length);
        if (result == 1) return true;

        // Clear errors if 0
        ERR_clear_error();
        return false;
      } finally {
        EVP_MD_CTX_free(ctx);
      }
    });
  }


  static Uint8List _derToRaw(Uint8List derSig, EcKey key, Arena arena) {
    // Parse DER to ECDSA_SIG
    final cbs = arena<cbs_st>();
    final derPtr = arena.dataAsPointer(derSig);
    cbs.ref.data = derPtr;
    cbs.ref.len = derSig.length;

    final sig = ECDSA_SIG_parse(cbs.cast());
    checkOp(sig != nullptr, message: 'Invalid DER signature');

    try {
      final ecKey = EVP_PKEY_get1_EC_KEY(key.pkey);
      checkOp(ecKey != nullptr, message: 'Not an EC key');
      try {
        final group = EC_KEY_get0_group(ecKey);
        final degree = EC_GROUP_get_degree(group);
        final n = (degree + 7) ~/ 8;

        final r = arena<Pointer<BIGNUM>>();
        final s = arena<Pointer<BIGNUM>>();
        ECDSA_SIG_get0(sig, r, s);

        final out = arena<Uint8>(2 * n);
        checkOpIsOne(
          BN_bn2bin_padded(out, n, r.value),
          message: 'Bn2Bin R failed',
        );
        checkOpIsOne(
          BN_bn2bin_padded(out + n, n, s.value),
          message: 'Bn2Bin S failed',
        );

        return Uint8List.fromList(out.asTypedList(2 * n));
      } finally {
        EC_KEY_free(ecKey);
      }
    } finally {
      ECDSA_SIG_free(sig);
    }
  }

  static Uint8List? _rawToDer(Uint8List rawSig, EcKey key, Arena arena) {
    // Only need curve to check length if needed, but rawSig is fixed size?
    // We assume rawSig is R|S.
    if (rawSig.length % 2 != 0) return null;
    final n = rawSig.length ~/ 2;

    final rBytes = _minimalSignedInt(rawSig.sublist(0, n));
    final sBytes = _minimalSignedInt(rawSig.sublist(n));

    // Construct SEQUENCE
    // Payload = INTEGER(r) | INTEGER(s)
    final payload = BytesBuilder();
    payload.addByte(0x02); // INTEGER tag
    _encodeLength(payload, rBytes.length);
    payload.add(rBytes);

    payload.addByte(0x02); // INTEGER tag
    _encodeLength(payload, sBytes.length);
    payload.add(sBytes);

    final seq = BytesBuilder();
    seq.addByte(0x30); // SEQUENCE tag
    _encodeLength(seq, payload.length);
    seq.add(payload.toBytes());

    return seq.toBytes();
  }

  static Uint8List _minimalSignedInt(Uint8List bytes) {
    // Strip leading zeros
    var start = 0;
    while (start < bytes.length && bytes[start] == 0) {
      start++;
    }
    if (start == bytes.length) return Uint8List.fromList([0]);

    final stripped = bytes.sublist(start);
    // If MSB is set, prepend 0x00
    if ((stripped[0] & 0x80) != 0) {
      final out = Uint8List(stripped.length + 1);
      out[0] = 0x00;
      out.setAll(1, stripped);
      return out;
    }
    return stripped;
  }

  static void _encodeLength(BytesBuilder builder, int length) {
    if (length < 128) {
      builder.addByte(length);
    } else {
      // Find minimal bytes needed
      final bytes = <int>[];
      var l = length;
      while (l > 0) {
        bytes.add(l & 0xff);
        l >>= 8;
      }
      builder.addByte(0x80 | bytes.length);
      builder.add(bytes.reversed.toList());
    }
  }
}

