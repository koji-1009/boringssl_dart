// AES-CTR known-answer tests from NIST SP 800-38A, Appendix F.5.
//
// Wycheproof ships no AES-CTR suite, so these are the canonical NIST vectors.
// All six sub-cases (F.5.1 - F.5.6) share the same plaintext (the standard
// four-block message) and the same initial counter block
// f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff; only the key and expected ciphertext change
// per key size. Because AES-CTR is symmetric, each key size is checked in both
// directions: encrypt(plaintext) == ciphertext (the Encrypt sub-case) and
// decrypt(ciphertext) == plaintext (the Decrypt sub-case).
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

/// Decodes a whitespace-free hex string into bytes.
Uint8List _hex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

// Initial counter block, shared by every F.5 sub-case.
final Uint8List _iv = _hex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');

// The standard four-block plaintext message, shared by every F.5 sub-case.
final Uint8List _plaintext = _hex(
  '6bc1bee22e409f96e93d7e117393172a'
  'ae2d8a571e03ac9c9eb76fac45af8e51'
  '30c81c46a35ce411e5fbc1191a0a52ef'
  'f69f2445df4f9b17ad2b417be66c3710',
);

void main() {
  group('NIST SP 800-38A AES-CTR known-answer tests', () {
    // F.5.1 (CTR-AES128.Encrypt) and F.5.2 (CTR-AES128.Decrypt).
    _ctrCase(
      name: 'AES-128 (F.5.1 / F.5.2)',
      key: '2b7e151628aed2a6abf7158809cf4f3c',
      ciphertext: '874d6191b620e3261bef6864990db6ce'
          '9806f66b7970fdff8617187bb9fffdff'
          '5ae4df3edbd5d35e5b4f09020db03eab'
          '1e031dda2fbe03d1792170a0f3009cee',
    );

    // F.5.3 (CTR-AES192.Encrypt) and F.5.4 (CTR-AES192.Decrypt).
    _ctrCase(
      name: 'AES-192 (F.5.3 / F.5.4)',
      key: '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
      ciphertext: '1abc932417521ca24f2b0459fe7e6e0b'
          '090339ec0aa6faefd5ccc2c6f4ce8e94'
          '1e36b26bd1ebc670d1bd1d665620abf7'
          '4f78a7f6d29809585a97daec58c6b050',
    );

    // F.5.5 (CTR-AES256.Encrypt) and F.5.6 (CTR-AES256.Decrypt).
    _ctrCase(
      name: 'AES-256 (F.5.5 / F.5.6)',
      key: '603deb1015ca71be2b73aef0857d7781'
          '1f352c073b6108d72d9810a30914dff4',
      ciphertext: '601ec313775789a5b7a7f504bbf3d228'
          'f443e3ca4d62b59aca84e990cacaf5c5'
          '2b0930daa23de94ce87017ba2d84988d'
          'dfc9c58db67aada613c2dd08457941a6',
    );
  });
}

void _ctrCase({
  required String name,
  required String key,
  required String ciphertext,
}) {
  final keyBytes = _hex(key);
  final ctBytes = _hex(ciphertext);

  test('$name encrypt', () {
    expect(AesCtr.encrypt(keyBytes, _iv, _plaintext), equals(ctBytes));
  });

  test('$name decrypt', () {
    expect(AesCtr.decrypt(keyBytes, _iv, ctBytes), equals(_plaintext));
  });
}
