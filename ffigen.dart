// Regenerate bindings with `dart run ffigen.dart`.
import 'dart:io';

import 'package:ffigen/ffigen.dart';

final config = FfiGenerator(
  headers: Headers(
    entryPoints: [
      Uri.file('third_party/boringssl/include/openssl/aead.h'),
      Uri.file('third_party/boringssl/include/openssl/aes.h'),
      Uri.file('third_party/boringssl/include/openssl/bn.h'),
      Uri.file('third_party/boringssl/include/openssl/bytestring.h'),
      Uri.file('third_party/boringssl/include/openssl/cipher.h'),
      Uri.file('third_party/boringssl/include/openssl/crypto.h'),
      Uri.file('third_party/boringssl/include/openssl/digest.h'),
      Uri.file('third_party/boringssl/include/openssl/ec_key.h'),
      Uri.file('third_party/boringssl/include/openssl/ec.h'),
      Uri.file('third_party/boringssl/include/openssl/ecdh.h'),
      Uri.file('third_party/boringssl/include/openssl/ecdsa.h'),
      Uri.file('third_party/boringssl/include/openssl/err.h'),
      Uri.file('third_party/boringssl/include/openssl/evp.h'),
      Uri.file('third_party/boringssl/include/openssl/hkdf.h'),
      Uri.file('third_party/boringssl/include/openssl/hmac.h'),
      Uri.file('third_party/boringssl/include/openssl/mem.h'),
      Uri.file('third_party/boringssl/include/openssl/rand.h'),
      Uri.file('third_party/boringssl/include/openssl/rsa.h'),
    ],
    include: (Uri uri) => uri.path.contains('third_party/boringssl/include'),
    compilerOptions: [
      if (Platform.isMacOS) ...['-isysroot', macSdkPath],
      '-Ithird_party/boringssl/include',
    ],
  ),
  output: Output(
    dartFile: Uri.file('lib/src/bindings.g.dart'),
    style: const NativeExternalBindings(
      assetId: 'package:boringssl_dart/boringssl_dart',
    ),
  ),
  macros: Macros.includeSet({
    'AES_BLOCK_SIZE',
    'EC_PKEY_NO_PUBKEY',
    'EVP_PKEY_EC',
    'EVP_PKEY_RSA',
    'HKDF_R_OUTPUT_TOO_LARGE',
    'NID_secp384r1',
    'NID_secp521r1',
    'NID_X9_62_prime256v1',
    'RSA_PKCS1_OAEP_PADDING',
    'RSA_PKCS1_PADDING',
    'RSA_PKCS1_PSS_PADDING',
  }),
  enums: Enums.includeSet({'point_conversion_form_t'}),
  unnamedEnums: UnnamedEnums.includeSet({'ERR_LIB_HKDF'}),
  structs: Structs.includeSet({'cbs_st', 'cbb_st'}),
  functions: Functions.includeSet({
    'BN_add',
    'BN_bin2bn',
    'BN_bn2bin_padded',
    'BN_cmp',
    'BN_free',
    'BN_lshift',
    'BN_new',
    'BN_num_bytes',
    'BN_set_word',
    'BN_sub',
    'BN_value_one',
    'BORINGSSL_self_test',
    'CBB_cleanup',
    'CBB_data',
    'CBB_flush',
    'CBB_init',
    'CBB_len',
    'CBB_zero',
    'CRYPTO_memcmp',
    'd2i_RSAPrivateKey',
    'EC_GROUP_free',
    'EC_GROUP_get_curve_name',
    'EC_GROUP_get_degree',
    'EC_GROUP_get0_order',
    'EC_GROUP_new_by_curve_name',
    'EC_KEY_check_key',
    'EC_KEY_free',
    'EC_KEY_generate_key',
    'EC_KEY_get_enc_flags',
    'EC_KEY_get0_group',
    'EC_KEY_get0_private_key',
    'EC_KEY_get0_public_key',
    'EC_KEY_new_by_curve_name',
    'EC_KEY_set_enc_flags',
    'EC_KEY_set_private_key',
    'EC_KEY_set_public_key_affine_coordinates',
    'EC_KEY_set_public_key',
    'EC_POINT_free',
    'EC_POINT_get_affine_coordinates_GFp',
    'EC_POINT_new',
    'EC_POINT_oct2point',
    'EC_POINT_point2cbb',
    'ECDH_compute_key',
    'ECDSA_SIG_free',
    'ECDSA_SIG_get0',
    'ECDSA_SIG_marshal',
    'ECDSA_SIG_new',
    'ECDSA_SIG_parse',
    'ERR_clear_error',
    'ERR_error_string_n',
    'ERR_get_error',
    'ERR_peek_error',
    'EVP_aead_aes_128_gcm',
    'EVP_aead_aes_192_gcm',
    'EVP_aead_aes_256_gcm',
    'EVP_AEAD_CTX_free',
    'EVP_AEAD_CTX_new',
    'EVP_AEAD_CTX_open',
    'EVP_AEAD_CTX_seal',
    'EVP_AEAD_key_length',
    'EVP_AEAD_max_overhead',
    'EVP_AEAD_max_tag_len',
    'EVP_AEAD_nonce_length',
    'EVP_aes_128_cbc',
    'EVP_aes_128_ctr',
    'EVP_aes_192_cbc',
    'EVP_aes_192_ctr',
    'EVP_aes_256_cbc',
    'EVP_aes_256_ctr',
    'EVP_CIPHER_block_size',
    'EVP_CIPHER_CTX_free',
    'EVP_CIPHER_CTX_new',
    'EVP_CIPHER_iv_length',
    'EVP_CipherFinal_ex',
    'EVP_CipherInit_ex',
    'EVP_CipherUpdate',
    'EVP_DigestFinal',
    'EVP_DigestInit',
    'EVP_DigestSignFinal',
    'EVP_DigestSignInit',
    'EVP_DigestSignUpdate',
    'EVP_DigestUpdate',
    'EVP_DigestVerifyFinal',
    'EVP_DigestVerifyInit',
    'EVP_DigestVerifyUpdate',
    'EVP_marshal_private_key',
    'EVP_marshal_public_key',
    'EVP_MD_CTX_free',
    'EVP_MD_CTX_new',
    'EVP_MD_CTX_size',
    'EVP_MD_size',
    'EVP_parse_private_key',
    'EVP_parse_public_key',
    'EVP_PKEY_bits',
    'EVP_PKEY_CTX_free',
    'EVP_PKEY_CTX_new',
    'EVP_PKEY_CTX_set_rsa_mgf1_md',
    'EVP_PKEY_CTX_set_rsa_oaep_md',
    'EVP_PKEY_CTX_set_rsa_padding',
    'EVP_PKEY_CTX_set_rsa_pss_saltlen',
    'EVP_PKEY_CTX_set0_rsa_oaep_label',
    'EVP_PKEY_decrypt_init',
    'EVP_PKEY_decrypt',
    'EVP_PKEY_encrypt_init',
    'EVP_PKEY_encrypt',
    'EVP_PKEY_free',
    'EVP_PKEY_get1_EC_KEY',
    'EVP_PKEY_get1_RSA',
    'EVP_PKEY_id',
    'EVP_PKEY_new',
    'EVP_PKEY_set_type',
    'EVP_PKEY_set1_EC_KEY',
    'EVP_PKEY_set1_RSA',
    'EVP_sha1',
    'EVP_sha256',
    'EVP_sha384',
    'EVP_sha512',
    'HKDF',
    'HMAC_CTX_free',
    'HMAC_CTX_new',
    'HMAC_Final',
    'HMAC_Init_ex',
    'HMAC_size',
    'HMAC_Update',
    'OPENSSL_free',
    'OPENSSL_malloc',
    'OPENSSL_memdup',
    'PKCS5_PBKDF2_HMAC',
    'RAND_bytes',
    'RSA_check_key',
    'RSA_free',
    'RSA_generate_key_ex',
    'RSA_get0_crt_params',
    'RSA_get0_factors',
    'RSA_get0_key',
    'RSA_new',
    'RSA_set0_crt_params',
    'RSA_set0_factors',
    'RSA_set0_key',
    'RSAPublicKey_dup',
  }),
  typedefs: Typedefs.includeSet({
    'BIGNUM',
    'BN_GENCB',
    'CBB',
    'CBS',
    'EC_GROUP',
    'EC_KEY',
    'EC_POINT',
    'ECDSA_SIG',
    'EVP_AEAD_CTX',
    'EVP_AEAD',
    'EVP_CIPHER_CTX',
    'EVP_CIPHER',
    'EVP_MD_CTX',
    'EVP_MD',
    'EVP_PKEY_CTX',
    'EVP_PKEY',
    'HMAC_CTX',
    'RSA',
  }),
);

/// Download BoringSSL source for the commit specified in native/boringssl_commit.txt.
Future<void> setupBoringSsl() async {
  final boringsslDir = Directory('third_party/boringssl');
  final commitFile = File('native/boringssl_commit.txt');

  if (!commitFile.existsSync()) {
    throw Exception('Missing native/boringssl_commit.txt');
  }

  final commit = commitFile.readAsStringSync().trim();
  final markerFile = File('third_party/boringssl/.commit');

  if (markerFile.existsSync() &&
      markerFile.readAsStringSync().trim() == commit) {
    print('BoringSSL already at $commit');
    return;
  }

  final url = 'https://github.com/google/boringssl/archive/$commit.tar.gz';
  print('Fetching $url');

  final client = HttpClient();
  try {
    final request = await client.getUrl(Uri.parse(url));
    final response = await request.close();
    if (response.statusCode != 200) {
      throw Exception('HTTP ${response.statusCode} fetching $url');
    }

    if (boringsslDir.existsSync()) await boringsslDir.delete(recursive: true);
    await boringsslDir.create(recursive: true);

    final tarball = File('third_party/boringssl.tar.gz');
    await response.pipe(tarball.openWrite());

    final result = await Process.run('tar', [
      'xzf',
      tarball.path,
      '--strip-components=1',
      '-C',
      boringsslDir.path,
    ]);
    if (result.exitCode != 0) {
      throw Exception('tar extraction failed: ${result.stderr}');
    }

    await markerFile.writeAsString(commit);
    await tarball.delete();
  } finally {
    client.close();
  }
}

/// Extract @ffi.Native C symbols from bindings.g.dart and write hook/symbols.dart.
Future<void> generateSymbols() async {
  final bindingsFile = File('lib/src/bindings.g.dart');
  if (!bindingsFile.existsSync()) {
    throw Exception('Missing lib/src/bindings.g.dart');
  }

  final content = bindingsFile.readAsStringSync();
  final symbols = <String>{};

  // Explicit: @ffi.Native<...>(symbol: 'NAME')
  final explicitPattern = RegExp(r"symbol:\s*'(\w+)'");
  for (final match in explicitPattern.allMatches(content)) {
    symbols.add(match.group(1)!);
  }

  // Implicit: @ffi.Native<...>() \n external ... NAME(
  // The function name IS the C symbol (no symbol: override).
  // Skip underscore-prefixed names as they always have an explicit symbol:.
  final externalPattern = RegExp(r'^external\s+.*\s(\w+)\(', multiLine: true);
  for (final match in externalPattern.allMatches(content)) {
    final name = match.group(1)!;
    if (!name.startsWith('_')) {
      symbols.add(name);
    }
  }

  final sorted = symbols.toList()..sort();

  final buffer = StringBuffer();
  buffer.writeln('/// Auto-generated by ffigen.dart. Do not edit.');
  buffer.writeln(
    '/// C function symbols referenced by @ffi.Native in bindings.g.dart.',
  );
  buffer.writeln('const List<String> symbols = [');
  for (final symbol in sorted) {
    buffer.writeln("  '$symbol',");
  }
  buffer.write('];');
  buffer.writeln();

  await File('hook/symbols.dart').writeAsString(buffer.toString());
  print('Generated hook/symbols.dart with ${sorted.length} symbols');
}

void main() async {
  await setupBoringSsl();
  config.generate();
  await generateSymbols();
}
