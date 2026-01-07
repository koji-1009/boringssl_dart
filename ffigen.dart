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
    'd2i_RSAPrivateKey',
    'BN_bin2bn',
    'BN_bn2bin_padded',
    'BN_free',
    'BN_new',
    'BN_num_bytes',
    'BN_set_word',
    'CBB_cleanup',
    'CBB_data',
    'CBB_flush',
    'CBB_init',
    'CBB_len',
    'CBB_zero',
    'CBS_init',
    'CRYPTO_memcmp',
    'ECDH_compute_key',
    'ECDSA_SIG_free',
    'ECDSA_SIG_get0',
    'ECDSA_SIG_marshal',
    'ECDSA_SIG_new',
    'ECDSA_SIG_parse',
    'EC_GROUP_get0_order',
    'EC_GROUP_get_curve_name',
    'EC_GROUP_get_degree',
    'EC_KEY_check_key',
    'EC_KEY_free',
    'EC_KEY_generate_key',
    'EC_KEY_get0_group',
    'EC_KEY_get0_private_key',
    'EC_KEY_get0_public_key',
    'EC_KEY_get_enc_flags',
    'EC_KEY_new_by_curve_name',
    'EC_KEY_set_enc_flags',
    'EC_KEY_set_private_key',
    'EC_KEY_set_public_key',
    'EC_KEY_set_public_key_affine_coordinates',
    'EC_POINT_free',
    'EC_POINT_get_affine_coordinates_GFp',
    'EC_POINT_new',
    'EC_POINT_oct2point',
    'EC_POINT_point2cbb',
    'ERR_clear_error',
    'ERR_error_string_n',
    'ERR_get_error',
    'ERR_peek_error',
    'EVP_aead_aes_128_gcm',
    'EVP_aead_aes_256_gcm',
    'EVP_AEAD_CTX_free',
    'EVP_AEAD_CTX_new',
    'EVP_AEAD_CTX_open',
    'EVP_AEAD_CTX_seal',
    'EVP_AEAD_max_overhead',
    'EVP_aes_128_cbc',
    'EVP_aes_128_ctr',
    'EVP_aes_256_cbc',
    'EVP_aes_256_ctr',
    'EVP_CIPHER_CTX_free',
    'EVP_CIPHER_CTX_new',
    'EVP_CipherFinal_ex',
    'EVP_CipherInit_ex',
    'EVP_CIPHER_iv_length',
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
    'EVP_parse_private_key',
    'EVP_parse_public_key',
    'EVP_PKEY_CTX_free',
    'EVP_PKEY_CTX_new',
    'EVP_PKEY_CTX_set0_rsa_oaep_label',
    'EVP_PKEY_CTX_set_rsa_mgf1_md',
    'EVP_PKEY_CTX_set_rsa_oaep_md',
    'EVP_PKEY_CTX_set_rsa_padding',
    'EVP_PKEY_CTX_set_rsa_pss_saltlen',
    'EVP_PKEY_decrypt',
    'EVP_PKEY_decrypt_init',
    'EVP_PKEY_encrypt',
    'EVP_PKEY_encrypt_init',
    'EVP_PKEY_free',
    'EVP_PKEY_get1_EC_KEY',
    'EVP_PKEY_get1_RSA',
    'EVP_PKEY_id',
    'EVP_PKEY_new',
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
    'OPENSSL_malloc',
    'PKCS5_PBKDF2_HMAC',
    'RAND_bytes',
    'RSA_check_key',
    'RSA_free',
    'RSA_generate_key_ex',
    'RSA_get0_crt_params',
    'RSA_get0_factors',
    'RSA_get0_key',
    'RSA_new',
    'RSAPublicKey_dup',
    'RSA_set0_crt_params',
    'RSA_set0_factors',
    'RSA_set0_key',
    'OPENSSL_free',
    'OPENSSL_memdup',
    'EVP_MD_size',
    'EVP_AEAD_nonce_length',
    'EVP_AEAD_max_tag_len',
    'EVP_AEAD_key_length',
    'BN_value_one',
    'BN_add',
    'BN_sub',
    'BN_cmp',
    'BN_lshift',
    'EVP_CIPHER_block_size',
    'EC_GROUP_new_by_curve_name',
    'EC_GROUP_free',
    'EVP_PKEY_set_type',
    'BORINGSSL_self_test',
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

// Helper to setup BoringSSL source
Future<void> setupBoringSsl() async {
  // Assume running from package root
  final boringsslPath = 'third_party/boringssl';
  final commitFile = File('native/boringssl_commit.txt');

  if (!commitFile.existsSync()) {
    throw Exception('Missing config: native/boringssl_commit.txt');
  }
  final targetCommit = commitFile.readAsStringSync().trim();

  if (!Directory(boringsslPath).existsSync()) {
    print('Initializing BoringSSL repository...');
    await Directory(boringsslPath).create(recursive: true);
    await _runGit(['init'], workingDirectory: boringsslPath);
    await _runGit([
      'remote',
      'add',
      'origin',
      'https://github.com/google/boringssl.git',
    ], workingDirectory: boringsslPath);
  }

  print('Fetching BoringSSL commit $targetCommit...');
  await _runGit([
    'fetch',
    '--depth',
    '1',
    '--no-tags',
    'origin',
    targetCommit,
  ], workingDirectory: boringsslPath);

  // Check if we are already on the target commit
  String? currentHead;

  // Correction: _runGit as defined in previous steps is void and throws.
  // Use Process.run directly for checks.
  final headResult = await Process.run('git', [
    'rev-parse',
    'HEAD',
  ], workingDirectory: boringsslPath);
  if (headResult.exitCode == 0) {
    currentHead = headResult.stdout.toString().trim();
  }

  if (currentHead == targetCommit) {
    print('Already on commit $targetCommit. Skipping checkout.');
  } else {
    print('Checking out $targetCommit...');
    await _runGit(['checkout', targetCommit], workingDirectory: boringsslPath);
  }
}

Future<void> _runGit(List<String> args, {String? workingDirectory}) async {
  final result = await Process.run(
    'git',
    args,
    workingDirectory: workingDirectory,
  );
  if (result.exitCode != 0) {
    throw Exception('git ${args.join(" ")} failed: ${result.stderr}');
  }
}

void main() async {
  await setupBoringSsl();
  config.generate();
}
