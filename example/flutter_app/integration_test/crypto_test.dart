// On-device integration test for boringssl_dart.
//
// Runs on a real Android/iOS device (or emulator/simulator) via
// `flutter test integration_test/crypto_test.dart`. It drives representative
// operations across the API through the from-source BoringSSL the build hook
// compiled and linked for the target, turning "builds for mobile" into a
// pass/fail assertion rather than a claim.

import 'dart:convert';
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  final message = Uint8List.fromList(utf8.encode('boringssl_dart on device'));

  test('BoringSSL commit is a pinned 40-char hash', () {
    expect(boringsslCommit, matches(RegExp(r'^[0-9a-f]{40}$')));
  });

  test('SHA-256 digest has the right length', () {
    expect(Hash.sha256.digest(message), hasLength(32));
  });

  test('HMAC-SHA256 produces a 32-byte tag', () {
    expect(Hmac.sign(Uint8List(32), message, 'SHA-256'), hasLength(32));
  });

  test('AES-GCM round-trips', () {
    final key = Uint8List(32);
    final iv = Uint8List(12);
    final ciphertext = AesGcm.encrypt(key, iv, message);
    expect(AesGcm.decrypt(key, iv, ciphertext), equals(message));
  });

  test('ECDSA P-256 sign/verify (valid true, tampered false)', () {
    final key = EcKey.generate('P-256');
    final sig = Ecdsa.sign(key, message, 'SHA-256');
    expect(Ecdsa.verify(key, sig, message, 'SHA-256'), isTrue);
    final tampered = Uint8List.fromList(utf8.encode('a different message'));
    expect(Ecdsa.verify(key, sig, tampered, 'SHA-256'), isFalse);
  });
}
