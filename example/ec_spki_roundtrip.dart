// Round-trips a P-256 EC key through SubjectPublicKeyInfo (SPKI) DER
// encoding. Also used by .github/workflows/test.yml as the link-hook
// AOT regression check — `dart test` runs in JIT and bypasses that path.

import 'package:boringssl_dart/boringssl_dart.dart';

void main() {
  final original = EcKey.generate('P-256');
  final spki = original.exportSpki();
  final roundTripped = EcKey.importSpki(spki, 'P-256');

  final coords = roundTripped.exportCoordinates();
  final xLen = coords['x']!.length;
  final yLen = coords['y']!.length;
  if (xLen != 32 || yLen != 32) {
    throw StateError('Unexpected P-256 coord lengths: x=$xLen y=$yLen');
  }

  print('EC SPKI roundtrip OK (spki=${spki.length}B, x=${xLen}B, y=${yLen}B)');
}
