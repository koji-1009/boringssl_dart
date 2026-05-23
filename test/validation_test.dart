import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

/// Tests for the Dart wrapper's own contract — argument validation, error
/// mapping, streaming-context state, and the plumbing that splits/joins data
/// around the FFI boundary.
///
/// These deliberately do NOT re-verify BoringSSL's cryptographic correctness
/// (covered by the KAT/round-trip suites). They pin the behaviour the wrapper
/// is responsible for, so refactors of the FFI glue can't silently drop a
/// guard.
void main() {
  group('getRandomValues bounds', () {
    test('rejects buffers larger than 65536 bytes', () {
      expect(
        () => getRandomValues(Uint8List(65537)),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('accepts the 65536-byte boundary', () {
      expect(() => getRandomValues(Uint8List(65536)), returnsNormally);
    });

    test('honours lengthInBytes for non-Uint8List TypedData', () {
      // Uint16List(8) is 16 bytes; the wrapper must use lengthInBytes, not
      // element count, and write back through the underlying ByteBuffer.
      expect(() => getRandomValues(Uint16List(8)), returnsNormally);
    });
  });

  group('AES key/IV validation', () {
    final validKey = Uint8List(32);
    final validIv = Uint8List(16);

    test('AES-CTR rejects invalid key length', () {
      expect(
        () => AesCtr.encrypt(Uint8List(10), validIv, Uint8List(0)),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('AES-GCM rejects invalid key length', () {
      expect(
        () => AesGcm.encrypt(Uint8List(10), Uint8List(12), Uint8List(0)),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('AES-CBC rejects IV that is not 16 bytes', () {
      expect(
        () => AesCbc.encrypt(validKey, Uint8List(8), Uint8List(0)),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('AES-CTR rejects IV that is not 16 bytes', () {
      expect(
        () => AesCtr.encrypt(validKey, Uint8List(8), Uint8List(0)),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('AES-CBC streaming', () {
    final key = Uint8List.fromList(List.generate(32, (i) => i));
    final iv = Uint8List.fromList(List.generate(16, (i) => i));
    final data = Uint8List.fromList(List.generate(40, (i) => i));

    test('update + finish equals the one-shot result', () {
      final ctx = AesCbc.startEncrypt(key, iv);
      final out = BytesBuilder()
        ..add(ctx.update(data))
        ..add(ctx.finish());

      expect(out.toBytes(), equals(AesCbc.encrypt(key, iv, data)));
    });

    test('throws StateError after finish', () {
      final ctx = AesCbc.startEncrypt(key, iv);
      ctx.update(data);
      ctx.finish();

      expect(() => ctx.update(data), throwsStateError);
      expect(() => ctx.finish(), throwsStateError);
    });
  });

  group('Hash streaming', () {
    final data = Uint8List.fromList(List.generate(40, (i) => i));

    test('update + finish equals digest()', () {
      final ctx = Hash.sha256.start();
      ctx.update(data.sublist(0, 10));
      ctx.update(data.sublist(10));

      expect(ctx.finish(), equals(Hash.sha256.digest(data)));
    });

    test('throws StateError after finish', () {
      final ctx = Hash.sha256.start();
      ctx.update(data);
      ctx.finish();

      expect(() => ctx.update(data), throwsStateError);
      expect(() => ctx.finish(), throwsStateError);
    });
  });

  group('KDF validation', () {
    final key = Uint8List(16);
    final salt = Uint8List(16);

    test('PBKDF2 rejects non-positive iteration counts', () {
      expect(
        () => Pbkdf2.derive(
          key: key,
          salt: salt,
          iterations: 0,
          length: 32,
          hashAlgorithm: 'SHA-256',
        ),
        throwsA(isA<ArgumentError>()),
      );
      expect(
        () => Pbkdf2.derive(
          key: key,
          salt: salt,
          iterations: -1,
          length: 32,
          hashAlgorithm: 'SHA-256',
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('rejects an unsupported hash algorithm', () {
      expect(
        () => Pbkdf2.derive(
          key: key,
          salt: salt,
          iterations: 1000,
          length: 32,
          hashAlgorithm: 'SHA-999',
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('EC key validation', () {
    test('generate rejects an unsupported curve', () {
      expect(() => EcKey.generate('P-999'), throwsA(isA<ArgumentError>()));
    });

    test('importSpki throws on unparseable bytes', () {
      expect(
        () => EcKey.importSpki(Uint8List.fromList([1, 2, 3]), 'P-256'),
        throwsA(isA<Exception>()),
      );
    });

    test('importSpki rejects a curve that does not match the key', () {
      final spki = EcKey.generate('P-256').exportSpki();
      expect(
        () => EcKey.importSpki(spki, 'P-384'),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('constantTimeEq', () {
    test('returns true for equal buffers', () {
      final a = Uint8List.fromList([1, 2, 3, 4]);
      final b = Uint8List.fromList([1, 2, 3, 4]);
      expect(constantTimeEq(a, b), isTrue);
    });

    test('returns false for differing lengths', () {
      expect(
        constantTimeEq(Uint8List.fromList([1, 2]), Uint8List.fromList([1])),
        isFalse,
      );
    });

    test('returns false for a single-byte difference', () {
      final a = Uint8List.fromList([1, 2, 3, 4]);
      final b = Uint8List.fromList([1, 2, 3, 5]);
      expect(constantTimeEq(a, b), isFalse);
    });
  });
}
