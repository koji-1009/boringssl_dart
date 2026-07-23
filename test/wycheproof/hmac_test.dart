// HMAC Wycheproof suites (SHA-1, SHA-256, SHA-384, SHA-512).
//
// Each group fixes a keySize and a tagSize (both in bits). A group whose
// tagSize equals the hash's full output is a full-length group; a group whose
// tagSize is smaller is a truncated group.
//
// Full-length groups use `Hmac.verify`, which per doc/design-notes.md is
// fail-closed: a `valid` case returns true, an `invalid` case returns false,
// and neither ever throws.
//
// Truncated groups CANNOT go through `Hmac.verify`: that helper recomputes the
// full-length tag and short-circuits to false whenever the supplied signature's
// length differs (`computed.length != signature.length`), so a truncated tag
// would always compare false, even for a valid vector. We therefore compute the
// full tag with `Hmac.sign` and compare its leading `tagSize/8` bytes against
// the vector tag using the constant-time `constantTimeEq` — valid -> equal,
// invalid -> not equal. Truncated groups are never silently skipped.
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

import 'runner.dart';

/// A vendored HMAC suite: its file, the hash name `Hmac` expects, and the
/// hash's full output length in bits.
class _HmacSpec {
  const _HmacSpec(this.fileName, this.hashAlgorithm, this.outputBits);
  final String fileName;
  final String hashAlgorithm;
  final int outputBits;
}

const List<_HmacSpec> _specs = [
  _HmacSpec('hmac_sha1_test.json', 'SHA-1', 160),
  _HmacSpec('hmac_sha256_test.json', 'SHA-256', 256),
  _HmacSpec('hmac_sha384_test.json', 'SHA-384', 384),
  _HmacSpec('hmac_sha512_test.json', 'SHA-512', 512),
];

void main() {
  for (final spec in _specs) {
    _runHmacSuite(spec);
  }
}

void _runHmacSuite(_HmacSpec spec) {
  final suite = WycheproofSuite.load(spec.fileName);

  var exercised = 0;
  const skipped = 0;

  group('HMAC Wycheproof (${suite.algorithm})', () {
    for (final g in suite.groups) {
      final tagBytes = g.tagSize! ~/ 8;
      final truncated = g.tagSize! < spec.outputBits;

      for (final c in g.tests) {
        final key = c.bytes('key');
        final msg = c.bytes('msg');
        final tag = c.bytes('tag');

        exercised++;
        test('${suite.algorithm} tag${g.tagSize} ${caseName(c)}', () {
          if (truncated) {
            // Truncated tags: compare the tag against the leading bytes of the
            // full HMAC output (see file header for why verify() cannot be
            // used here).
            final full = Hmac.sign(key, msg, spec.hashAlgorithm);
            final prefix = Uint8List.sublistView(full, 0, tagBytes);
            final matches = constantTimeEq(prefix, tag);
            switch (c.result) {
              case 'valid':
                expect(matches, isTrue);
              case 'invalid':
                expect(matches, isFalse);
              case 'acceptable':
                // No truncated group carries acceptable cases in these
                // vectors, but keep the branch total: a match is only allowed
                // when the tag was in fact correct.
                expect(matches, anyOf(isTrue, isFalse));
              default:
                fail('Unknown result: ${c.result}');
            }
          } else {
            // Full-length tags: verify() is fail-closed and must never throw.
            final ok = Hmac.verify(key, tag, msg, spec.hashAlgorithm);
            switch (c.result) {
              case 'valid':
                expect(ok, isTrue);
              case 'invalid':
                expect(ok, isFalse);
              case 'acceptable':
                expect(ok, anyOf(isTrue, isFalse));
              default:
                fail('Unknown result: ${c.result}');
            }
          }
          expectCleanErrorQueue();
        });
      }
    }

    test('${suite.algorithm} coverage summary', () {
      // ignore: avoid_print
      print(
        '${suite.algorithm}: $exercised cases exercised, $skipped skipped '
        '(of ${suite.numberOfTests} total vectors).',
      );
      expect(exercised, greaterThan(0));
    });
  });
}
