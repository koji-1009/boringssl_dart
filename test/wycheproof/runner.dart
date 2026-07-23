// Shared infrastructure for Wycheproof vector suites.
//
// Loads the Wycheproof JSON shape (schema / testGroups / tests) into a typed
// representation general enough for AEAD, signature-verify, KDF, and MAC
// suites, and provides the helpers each suite reuses: hex decoding, per-case
// test naming, and the error-queue hygiene assertion that enforces this
// package's "the BoringSSL error queue never leaks between calls" guarantee
// (see doc/design-notes.md, "Error handling posture") across thousands of
// vectors.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

/// Directory holding the vendored vector files, relative to the package root
/// (where `dart test` runs). Populated by `tool/sync_wycheproof.dart`.
const String vectorsDir = 'test/wycheproof/vectors';

/// A parsed Wycheproof vector file: the top-level `algorithm`/`schema` plus its
/// test groups.
class WycheproofSuite {
  WycheproofSuite({
    required this.algorithm,
    required this.schema,
    required this.numberOfTests,
    required this.groups,
  });

  final String algorithm;
  final String schema;
  final int numberOfTests;
  final List<WycheproofGroup> groups;

  /// Loads and parses `<vectorsDir>/<fileName>`.
  factory WycheproofSuite.load(String fileName) {
    final file = File('$vectorsDir/$fileName');
    if (!file.existsSync()) {
      throw StateError(
        'Missing vector file: ${file.path}. '
        'Run `dart run tool/sync_wycheproof.dart` to vendor it.',
      );
    }
    final json = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    final groups = (json['testGroups'] as List)
        .map((g) => WycheproofGroup._(g as Map<String, dynamic>))
        .toList();
    return WycheproofSuite(
      algorithm: json['algorithm'] as String,
      schema: json['schema'] as String,
      numberOfTests: json['numberOfTests'] as int,
      groups: groups,
    );
  }
}

/// One `testGroups` entry. Group-level parameters vary by schema (e.g.
/// `ivSize`/`tagSize`/`keySize` for AEAD, `keyDer`/`sha` for signatures), so
/// they are exposed generically via [field]/[intField] over the raw map, with
/// typed getters for the common AEAD/IND-CPA fields.
class WycheproofGroup {
  WycheproofGroup._(this._raw)
    : tests = (_raw['tests'] as List)
          .map((t) => WycheproofCase._(t as Map<String, dynamic>))
          .toList();

  final Map<String, dynamic> _raw;
  final List<WycheproofCase> tests;

  /// A raw group-level field, or null when absent.
  T? field<T>(String name) => _raw[name] as T?;

  /// Decodes a required hex-encoded group-level byte field (e.g. key material
  /// like `privateKeyPkcs8` / `publicKeyDer`).
  Uint8List bytes(String name) => hexDecode(_raw[name] as String);

  /// An integer group-level field, or null when absent.
  int? intField(String name) => _raw[name] as int?;

  /// IV size in bits (AEAD / IND-CPA groups).
  int? get ivSize => intField('ivSize');

  /// Tag size in bits (AEAD groups).
  int? get tagSize => intField('tagSize');

  /// Key size in bits.
  int? get keySize => intField('keySize');

  String? get type => field<String>('type');
}

/// One `tests` entry. Byte-valued fields are hex-encoded in the JSON and
/// decoded on demand via [bytes]/[bytesOrNull].
class WycheproofCase {
  WycheproofCase._(this._raw)
    : tcId = _raw['tcId'] as int,
      comment = _raw['comment'] as String? ?? '',
      result = _raw['result'] as String,
      flags =
          (_raw['flags'] as List?)?.cast<String>() ?? const <String>[];

  final Map<String, dynamic> _raw;
  final int tcId;
  final String comment;
  final String result; // "valid" | "invalid" | "acceptable"
  final List<String> flags;

  bool get isValid => result == 'valid';
  bool get isInvalid => result == 'invalid';
  bool get isAcceptable => result == 'acceptable';

  /// A raw case-level field, or null when absent.
  T? field<T>(String name) => _raw[name] as T?;

  /// Decodes a required hex-encoded byte field.
  Uint8List bytes(String name) => hexDecode(_raw[name] as String);

  /// Decodes an optional hex-encoded byte field (null when absent).
  Uint8List? bytesOrNull(String name) {
    final v = _raw[name];
    return v == null ? null : hexDecode(v as String);
  }
}

/// Decodes a hex string into bytes.
Uint8List hexDecode(String hex) {
  if (hex.length.isOdd) {
    throw FormatException('Odd-length hex string', hex);
  }
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

/// Names a `test()` so a failure points straight at the offending vector.
String caseName(WycheproofCase c) => 'tcId ${c.tcId}: ${c.comment}';

/// Asserts BoringSSL's error queue is empty. Call after every vector so a
/// single case that leaves a residual error — which would silently corrupt the
/// next call on the thread — fails loudly and traceably.
void expectCleanErrorQueue() {
  final errors = getOpenSslErrors();
  expect(
    errors,
    isEmpty,
    reason: 'BoringSSL error queue must be empty after each case',
  );
}
