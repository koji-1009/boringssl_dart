import 'dart:io';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:test/test.dart';

void main() {
  group('boringsslCommit', () {
    // boringsslCommit is generated from native/boringssl_commit.txt by
    // ffigen.dart. If the pin is bumped without regenerating, the exposed
    // constant would silently lie about which BoringSSL backs the build, so
    // this test fails to force the two back in sync.
    test('matches the pinned commit in native/boringssl_commit.txt', () {
      final pinned = File(
        'native/boringssl_commit.txt',
      ).readAsStringSync().trim();
      expect(boringsslCommit, equals(pinned));
    });

    test('is a full 40-character hex hash', () {
      expect(boringsslCommit, matches(RegExp(r'^[0-9a-f]{40}$')));
    });
  });
}
