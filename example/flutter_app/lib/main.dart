// Minimal Flutter example that exercises boringssl_dart on device.
//
// Its only job is to prove the package builds, links, and runs on Android and
// iOS: on startup it drives a few representative operations across the API
// surface (digest, HMAC, AES-GCM round-trip, EC generate + ECDSA sign/verify)
// through the from-source BoringSSL the build hook compiled, and shows each
// result — so a green screen is an on-device verification, not a claim.

import 'dart:convert';
import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:flutter/material.dart';

void main() => runApp(const BoringSslExampleApp());

class BoringSslExampleApp extends StatelessWidget {
  const BoringSslExampleApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'boringssl_dart example',
    theme: ThemeData(colorSchemeSeed: Colors.teal, useMaterial3: true),
    home: const _Home(),
  );
}

class _Check {
  const _Check(this.name, this.ok, this.detail);
  final String name;
  final bool ok;
  final String detail;
}

class _Home extends StatelessWidget {
  const _Home();

  List<_Check> _run() {
    final checks = <_Check>[];

    void check(String name, bool Function() body) {
      try {
        final ok = body();
        checks.add(_Check(name, ok, ok ? 'ok' : 'returned false'));
      } catch (e) {
        checks.add(_Check(name, false, '$e'));
      }
    }

    final message = Uint8List.fromList(utf8.encode('boringssl_dart on device'));

    check('SHA-256 digest', () => Hash.sha256.digest(message).length == 32);

    check('HMAC-SHA256', () {
      final mac = Hmac.sign(Uint8List(32), message, 'SHA-256');
      return mac.length == 32;
    });

    check('AES-GCM round-trip', () {
      final key = Uint8List(32);
      final iv = Uint8List(12);
      final ct = AesGcm.encrypt(key, iv, message);
      final pt = AesGcm.decrypt(key, iv, ct);
      return _eq(pt, message);
    });

    check('ECDSA P-256 sign/verify', () {
      final k = EcKey.generate('P-256');
      final sig = Ecdsa.sign(k, message, 'SHA-256');
      final good = Ecdsa.verify(k, sig, message, 'SHA-256');
      final tampered = Uint8List.fromList(utf8.encode('different message'));
      final bad = Ecdsa.verify(k, sig, tampered, 'SHA-256');
      return good && !bad;
    });

    check('BoringSSL commit pinned', () => boringsslCommit.length == 40);

    return checks;
  }

  static bool _eq(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  @override
  Widget build(BuildContext context) {
    final checks = _run();
    final allOk = checks.every((c) => c.ok);
    return Scaffold(
      appBar: AppBar(
        title: const Text('boringssl_dart'),
        backgroundColor: allOk ? Colors.teal : Colors.red,
        foregroundColor: Colors.white,
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(
            allOk ? 'All crypto checks passed on device' : 'Some checks FAILED',
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          Text(
            'BoringSSL @ $boringsslCommit',
            style: Theme.of(context).textTheme.bodySmall,
          ),
          const Divider(height: 24),
          for (final c in checks)
            ListTile(
              dense: true,
              leading: Icon(
                c.ok ? Icons.check_circle : Icons.error,
                color: c.ok ? Colors.green : Colors.red,
              ),
              title: Text(c.name),
              subtitle: Text(c.detail),
            ),
        ],
      ),
    );
  }
}
