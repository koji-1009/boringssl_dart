import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';
import 'package:crypto/crypto.dart' as crypto;

void main() {
  print('Running Benchmarks: BoringSSL (FFI) vs Package:crypto (Dart)\n');

  // Warmup
  print('Warming up...');
  final warmupData = Uint8List(1024);
  for (var i = 0; i < 1000; i++) {
    Hash.sha256.digest(warmupData);
    crypto.sha256.convert(warmupData);
  }
  print('Warmup complete.\n');

  _benchmark('Small Payload (64 Bytes)', 64, 100000);
  _benchmark('Medium Payload (1 KB)', 1024, 20000);
  _benchmark('Large Payload (1 MB)', 1024 * 1024, 100);
}

void _benchmark(String label, int size, int iterations) {
  final data = Uint8List(size);

  // BoringSSL
  final swB = Stopwatch()..start();
  for (var i = 0; i < iterations; i++) {
    Hash.sha256.digest(data);
  }
  swB.stop();
  final timeB = swB.elapsedMicroseconds / 1000.0; // milliseconds

  // Crypto
  final swC = Stopwatch()..start();
  for (var i = 0; i < iterations; i++) {
    crypto.sha256.convert(data);
  }
  swC.stop();
  final timeC = swC.elapsedMicroseconds / 1000.0; // milliseconds

  print('--- $label ---');
  print('Data Size  : $size bytes');
  print('Iterations : $iterations');

  final opsB = (iterations / (timeB / 1000.0)).toStringAsFixed(0);
  final throughputB = ((iterations * size) / 1024 / 1024 / (timeB / 1000.0))
      .toStringAsFixed(2);
  print(
    'BoringSSL  : ${timeB.toStringAsFixed(2)} ms ($opsB ops/s, $throughputB MB/s)',
  );

  final opsC = (iterations / (timeC / 1000.0)).toStringAsFixed(0);
  final throughputC = ((iterations * size) / 1024 / 1024 / (timeC / 1000.0))
      .toStringAsFixed(2);
  print(
    'Crypto     : ${timeC.toStringAsFixed(2)} ms ($opsC ops/s, $throughputC MB/s)',
  );

  final ratio = (timeC / timeB).toStringAsFixed(2);
  print('Speedup    : ${ratio}x faster\n');
}
