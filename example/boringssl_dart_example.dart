import 'dart:typed_data';

import 'package:boringssl_dart/boringssl_dart.dart';

void main() {
  final buffer = Uint8List(16);
  getRandomValues(buffer);
  print(buffer);
}
