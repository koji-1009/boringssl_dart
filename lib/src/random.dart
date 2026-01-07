import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.g.dart';
import 'util.dart';

/// Fills [buffer] with cryptographically random values.
///
/// Throws [ArgumentError] if the size of [buffer] exceeds 65536 bytes.
void getRandomValues(TypedData buffer) {
  final length = buffer.lengthInBytes;
  if (length > 65536) {
    throw ArgumentError.value(
      length,
      'buffer',
      'Buffer size must not exceed 65536 bytes',
    );
  }

  using((arena) {
    // Use a temporary native buffer to get random bytes.
    // The buffer is automatically freed when the arena scope ends.
    final tempPtr = arena<Uint8>(length);

    checkOpIsOne(
      RAND_bytes(tempPtr, length),
      message: 'Failed to generate random bytes',
    );

    // Copy back to Dart buffer
    final uint8List = buffer.buffer.asUint8List(buffer.offsetInBytes, length);
    final nativeList = tempPtr.asTypedList(length);
    uint8List.setAll(0, nativeList);
  });
}
