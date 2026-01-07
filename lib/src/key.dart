import 'dart:ffi';
import 'dart:typed_data';

import 'bindings.g.dart';
import 'util.dart';

/// Wrapper around [EVP_PKEY].
class CryptoKey implements Finalizable {
  static final _finalizer = NativeFinalizer(
    Native.addressOf<NativeFunction<Void Function(Pointer<EVP_PKEY>)>>(
      EVP_PKEY_free,
    ).cast(),
  );

  final Pointer<EVP_PKEY> pkey;

  CryptoKey(this.pkey) {
    if (pkey == nullptr) {
      throw ArgumentError.notNull('pkey');
    }
    _finalizer.attach(this, pkey.cast(), detach: this, externalSize: 4096);
  }

  /// Create from an existing pointer (e.g. from generation).
  factory CryptoKey.fromPointer(Pointer<EVP_PKEY> ptr) => CryptoKey(ptr);

  Uint8List exportPkcs8() {
    return runCBB((cbb) {
      if (EVP_marshal_private_key(cbb, pkey) != 1) {
        throw Exception('Failed to marshal private key');
      }
    });
  }

  Uint8List exportSpki() {
    return runCBB((cbb) {
      if (EVP_marshal_public_key(cbb, pkey) != 1) {
        throw Exception('Failed to marshal public key');
      }
    });
  }
}
