import 'dart:ffi' as ffi;

import 'quiche_bindings.dart';

class QuicheQuic {
  late QuicheBindings quiche;

  QuicheQuic() {
    final dylib = ffi.DynamicLibrary.open('quich/quiche.dll');
    quiche = QuicheBindings(dylib);
  }
}
