import 'dart:ffi' as ffi;
import 'package:ffi/ffi.dart';
import 'package:quiche_quic/quiche_bindings.dart'; // Ensure this matches your package name in pubspec.yaml

void main() {
  // 1. Load the dynamic library
  // Make sure quiche.dll is in the root of your project folder
  final dylib = ffi.DynamicLibrary.open('quich/quiche.dll');

  // 2. Initialize the bindings
  final quiche = QuicheBindings(dylib);

  // 3. Call the version function
  final versionPtr = quiche.quiche_version();
  final versionString = versionPtr.cast<Utf8>().toDartString();

  print('--- QUICHE BRIDGE STATUS ---');
  print('✅ DLL Loaded Successfully');
  print('✅ Binding generated successfully');
  print('✅ Library Version: $versionString');

  // 4. Try creating a config object as a test
  // QUICHE_PROTOCOL_VERSION = 0xff00001d (Draft 29) or 1 (v1)
  final config = quiche.quiche_config_new(1);
  if (config != ffi.nullptr) {
    print('✅ Config object created in memory');
    quiche.quiche_config_free(config);
    print('✅ Config object freed');
  }
}
