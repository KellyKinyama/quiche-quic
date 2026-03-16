import 'dart:ffi' as ffi;
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:quiche_quic/quiche_bindings.dart';

void debugCallback(ffi.Pointer<ffi.Char> line, ffi.Pointer<ffi.Void> argp) {
  print("🛠️ [QUICHE] ${line.cast<Utf8>().toDartString()}");
}

void main() async {
  final dylib = ffi.DynamicLibrary.open('quich/quiche.dll');
  final quiche = QuicheBindings(dylib);

  print(
    '✅ DLL Loaded. Version: ${quiche.quiche_version().cast<Utf8>().toDartString()}',
  );

  // 1. Enable logging first to see internal errors
  final nativeCallback =
      ffi.Pointer.fromFunction<
        ffi.Void Function(ffi.Pointer<ffi.Char>, ffi.Pointer<ffi.Void>)
      >(debugCallback);
  quiche.quiche_enable_debug_logging(nativeCallback, ffi.nullptr);

  // 2. Try to create config with Version 1 (0x00000001)
  // If this crashes, try 0xff00001d (Draft 29)
  const quicVersion = 1;
  print('🧪 Attempting to create config with version: $quicVersion');

  final config = quiche.quiche_config_new(quicVersion);

  if (config == ffi.nullptr) {
    print(
      "❌ CRITICAL: quiche_config_new returned NULL. The version $quicVersion is not supported by this DLL.",
    );
    return;
  }

  print(
    '🚀 Config created successfully at address: ${config.address.toRadixString(16)}',
  );

  try {
    print('⚙️ Setting timeout...');
    quiche.quiche_config_set_max_idle_timeout(config, 5000);

    print('⚙️ Setting initial data...');
    quiche.quiche_config_set_initial_max_data(config, 10000000);

    print('⚙️ Setting stream data...');
    quiche.quiche_config_set_initial_max_stream_data_bidi_local(
      config,
      1000000,
    );

    print('✨ Config successfully initialized!');
  } catch (e) {
    print('💥 Exception during config setup: $e');
  }
}
