// dart run bin/test_symbols.dart
import 'dart:ffi' as ffi;
import 'dart:io';

// --------- Concrete native typedefs (no generics) ---------
typedef _Void_H3Cfg_Bool_Native =
    ffi.Void Function(ffi.Pointer<ffi.Void>, ffi.Bool);
typedef _Void_H3Cfg_Dart = void Function(ffi.Pointer<ffi.Void>, bool);

typedef _Void_H3Cfg_Only_Native = ffi.Void Function(ffi.Pointer<ffi.Void>);
typedef _Void_H3Cfg_Only_Dart = void Function(ffi.Pointer<ffi.Void>);

typedef _Ptr_H3_NewWithTransport_Native =
    ffi.Pointer<ffi.Void> Function(
      ffi.Pointer<ffi.Void>,
      ffi.Pointer<ffi.Void>,
    );
typedef _Ptr_H3_NewWithTransport_Dart =
    ffi.Pointer<ffi.Void> Function(
      ffi.Pointer<ffi.Void>,
      ffi.Pointer<ffi.Void>,
    );

typedef _I64_H3ConnPoll_Native =
    ffi.Int64 Function(
      ffi.Pointer<ffi.Void>, // quiche_h3_conn*
      ffi.Pointer<ffi.Void>, // quiche_conn*
      ffi.Pointer<ffi.Pointer<ffi.Void>>, // quiche_h3_event**
    );
typedef _I64_H3ConnPoll_Dart =
    int Function(
      ffi.Pointer<ffi.Void>,
      ffi.Pointer<ffi.Void>,
      ffi.Pointer<ffi.Pointer<ffi.Void>>,
    );

typedef _I32_H3EventType_Native = ffi.Int32 Function(ffi.Pointer<ffi.Void>);
typedef _I32_H3EventType_Dart = int Function(ffi.Pointer<ffi.Void>);

typedef _I32_ForEachHeader_Native =
    ffi.Int32 Function(
      ffi.Pointer<ffi.Void>, // quiche_h3_event*
      ffi.Pointer<
        ffi.NativeFunction<
          ffi.Int32 Function(
            ffi.Pointer<ffi.Uint8>,
            ffi.Size,
            ffi.Pointer<ffi.Uint8>,
            ffi.Size,
            ffi.Pointer<ffi.Void>,
          )
        >
      >,
      ffi.Pointer<ffi.Void>,
    );
typedef _I32_ForEachHeader_Dart =
    int Function(
      ffi.Pointer<ffi.Void>,
      ffi.Pointer<
        ffi.NativeFunction<
          ffi.Int32 Function(
            ffi.Pointer<ffi.Uint8>,
            ffi.Size,
            ffi.Pointer<ffi.Uint8>,
            ffi.Size,
            ffi.Pointer<ffi.Void>,
          )
        >
      >,
      ffi.Pointer<ffi.Void>,
    );

typedef _I32_ForEachSetting_Native =
    ffi.Int32 Function(
      ffi.Pointer<ffi.Void>, // quiche_h3_conn*
      ffi.Pointer<
        ffi.NativeFunction<
          ffi.Int32 Function(ffi.Uint64, ffi.Uint64, ffi.Pointer<ffi.Void>)
        >
      >,
      ffi.Pointer<ffi.Void>,
    );
typedef _I32_ForEachSetting_Dart =
    int Function(
      ffi.Pointer<ffi.Void>,
      ffi.Pointer<
        ffi.NativeFunction<
          ffi.Int32 Function(ffi.Uint64, ffi.Uint64, ffi.Pointer<ffi.Void>)
        >
      >,
      ffi.Pointer<ffi.Void>,
    );

typedef _I32_SendSettings_Native =
    ffi.Int32 Function(
      ffi.Pointer<ffi.Void> /*h3*/,
      ffi.Pointer<ffi.Void> /*conn*/,
    );
typedef _I32_SendSettings_Dart =
    int Function(ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Void>);

// ----------------------------------------------------------

String probeVoid_H3Cfg_Bool(ffi.DynamicLibrary d, String name) {
  try {
    final s = d.lookup<ffi.NativeFunction<_Void_H3Cfg_Bool_Native>>(name);
    // Verify signature mapping compiles:
    s.asFunction<_Void_H3Cfg_Dart>();
    return '✅ $name';
  } catch (e) {
    return '❌ $name  ($e)';
  }
}

String probeVoid_H3CfgOnly(ffi.DynamicLibrary d, String name) {
  try {
    final s = d.lookup<ffi.NativeFunction<_Void_H3Cfg_Only_Native>>(name);
    s.asFunction<_Void_H3Cfg_Only_Dart>();
    return '✅ $name';
  } catch (e) {
    return '❌ $name  ($e)';
  }
}

String probePtr_H3_NewWithTransport(ffi.DynamicLibrary d, String name) {
  try {
    final s = d.lookup<ffi.NativeFunction<_Ptr_H3_NewWithTransport_Native>>(
      name,
    );
    s.asFunction<_Ptr_H3_NewWithTransport_Dart>();
    return '✅ $name';
  } catch (e) {
    return '❌ $name  ($e)';
  }
}

String probeI64_H3ConnPoll(ffi.DynamicLibrary d, String name) {
  try {
    final s = d.lookup<ffi.NativeFunction<_I64_H3ConnPoll_Native>>(name);
    s.asFunction<_I64_H3ConnPoll_Dart>();
    return '✅ $name';
  } catch (e) {
    return '❌ $name  ($e)';
  }
}

String probeI32_H3EventType(ffi.DynamicLibrary d, String name) {
  try {
    final s = d.lookup<ffi.NativeFunction<_I32_H3EventType_Native>>(name);
    s.asFunction<_I32_H3EventType_Dart>();
    return '✅ $name';
  } catch (e) {
    return '❌ $name  ($e)';
  }
}

String probeI32_ForEachHeader(ffi.DynamicLibrary d, String name) {
  try {
    final s = d.lookup<ffi.NativeFunction<_I32_ForEachHeader_Native>>(name);
    s.asFunction<_I32_ForEachHeader_Dart>();
    return '✅ $name';
  } catch (e) {
    return '❌ $name  ($e)';
  }
}

String probeI32_ForEachSetting(ffi.DynamicLibrary d, String name) {
  try {
    final s = d.lookup<ffi.NativeFunction<_I32_ForEachSetting_Native>>(name);
    s.asFunction<_I32_ForEachSetting_Dart>();
    return '✅ $name';
  } catch (e) {
    return '❌ $name  ($e)';
  }
}

String probeI32_SendSettings(ffi.DynamicLibrary d, String name) {
  try {
    final s = d.lookup<ffi.NativeFunction<_I32_SendSettings_Native>>(name);
    s.asFunction<_I32_SendSettings_Dart>();
    return '✅ $name';
  } catch (e) {
    return '❌ $name  ($e)';
  }
}

void main() {
  final dllPath = 'quich/quiche.dll'; // adjust if needed
  if (!File(dllPath).existsSync()) {
    stderr.writeln(
      '❌ Cannot find $dllPath — adjust the path at the top of this script.',
    );
    exit(2);
  }

  late final ffi.DynamicLibrary dylib;
  try {
    dylib = ffi.DynamicLibrary.open(dllPath);
  } catch (e) {
    stderr.writeln('❌ Failed to open $dllPath: $e');
    exit(2);
  }

  print('🔎 Probing H3 symbols in $dllPath\n');

  final results = <String>[
    // Extended CONNECT + config free
    probeVoid_H3Cfg_Bool(dylib, 'quiche_h3_config_enable_extended_connect'),
    probeVoid_H3CfgOnly(dylib, 'quiche_h3_config_free'),

    // Create H3 from transport & poll
    probePtr_H3_NewWithTransport(dylib, 'quiche_h3_conn_new_with_transport'),
    probeI64_H3ConnPoll(dylib, 'quiche_h3_conn_poll'),

    // Event helpers
    probeI32_H3EventType(dylib, 'quiche_h3_event_type'),
    probeI32_ForEachHeader(dylib, 'quiche_h3_event_for_each_header'),
    probeI32_ForEachSetting(dylib, 'quiche_h3_for_each_setting'),

    // SETTINGS sender — try both common symbol names
    probeI32_SendSettings(dylib, 'quiche_h3_conn_send_settings'),
    probeI32_SendSettings(dylib, 'quiche_h3_send_settings'),
  ];

  for (final line in results) {
    print(line);
  }

  print(
    '\nℹ️  If exactly one of the SETTINGS symbols is ✅, use that one in your server:',
  );
  print('    - quiche_h3_conn_send_settings(h3, conn)  OR');
  print('    - quiche_h3_send_settings(h3, conn)\n');

  print('Next steps:');
  print(
    '  1) Call the found SETTINGS function immediately after quiche_h3_conn_new_with_transport().',
  );
  print('  2) Call _flush() right away so SETTINGS are sent.');
  print(
    '  3) Then handle HEADERS and reply 200 (no body) for the Extended CONNECT.',
  );
}
