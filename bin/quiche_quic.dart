import 'dart:async';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
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

    quiche.quiche_config_log_keys(config);
    quiche.quiche_config_enable_early_data(config);
    quiche.quiche_config_enable_dgram(config, true, 1000, 1000);
    quiche.quiche_config_enable_hystart(config, false);

    print('🚀 Initializing QUIC Connection...');

    // 3. Generate SCID
    final scid = Uint8List.fromList(
      List.generate(16, (_) => Random().nextInt(256)),
    );
    final scidPtr = calloc<ffi.Uint8>(scid.length);
    scidPtr.asTypedList(scid.length).setAll(0, scid);

    // 4. PREVENT CRASH: Allocate memory for sockaddr structures
    // Quiche internals need to see a valid memory address even for "empty" locations
    // 4. Properly initialize sockaddr_in for IPv4 (AF_INET = 2)
    final localAddrPtr = calloc<ffi.Uint8>(
      16,
    ); // 16 bytes is standard for sockaddr_in
    final peerAddrPtr = calloc<ffi.Uint8>(16);

    // Set Address Family to 2 (AF_INET)
    // Byte order depends on architecture, but for family, it's usually the first short
    localAddrPtr.asTypedList(16)[0] = 2;
    peerAddrPtr.asTypedList(16)[0] = 2;

    print('🚀 Initializing QUIC Connection...');

    // 5. Create Connection
    final conn = quiche.quiche_connect(
      "localhost".toNativeUtf8().cast<ffi.Char>(),
      scidPtr,
      scid.length,
      localAddrPtr.cast(),
      16, // The length must be 16 for IPv4
      peerAddrPtr.cast(),
      16,
      config,
    );

    if (conn == ffi.nullptr) {
      print('❌ Failed to create Quiche connection');
      return;
    }

    // 6. Setup UDP Socket
    final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    final serverAddr = InternetAddress.loopbackIPv4;
    const serverPort = 4433;

    print('📡 UDP Socket bound to port ${socket.port}');

    // 7. Timer for QUIC timeouts (Crucial for handshake progression)
    Timer.periodic(Duration(milliseconds: 50), (timer) {
      quiche.quiche_conn_on_timeout(conn);
      _flushOutgoing(quiche, conn, socket, serverAddr, serverPort);

      if (quiche.quiche_conn_is_closed(conn)) {
        print('🔒 Connection Closed');
        timer.cancel();
      }
    });

    // 8. Flush initial handshake packet
    _flushOutgoing(quiche, conn, socket, serverAddr, serverPort);

    // 9. Network Listener
    socket.listen((event) {
      if (event == RawSocketEvent.read) {
        final dg = socket.receive();
        if (dg == null) return;

        final inPtr = calloc<ffi.Uint8>(dg.data.length);
        inPtr.asTypedList(dg.data.length).setAll(0, dg.data);

        final recvCount = quiche.quiche_conn_recv(
          conn,
          inPtr,
          dg.data.length,
          localAddrPtr.cast(), // Pass valid address buffer
          // 16,
        );

        calloc.free(inPtr);

        if (recvCount < 0) {
          print('⚠️ Quiche recv error: $recvCount');
        } else {
          print('📥 Processed $recvCount bytes from network');
        }

        _flushOutgoing(quiche, conn, socket, serverAddr, serverPort);
      }
    });

    print('⏳ Running... (Press Ctrl+C to stop)');

    // final conn = quiche.quiche_accept(
    //   scid,
    //   scid_len,
    //   odcid,
    //   odcid_len,
    //   local,
    //   local_len,
    //   peer,
    //   peer_len,
    //   config,
    // );
  } catch (e) {
    print('💥 Exception during config setup: $e');
  }
}

void _flushOutgoing(
  QuicheBindings quiche,
  ffi.Pointer<quiche_conn> conn,
  RawDatagramSocket socket,
  InternetAddress addr,
  int port,
) {
  final outBuf = calloc<ffi.Uint8>(1350);
  // Temporary buffer for recv_info/send_info if your bindings require them
  final sendInfoPtr = calloc<ffi.Uint8>(128);

  while (true) {
    // Note: check your generated bindings.
    // If quiche_conn_send has 4 or 5 arguments, ensure they match here.
    final written = quiche.quiche_conn_send(
      conn,
      outBuf,
      1350,
      sendInfoPtr.cast(),
    );

    if (written <= 0) break;

    socket.send(outBuf.asTypedList(written), addr, port);
    print('📤 Sent $written bytes (QUIC Packet) to $addr:$port');
  }

  calloc.free(outBuf);
  calloc.free(sendInfoPtr);
}
