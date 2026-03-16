import 'dart:async';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:quiche_quic/quiche_bindings.dart';

void debugCallback(ffi.Pointer<ffi.Char> line, ffi.Pointer<ffi.Void> argp) {
  print("🛠️ [QUICHE] ${line.cast<Utf8>().toDartString()}");
}

void main() async {
  final dylib = ffi.DynamicLibrary.open('quich/quiche.dll');
  final quiche = QuicheBindings(dylib);

  // 1. Enable Debug Logging
  final logCb =
      ffi.Pointer.fromFunction<
        ffi.Void Function(ffi.Pointer<ffi.Char>, ffi.Pointer<ffi.Void>)
      >(debugCallback);
  quiche.quiche_enable_debug_logging(logCb, ffi.nullptr);

  // 2. Setup Config
  final config = quiche.quiche_config_new(1); // QUIC v1
  quiche.quiche_config_set_max_idle_timeout(config, 5000);
  quiche.quiche_config_set_initial_max_data(config, 10000000);
  quiche.quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);

  // Set ALPN for Cloudflare
  final h3Proto = "\x02h3".toNativeUtf8();
  quiche.quiche_config_set_application_protos(config, h3Proto.cast(), 3);

  // 3. Resolve Endpoint
  final serverAddr = (await InternetAddress.lookup(
    'cloudflare-quic.com',
  )).first;
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  print('🚀 Connecting to ${serverAddr.address}:${socket.port}...');

  // 4. Persistent Address Pointers (Preventing GC/Access Violation)
  final localAddrPtr = _createIPv4Address(socket.address.address, socket.port);
  final peerAddrPtr = _createIPv4Address(serverAddr.address, 443);

  final scid = Uint8List.fromList(List.generate(16, (i) => i));
  final scidPtr = malloc<ffi.Uint8>(16)..asTypedList(16).setAll(0, scid);

  final conn = quiche.quiche_connect(
    "cloudflare-quic.com".toNativeUtf8().cast(),
    scidPtr,
    16,
    localAddrPtr.cast(),
    16,
    peerAddrPtr.cast(),
    16,
    config,
  );

  if (conn == ffi.nullptr) {
    print("❌ Failed to create connection");
    return;
  }

  void pump() {
    final outBuf = malloc<ffi.Uint8>(1350);
    final sendInfo = malloc<quiche_send_info>();

    while (true) {
      final written = quiche.quiche_conn_send(conn, outBuf, 1350, sendInfo);
      if (written < 0) break;
      socket.send(outBuf.asTypedList(written), serverAddr, 443);
      print("📡 UDP Sent: $written bytes");
    }
    malloc.free(outBuf);
    malloc.free(sendInfo);
  }

  socket.listen((event) {
    if (event == RawSocketEvent.read) {
      final dg = socket.receive();
      if (dg == null) return;

      // Reconstruct addresses for the incoming packet
      final fromAddr = _createIPv4Address(dg.address.address, dg.port);
      final toAddr = _createIPv4Address(socket.address.address, socket.port);

      final inPtr = malloc<ffi.Uint8>(dg.data.length)
        ..asTypedList(dg.data.length).setAll(0, dg.data);
      final recvInfo = malloc<quiche_recv_info>();

      recvInfo.ref.from = fromAddr.cast();
      recvInfo.ref.from_len = 16;
      recvInfo.ref.to = toAddr.cast();
      recvInfo.ref.to_len = 16;

      quiche.quiche_conn_recv(conn, inPtr, dg.data.length, recvInfo);

      if (quiche.quiche_conn_is_established(conn) == 1) {
        print("🎉 QUIC Handshake Established!");
      }

      pump();

      malloc.free(inPtr);
      malloc.free(recvInfo);
      malloc.free(fromAddr);
      malloc.free(toAddr);
    }
  });

  // Start Handshake
  pump();

  // Keep alive timer for retransmits
  Timer.periodic(Duration(milliseconds: 50), (t) {
    quiche.quiche_conn_on_timeout(conn);
    pump();
    if (quiche.quiche_conn_is_closed(conn) == 1) t.cancel();
  });
}

/// Creates a Windows-compatible sockaddr_in structure
ffi.Pointer<ffi.Uint8> _createIPv4Address(String ip, int port) {
  final ptr = malloc<ffi.Uint8>(16);
  final view = ptr.asTypedList(16);
  view.fillRange(0, 16, 0);

  // AF_INET is 2 on Windows
  view[0] = 2;
  view[1] = 0;

  // Port in Network Byte Order (Big Endian)
  view[2] = (port >> 8) & 0xFF;
  view[3] = port & 0xFF;

  // IP Address
  final parts = ip.split('.').map(int.parse).toList();
  for (var i = 0; i < 4; i++) {
    view[4 + i] = parts[i];
  }

  return ptr;
}
