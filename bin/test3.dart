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

  final logCb =
      ffi.Pointer.fromFunction<
        ffi.Void Function(ffi.Pointer<ffi.Char>, ffi.Pointer<ffi.Void>)
      >(debugCallback);
  quiche.quiche_enable_debug_logging(logCb, ffi.nullptr);

  final config = quiche.quiche_config_new(1);
  quiche.quiche_config_set_max_idle_timeout(config, 10000);
  quiche.quiche_config_set_initial_max_data(config, 10000000);
  quiche.quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
  quiche.quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
  quiche.quiche_config_set_initial_max_stream_data_uni(config, 1000000);
  quiche.quiche_config_set_initial_max_streams_bidi(config, 100);
  quiche.quiche_config_set_initial_max_streams_uni(config, 100);

  final h3Proto = "\x02h3".toNativeUtf8();
  quiche.quiche_config_set_application_protos(config, h3Proto.cast(), 3);

  final serverAddr = (await InternetAddress.lookup(
    'cloudflare-quic.com',
  )).first;
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  print('🚀 Target: ${serverAddr.address}:443 | Local Port: ${socket.port}');

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

  ffi.Pointer<quiche_h3_conn>? h3Conn;
  bool h3Initialized = false;

  void pump() {
    final outBuf = malloc<ffi.Uint8>(1500);
    final sendInfo = malloc<quiche_send_info>();
    while (true) {
      final written = quiche.quiche_conn_send(conn, outBuf, 1500, sendInfo);
      if (written < 0) break;
      socket.send(outBuf.asTypedList(written), serverAddr, 443);
    }
    malloc.free(outBuf);
    malloc.free(sendInfo);
  }

  socket.listen((event) {
    if (event == RawSocketEvent.read) {
      final dg = socket.receive();
      if (dg == null) return;

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

      // Try to poll H3 if it exists
      if (h3Conn != null) {
        _pollH3Events(quiche, h3Conn!, conn);
      }

      pump();
      malloc.free(inPtr);
      malloc.free(recvInfo);
      malloc.free(fromAddr);
      malloc.free(toAddr);
    }
  });

  // INITIAL PUMP to start handshake
  pump();

  // HEARTBEAT TIMER
  Timer.periodic(Duration(milliseconds: 20), (t) {
    quiche.quiche_conn_on_timeout(conn);

    // CHECK STATE REGARDLESS OF PACKETS
    if (!h3Initialized && quiche.quiche_conn_is_established(conn) == 1) {
      print("🎉 Connection Verified! Launching HTTP/3...");
      final h3Config = quiche.quiche_h3_config_new();
      h3Conn = quiche.quiche_h3_conn_new_with_transport(conn, h3Config);
      h3Initialized = true;
      _sendH3Request(quiche, h3Conn!, conn);
    }

    if (h3Conn != null) {
      _pollH3Events(quiche, h3Conn!, conn);
    }

    pump();

    if (quiche.quiche_conn_is_closed(conn) == 1) {
      print("🔒 QUIC Closed");
      t.cancel();
      exit(0);
    }
  });
}

// ... _sendH3Request and _createIPv4Address stay the same as previous response ...
void _sendH3Request(
  QuicheBindings quiche,
  ffi.Pointer<quiche_h3_conn> h3,
  ffi.Pointer<quiche_conn> conn,
) {
  final headers = malloc<quiche_h3_header>(4);
  void setH(int i, String n, String v) {
    headers[i].name = n.toNativeUtf8().cast();
    headers[i].name_len = n.length;
    headers[i].value = v.toNativeUtf8().cast();
    headers[i].value_len = v.length;
  }

  setH(0, ":method", "GET");
  setH(1, ":scheme", "https");
  setH(2, ":authority", "cloudflare-quic.com");
  setH(3, ":path", "/");

  final streamId = quiche.quiche_h3_send_request(h3, conn, headers, 4, true);
  print("📤 Request Sent on Stream ID: $streamId");
}

void _pollH3Events(
  QuicheBindings quiche,
  ffi.Pointer<quiche_h3_conn> h3,
  ffi.Pointer<quiche_conn> conn,
) {
  final evOut = malloc<ffi.Pointer<quiche_h3_event>>();

  while (true) {
    final res = quiche.quiche_h3_conn_poll(h3, conn, evOut);
    if (res < 0) break;

    final event = evOut.value;
    if (event == ffi.nullptr) continue;

    final int type = event.cast<ffi.Int32>().value;
    print("🔔 H3 Event: Type $type on Stream $res");

    if (type == 0) {
      // Headers
      print("📩 [Stream $res] Headers received");
    } else if (type == 1) {
      // Data
      final bodyBuf = malloc<ffi.Uint8>(8192);
      final len = quiche.quiche_h3_recv_body(h3, conn, res, bodyBuf, 8192);
      if (len > 0) {
        print("✅ DATA: ${String.fromCharCodes(bodyBuf.asTypedList(len))}");
      }
      malloc.free(bodyBuf);
    }
    quiche.quiche_h3_event_free(event);
  }
  malloc.free(evOut);
}

ffi.Pointer<ffi.Uint8> _createIPv4Address(String ip, int port) {
  final ptr = malloc<ffi.Uint8>(16);
  final view = ptr.asTypedList(16);
  view.fillRange(0, 16, 0);
  view[0] = 2; // AF_INET
  view[2] = (port >> 8) & 0xFF;
  view[3] = port & 0xFF;
  final parts = ip.split('.').map(int.parse).toList();
  for (var i = 0; i < 4; i++) view[4 + i] = parts[i];
  return ptr;
}
