import 'dart:async';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:quiche_quic/quiche_bindings.dart';

/// Debug log callback from quiche (FFI)
void debugCallback(ffi.Pointer<ffi.Char> line, ffi.Pointer<ffi.Void> argp) {
  try {
    final s = line.cast<Utf8>().toDartString();
    // Prefix quiche logs for clarity.
    print("🛠️ [QUICHE] $s");
  } catch (_) {}
}

Future<void> main() async {
  // ===== 0) Load the DLL and bind =====
  // Adjust path to your built quiche.dll as needed.
  final dylib = ffi.DynamicLibrary.open('quich/quiche.dll');
  final quiche = QuicheBindings(dylib);

  // ===== 1) Enable quiche debug logging =====
  final logCb =
      ffi.Pointer.fromFunction<
        ffi.Void Function(ffi.Pointer<ffi.Char>, ffi.Pointer<ffi.Void>)
      >(debugCallback);
  quiche.quiche_enable_debug_logging(logCb, ffi.nullptr);

  // ===== 2) QUIC config =====
  final config = quiche.quiche_config_new(1); // QUIC version 1
  if (config == ffi.nullptr) {
    print('❌ Failed to create quiche_config');
    exit(1);
  }

  // Basic flow control (tune as you like; server will clamp as needed)
  quiche.quiche_config_set_max_idle_timeout(config, 10000); // 10s
  quiche.quiche_config_set_initial_max_data(config, 10 * 1024 * 1024);
  quiche.quiche_config_set_initial_max_stream_data_bidi_local(
    config,
    1024 * 1024,
  );
  quiche.quiche_config_set_initial_max_stream_data_bidi_remote(
    config,
    1024 * 1024,
  );
  quiche.quiche_config_set_initial_max_stream_data_uni(config, 1024 * 1024);
  quiche.quiche_config_set_initial_max_streams_bidi(config, 100);
  quiche.quiche_config_set_initial_max_streams_uni(config, 100);

  // For local testing with self‑signed certs, disable peer verification.
  // DO NOT DO THIS IN PRODUCTION.
  quiche.quiche_config_verify_peer(config, false);

  // ALPN for HTTP/3: pass length-prefixed vector "\x02h3"
  final h3Proto = "\x02h3".toNativeUtf8();
  final alpnRc = quiche.quiche_config_set_application_protos(
    config,
    h3Proto.cast(),
    3,
  );
  malloc.free(h3Proto);
  if (alpnRc != 0) {
    print("❌ Failed to set application protos (ALPN)");
    exit(1);
  }

  // ===== 3) Networking (local server on 127.0.0.1:4433) =====
  final serverAddr = InternetAddress.loopbackIPv4;
  const serverPort = 4433;
  final sni = "localhost"; // SNI must match server cert/expectation

  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  print(
    '🚀 Target: ${serverAddr.address}:$serverPort | Local Port: ${socket.port}',
  );

  final localAddrPtr = _createIPv4SockAddr(socket.address.address, socket.port);
  final peerAddrPtr = _createIPv4SockAddr(serverAddr.address, serverPort);

  // Source Connection ID (arbitrary 16 bytes)
  final scid = Uint8List.fromList(List.generate(16, (i) => i));
  final scidPtr = malloc<ffi.Uint8>(16)..asTypedList(16).setAll(0, scid);

  // ===== 4) Create the QUIC connection (client) =====
  final sniPtr = sni.toNativeUtf8();
  final conn = quiche.quiche_connect(
    sniPtr.cast(), // SNI/Server name
    scidPtr,
    16,
    localAddrPtr.cast(),
    16,
    peerAddrPtr.cast(),
    16,
    config,
  );
  if (conn == ffi.nullptr) {
    print('❌ Failed to create quiche connection');
    // Clean up before exit
    malloc.free(sniPtr);
    malloc.free(scidPtr);
    malloc.free(localAddrPtr);
    malloc.free(peerAddrPtr);
    exit(1);
  }

  // We can free SNI string input after connect returns
  malloc.free(sniPtr);

  // ===== 5) Helper: pump outgoing packets =====
  void pump() {
    final outBuf = malloc<ffi.Uint8>(1500);
    final sendInfo =
        malloc<quiche_send_info>(); // real struct, not a dummy buffer
    try {
      while (true) {
        final written = quiche.quiche_conn_send(conn, outBuf, 1500, sendInfo);
        if (written <= 0) break;
        // Always send to our known peer; for more advanced path migration, parse sendInfo.ref.to
        socket.send(outBuf.asTypedList(written), serverAddr, serverPort);
        // Helpful debug:
        // print('📤 pump() sent $written bytes to ${serverAddr.address}:$serverPort');
      }
    } finally {
      malloc.free(outBuf);
      malloc.free(sendInfo);
    }
  }

  // Kick off the handshake by flushing initial packets
  pump();

  ffi.Pointer<quiche_h3_conn>? h3Conn;
  bool h3Initialized = false;

  // ===== 6) Socket receive loop =====
  socket.listen((event) {
    if (event == RawSocketEvent.read) {
      final dg = socket.receive();
      if (dg == null) return;

      final fromAddr = _createIPv4SockAddr(dg.address.address, dg.port);
      final toAddr = _createIPv4SockAddr(socket.address.address, socket.port);

      final inPtr = malloc<ffi.Uint8>(dg.data.length)
        ..asTypedList(dg.data.length).setAll(0, dg.data);
      final recvInfo = malloc<quiche_recv_info>();

      try {
        recvInfo.ref.from = fromAddr.cast();
        recvInfo.ref.from_len = 16;
        recvInfo.ref.to = toAddr.cast();
        recvInfo.ref.to_len = 16;

        quiche.quiche_conn_recv(conn, inPtr, dg.data.length, recvInfo);

        // Established?
        if (quiche.quiche_conn_is_established(conn) != 0) {
          if (!h3Initialized) {
            print("🎉 Connection Established! Launching HTTP/3...");
            final h3Config = quiche.quiche_h3_config_new();
            if (h3Config == ffi.nullptr) {
              print("❌ Failed to create h3 config");
              return;
            }
            h3Conn = quiche.quiche_h3_conn_new_with_transport(conn, h3Config);
            if (h3Conn == ffi.nullptr) {
              print("❌ Failed to create h3 connection");
              return;
            }
            h3Initialized = true;

            _sendH3Request(quiche, h3Conn!, conn);
            pump(); // push the HEADERS promptly
          }

          if (h3Conn != null) {
            _pollH3Events(quiche, h3Conn!, conn);
          }
        }

        // Always try to flush anything pending
        pump();
      } finally {
        malloc.free(inPtr);
        malloc.free(recvInfo);
        malloc.free(fromAddr);
        malloc.free(toAddr);
      }
    }
  });

  // ===== 7) Timers: handle QUIC PTO/handshake/timeouts =====
  final timer = Timer.periodic(const Duration(milliseconds: 50), (t) {
    quiche.quiche_conn_on_timeout(conn);
    pump();

    if (quiche.quiche_conn_is_closed(conn) != 0) {
      print("🔒 QUIC Closed");
      t.cancel();

      // Minimal cleanup (process exit will reclaim OS resources)
      malloc.free(scidPtr);
      malloc.free(localAddrPtr);
      malloc.free(peerAddrPtr);

      // You can also free h3/config objects when your bindings expose:
      // quiche.quiche_h3_conn_free(h3Conn);
      // quiche.quiche_h3_config_free(h3Config);
      // quiche.quiche_config_free(config);

      exit(0);
    }
  });

  // Optional: stop after some time to avoid hanging in demos
  // Future.delayed(Duration(seconds: 30), () {
  //   timer.cancel();
  //   socket.close();
  // });
}

/// Build a minimal IPv4 sockaddr_in (16 bytes) for quiche's recv/send_info.
ffi.Pointer<ffi.Uint8> _createIPv4SockAddr(String ip, int port) {
  final ptr = malloc<ffi.Uint8>(16); // sizeof(sockaddr_in)
  final view = ptr.asTypedList(16);
  view.fillRange(0, 16, 0);
  view[0] = 2; // AF_INET
  view[2] = (port >> 8) & 0xFF;
  view[3] = port & 0xFF;
  final parts = ip.split('.').map(int.parse).toList();
  for (var i = 0; i < 4; i++) {
    view[4 + i] = parts[i];
  }
  return ptr;
}

/// Send a simple GET / over HTTP/3 on a new request stream.
/// Uses :authority=localhost to match the local server.
void _sendH3Request(
  QuicheBindings quiche,
  ffi.Pointer<quiche_h3_conn> h3,
  ffi.Pointer<quiche_conn> conn,
) {
  final headers = malloc<quiche_h3_header>(4);

  // Keep pointers alive until after send_request returns.
  final List<ffi.Pointer<Utf8>> _toFree = [];

  void setH(int i, String n, String v) {
    final nPtr = n.toNativeUtf8();
    final vPtr = v.toNativeUtf8();
    _toFree.add(nPtr);
    _toFree.add(vPtr);

    headers[i].name = nPtr.cast();
    headers[i].name_len = n.length;
    headers[i].value = vPtr.cast();
    headers[i].value_len = v.length;
  }

  setH(0, ":method", "GET");
  setH(1, ":scheme", "https");
  setH(2, ":authority", "localhost"); // IMPORTANT for local server
  setH(3, ":path", "/");

  final streamId = quiche.quiche_h3_send_request(h3, conn, headers, 4, true);
  print("📤 Request Sent on Stream ID: $streamId");

  // Clean up header strings and header array after send_request returns
  for (final p in _toFree) {
    malloc.free(p);
  }
  malloc.free(headers);
}

/// Poll/consume HTTP/3 events. This implementation:
/// - Uses quiche_h3_event_type() (correct way; event struct is opaque).
/// - Prints when HEADERS/DATA/FINISH events occur.
/// - Reads body data on DATA events.
void _pollH3Events(
  QuicheBindings quiche,
  ffi.Pointer<quiche_h3_conn> h3,
  ffi.Pointer<quiche_conn> conn,
) {
  final evOut = malloc<ffi.Pointer<quiche_h3_event>>();
  try {
    while (true) {
      final streamId = quiche.quiche_h3_conn_poll(h3, conn, evOut);
      if (streamId < 0) break;

      final ev = evOut.value;
      if (ev == ffi.nullptr) continue;

      // ✅ Correct: use API, do not cast the pointer to read fields.
      // final evType = quiche.quiche_h3_event_type(ev);

      // ✅ Correct: use API, do not cast the pointer to read fields.
      final evType = quiche.quiche_h3_event_type1(ev);

      switch (evType) {
        case 0: // QUICHE_H3_EVENT_HEADERS
          print("📩 [Stream $streamId] HEADERS event");
          // If your bindings expose for_each_header, you can iterate here.
          break;

        case 1: // QUICHE_H3_EVENT_DATA
          final bodyBuf = malloc<ffi.Uint8>(8192);
          try {
            final len = quiche.quiche_h3_recv_body(
              h3,
              conn,
              streamId,
              bodyBuf,
              8192,
            );
            if (len > 0) {
              final data = bodyBuf.asTypedList(len);
              print("✅ [Stream $streamId] DATA: ${String.fromCharCodes(data)}");
            }
          } finally {
            malloc.free(bodyBuf);
          }
          break;

        case 2: // QUICHE_H3_EVENT_FINISHED
          print("🏁 [Stream $streamId] FINISHED");
          break;

        default:
          print("🔔 [Stream $streamId] H3 Event type=$evType");
      }

      quiche.quiche_h3_event_free(ev);
    }
  } finally {
    malloc.free(evOut);
  }
}
