import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:quiche_quic/quiche_bindings.dart';

/// ==== Constants for WebTransport over H3 ====
/// Bidi first frame type: WEBTRANSPORT_STREAM (0x41).
const int WT_H3_FRAME_WEBTRANSPORT_STREAM = 0x41; // varint
/// Unidirectional stream type: 0x54.
const int WT_H3_UNI_STREAM_TYPE = 0x54; // varint

void debugCallback(ffi.Pointer<ffi.Char> line, ffi.Pointer<ffi.Void> argp) {
  try {
    final s = line.cast<Utf8>().toDartString();
    print("🛠️ [QUICHE] $s");
  } catch (_) {}
}

// ---- H3 header callback typedefs (for printing & capturing :status) ----
// quiche_h3_event_for_each_header expects (name_ptr, name_len, value_ptr, value_len, arg)
typedef H3HeaderCbNative =
    ffi.Int Function(
      ffi.Pointer<ffi.Uint8>,
      ffi.Size,
      ffi.Pointer<ffi.Uint8>,
      ffi.Size,
      ffi.Pointer<ffi.Void>,
    );

int _printAndCaptureStatusCb(
  ffi.Pointer<ffi.Uint8> namePtr,
  int nameLen,
  ffi.Pointer<ffi.Uint8> valuePtr,
  int valueLen,
  ffi.Pointer<ffi.Void> arg,
) {
  final name = namePtr.cast<Utf8>().toDartString(length: nameLen);
  final value = valuePtr.cast<Utf8>().toDartString(length: valueLen);
  print('🔎  $name: $value');
  // Capture :status into the int* passed as arg (if provided)
  if (name == ':status' && arg != ffi.nullptr) {
    final ip = arg.cast<ffi.Int32>();
    final parsed = int.tryParse(value) ?? 0;
    ip.value = parsed;
  }
  return 0;
}

Future<void> main() async {
  // 0) Load and bind
  final dylib = ffi.DynamicLibrary.open('quich/quiche.dll');
  final quiche = QuicheBindings(dylib);

  // 1) Debug logs
  final logCb =
      ffi.Pointer.fromFunction<
        ffi.Void Function(ffi.Pointer<ffi.Char>, ffi.Pointer<ffi.Void>)
      >(debugCallback);
  quiche.quiche_enable_debug_logging(logCb, ffi.nullptr);

  // 2) QUIC config
  final config = quiche.quiche_config_new(1);
  if (config == ffi.nullptr) {
    print('❌ Failed to create quiche_config');
    exit(1);
  }
  quiche.quiche_config_set_max_idle_timeout(config, 10000);
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

  // QUIC DATAGRAMs (needed for WT datagrams).
  quiche.quiche_config_enable_dgram(config, true, 65536, 65536);

  // Disable verification (dev only).
  quiche.quiche_config_verify_peer(config, false);

  // ALPN h3
  final h3Proto = "\x02h3".toNativeUtf8();
  final alpnRc = quiche.quiche_config_set_application_protos(
    config,
    h3Proto.cast(),
    3,
  );
  malloc.free(h3Proto);
  if (alpnRc != 0) {
    print("❌ Failed to set ALPN");
    exit(1);
  }

  // 3) Socket/addresses
  final serverAddr = InternetAddress.loopbackIPv4; // 127.0.0.1
  const serverPort = 4433;
  final sni = "localhost"; // keep SNI as-is (verification disabled)

  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  print(
    '🚀 Target: ${serverAddr.address}:$serverPort | Local Port: ${socket.port}',
  );

  final localAddrPtr = _createIPv4SockAddr(socket.address.address, socket.port);
  final peerAddrPtr = _createIPv4SockAddr(serverAddr.address, serverPort);

  final scid = Uint8List.fromList(List.generate(16, (i) => i));
  final scidPtr = malloc<ffi.Uint8>(16)..asTypedList(16).setAll(0, scid);

  // 4) Connect QUIC
  final sniPtr = sni.toNativeUtf8();
  final conn = quiche.quiche_connect(
    sniPtr.cast(),
    scidPtr,
    16,
    localAddrPtr.cast(),
    16,
    peerAddrPtr.cast(),
    16,
    config,
  );
  malloc.free(sniPtr);
  if (conn == ffi.nullptr) {
    print('❌ quiche_connect failed');
    exit(1);
  }

  // 5) H3 config + Extended CONNECT
  final h3Config = quiche.quiche_h3_config_new();
  if (h3Config == ffi.nullptr) {
    print("❌ quiche_h3_config_new failed");
    exit(1);
  }
  // Try both function names; different bindings expose one or the other.
  bool extConnectEnabled = false;
  try {
    quiche.quiche_h3_config_enable_extended_connect(h3Config, true);
    extConnectEnabled = true;
  } catch (_) {
    try {
      quiche.quiche_h3_config_enable_extended_connect(h3Config, true);
      extConnectEnabled = true;
    } catch (_) {}
  }
  if (!extConnectEnabled) {
    print("❌ Missing H3 Extended CONNECT enable function in your bindings.");
    exit(1);
  }
  

  // Pump helper
  void pump() {
    final outBuf = malloc<ffi.Uint8>(1500);
    final sendInfo = malloc<quiche_send_info>();
    try {
      while (true) {
        final written = quiche.quiche_conn_send(conn, outBuf, 1500, sendInfo);
        if (written <= 0) break;
        socket.send(outBuf.asTypedList(written), serverAddr, serverPort);
      }
    } finally {
      malloc.free(outBuf);
      malloc.free(sendInfo);
    }
  }

  pump();

  // === Defer H3 creation until QUIC established (IMPORTANT) ===
  ffi.Pointer<quiche_h3_conn>? h3;

  // WT state
  int? connectStreamId; // session id (CONNECT stream)
  int nextClientUni = 2; // client uni ids: 2,6,10...
  int nextClientBidi =
      4; // client bidi ids: 0,4,8... (0 is CONNECT -> start at 4)
  bool wtReady = false;

  // Varint helpers
  Uint8List _varintEncode(int v) {
    if (v < 0) throw ArgumentError('varint negative');
    if (v < (1 << 6)) {
      return Uint8List.fromList([v & 0x3f]);
    } else if (v < (1 << 14)) {
      return Uint8List.fromList([0x40 | ((v >> 8) & 0x3f), v & 0xff]);
    } else if (v < (1 << 30)) {
      return Uint8List.fromList([
        0x80 | ((v >> 24) & 0x3f),
        (v >> 16) & 0xff,
        (v >> 8) & 0xff,
        v & 0xff,
      ]);
    } else {
      final b = ByteData(8)..setUint64(0, v);
      final bytes = b.buffer.asUint8List();
      bytes[0] = 0xC0 | (bytes[0] & 0x3f);
      return bytes;
    }
  }

  (int, int) _varintDecode(Uint8List data, int offset) {
    final first = data[offset];
    final prefix = first >> 6;
    final len = 1 << prefix; // 1,2,4,8
    int v = first & 0x3f;
    for (int i = 1; i < len; i++) {
      v = (v << 8) | data[offset + i];
    }
    return (v, len);
  }

  // JSON helpers
  Uint8List _utf8(Map<String, dynamic> j) =>
      Uint8List.fromList(utf8.encode(jsonEncode(j)));
  final _decoder = Utf8Decoder();

  // Send CONNECT to create WT session
  void _sendConnect(ffi.Pointer<quiche_h3_conn> h3) {
    final headers = malloc<quiche_h3_header>(6);
    final toFree = <ffi.Pointer<Utf8>>[];

    void setH(int i, String n, String v) {
      final nPtr = n.toNativeUtf8();
      final vPtr = v.toNativeUtf8();
      toFree
        ..add(nPtr)
        ..add(vPtr);
      headers[i].name = nPtr.cast();
      headers[i].name_len = n.length;
      headers[i].value = vPtr.cast();
      headers[i].value_len = v.length;
    }

    setH(0, ":method", "CONNECT");
    setH(1, ":scheme", "https");
    // Match listener exactly (authority + origin) to avoid routing mismatches.
    setH(2, ":authority", "127.0.0.1:4433");
    setH(3, ":path", "/");
    setH(4, ":protocol", "webtransport");
    setH(5, "origin", "https://127.0.0.1:4433");

    final sid = quiche.quiche_h3_send_request(
      h3,
      conn,
      headers,
      6,
      false /* keep open */,
    );
    connectStreamId = sid;
    print("🌐 WT CONNECT stream opened: $sid");

    for (final p in toFree) {
      malloc.free(p);
    }
    malloc.free(headers);
    pump();
  }

  // Stream send (transport-level)
  void _sendStream(int streamId, Uint8List data, {required bool fin}) {
    final ptr = malloc<ffi.Uint8>(data.length)
      ..asTypedList(data.length).setAll(0, data);
    final rc = quiche.quiche_conn_stream_send(
      conn,
      streamId,
      ptr,
      data.length,
      fin,
      ffi.nullptr,
    );
    malloc.free(ptr);
    if (rc < 0) print("❌ stream_send rc=$rc on $streamId");
    pump();
  }

  // Presence via DATAGRAM (flow id = CONNECT stream id).
  void sendPresence(String status) {
    if (!wtReady || connectStreamId == null) return;
    final stanza = {
      "type": "presence",
      "data": {"from": "me", "status": status},
    };
    final payload = Uint8List.fromList(
      _varintEncode(connectStreamId!) + _utf8(stanza),
    );
    final ptr = malloc<ffi.Uint8>(payload.length)
      ..asTypedList(payload.length).setAll(0, payload);
    final rc = quiche.quiche_conn_dgram_send(conn, ptr, payload.length);
    malloc.free(ptr);
    if (rc < 0) {
      // If rc == QUICHE_ERR_DONE or H3 DATAGRAM not negotiated, silently ignore.
    }
  }

  // Chat (client-uni): 0x54 + session-id + JSON.
  void sendChat(String from, String body, {String to = "all"}) {
    if (!wtReady || connectStreamId == null) return;
    final streamId = nextClientUni;
    nextClientUni += 4;
    final msg = {
      "type": "message",
      "data": {"id": _uuid(), "to": to, "from": from, "body": body},
    };
    final content = Uint8List.fromList(
      _varintEncode(WT_H3_UNI_STREAM_TYPE) +
          _varintEncode(connectStreamId!) +
          _utf8(msg),
    );
    _sendStream(streamId, content, fin: true);
    print("📤 Uni message on stream $streamId");
  }

  // IQ (client-bidi): 0x41 + session-id + JSON.
  Future<void> sendIqSyncHistory() async {
    if (!wtReady || connectStreamId == null) return;
    final streamId = nextClientBidi;
    nextClientBidi += 4;
    final iq = {
      "type": "iq",
      "data": {"id": _uuid(), "action": "sync_history", "payload": "{}"},
    };
    final content = Uint8List.fromList(
      _varintEncode(WT_H3_FRAME_WEBTRANSPORT_STREAM) +
          _varintEncode(connectStreamId!) +
          _utf8(iq),
    );
    _sendStream(streamId, content, fin: true);
    print("📤 Bidi IQ request on stream $streamId");
  }

  void _handleStanza(Map<String, dynamic> stanza) {
    print("📥 Stanza: $stanza");
  }

  void _processIncomingUni(int streamId, Uint8List body) {
    int off = 0;
    final (stType, l1) = _varintDecode(body, off);
    off += l1;
    if (stType != WT_H3_UNI_STREAM_TYPE) {
      print("ℹ️ uni stream $streamId unknown type=$stType");
      return;
    }
    final (sid, l2) = _varintDecode(body, off);
    off += l2;
    if (connectStreamId != null && sid != connectStreamId) return;
    final jsonBytes = body.sublist(off);
    try {
      _handleStanza(jsonDecode(_decoder.convert(jsonBytes)));
    } catch (e) {
      print("⚠️ bad JSON on uni stream $streamId: $e");
    }
  }

  void _processIncomingBidi(int streamId, Uint8List body) {
    int off = 0;
    final (ftype, l1) = _varintDecode(body, off);
    off += l1;
    if (ftype != WT_H3_FRAME_WEBTRANSPORT_STREAM) {
      print("ℹ️ bidi stream $streamId unknown frame=$ftype");
      return;
    }
    final (sid, l2) = _varintDecode(body, off);
    off += l2;
    if (connectStreamId != null && sid != connectStreamId) return;
    final jsonBytes = body.sublist(off);
    try {
      _handleStanza(jsonDecode(_decoder.convert(jsonBytes)));
    } catch (e) {
      print("⚠️ bad JSON on bidi stream $streamId: $e");
    }
  }

  // 6) Socket receive loop
  socket.listen((event) {
    if (event != RawSocketEvent.read) return;
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

      // Once handshake done, create H3 and send CONNECT (once)
      if (quiche.quiche_conn_is_established(conn) != false) {
        if (h3 == null) {
          final h3Ptr = quiche.quiche_h3_conn_new_with_transport(
            conn,
            h3Config,
          );
          if (h3Ptr == ffi.nullptr) {
            print("❌ quiche_h3_conn_new_with_transport failed");
            return;
          }
          h3 = h3Ptr;
        }
        if (connectStreamId == null) {
          _sendConnect(h3!);
        }

        // H3 control polling (e.g., CONNECT response)
        final evOut = malloc<ffi.Pointer<quiche_h3_event>>();
        try {
          while (true) {
            final sid = quiche.quiche_h3_conn_poll(h3!, conn, evOut);
            if (sid < 0) break;
            final ev = evOut.value;
            if (ev == ffi.nullptr) continue;
            final evType = quiche.quiche_h3_event_type1(ev);
            if (evType == 0) {
              print("📩 H3 HEADERS on stream $sid");

              // Try to dump and capture :status (not all bindings have this symbol)
              try {
                final statusPtr = malloc<ffi.Int32>();
                statusPtr.value = 0;
                final cbPtr = ffi.Pointer.fromFunction<H3HeaderCbNative>(
                  _printAndCaptureStatusCb,
                  0,
                );
                quiche.quiche_h3_event_for_each_header(
                  ev,
                  cbPtr,
                  statusPtr.cast(),
                );
                final status = statusPtr.value;
                malloc.free(statusPtr);
                if (sid == connectStreamId && status >= 200 && status < 300) {
                  if (!wtReady) {
                    wtReady = true;
                    print("✅ WebTransport CONNECT accepted (status=$status)");
                  }
                }
              } catch (_) {
                // If for_each_header is not available, leave wtReady as-is.
              }
            } else if (evType == 1) {
              // DATA on CONNECT stream implies rejection; ignore body here.
            } else if (evType == 2) {
              print("🏁 H3 stream $sid FINISHED");
            }
            quiche.quiche_h3_event_free(ev);
          }
        } finally {
          malloc.free(evOut);
        }

        // DATAGRAMS (flow id + json).
        while (true) {
          final buf = malloc<ffi.Uint8>(65535);
          final rc = quiche.quiche_conn_dgram_recv(conn, buf, 65535);
          if (rc <= 0) {
            malloc.free(buf);
            break;
          }
          final data = buf.asTypedList(rc);
          int off = 0;
          final (flowId, l1) = _varintDecode(data, off);
          off += l1;
          if (wtReady && connectStreamId != null && flowId == connectStreamId) {
            final json = data.sublist(off);
            try {
              _handleStanza(jsonDecode(_decoder.convert(json)));
            } catch (e) {
              print("⚠️ bad JSON in datagram: $e");
            }
          }
          malloc.free(buf);
        }

        // RAW streams (WT uni/bidi payloads)
        while (true) {
          final next = quiche.quiche_conn_stream_readable_next(conn);
          if (next < 0) break;
          final sid = next;
          final accum = BytesBuilder();
          final tmp = malloc<ffi.Uint8>(65535);
          while (true) {
            final finPtr = malloc<ffi.Uint8>(1);
            final rc = quiche.quiche_conn_stream_recv(
              conn,
              sid,
              tmp,
              65535,
              finPtr.cast(),
              ffi.nullptr,
            );
            final isDone = rc == -1; // QUICHE_ERR_DONE
            if (rc > 0) accum.add(tmp.asTypedList(rc));
            malloc.free(finPtr);
            if (isDone) break;
          }
          malloc.free(tmp);

          // Skip raw reads of the CONNECT stream itself.
          if (connectStreamId != null && sid == connectStreamId) continue;

          final bytes = accum.takeBytes();
          final isServerUni = (sid & 0x3) == 0x3;
          if (isServerUni) {
            _processIncomingUni(sid, bytes);
          } else {
            _processIncomingBidi(sid, bytes);
          }
        }
      }

      pump();
    } finally {
      malloc.free(inPtr);
      malloc.free(recvInfo);
      malloc.free(fromAddr);
      malloc.free(toAddr);
    }
  });

  // Timeout timer
  Timer.periodic(const Duration(milliseconds: 50), (t) {
    quiche.quiche_conn_on_timeout(conn);
    pump();
    if (quiche.quiche_conn_is_closed(conn) != false) {
      print("🔒 QUIC Closed");
      t.cancel();
      malloc.free(scidPtr);
      malloc.free(localAddrPtr);
      malloc.free(peerAddrPtr);
      exit(0);
    }
  });

  // Demo actions (send only after WT is accepted)
  bool demoSent = false;
  Timer.periodic(const Duration(milliseconds: 250), (timer) {
    if (wtReady && !demoSent) {
      demoSent = true;
      // Presence
      sendPresence("online");
      sendPresence("typing...");
      Future.delayed(const Duration(seconds: 2), () => sendPresence("online"));
      // IQ + chat
      sendIqSyncHistory();
      sendChat("Guest", "Hello from Dart WT client!");
      timer.cancel();
    }
  });
}

ffi.Pointer<ffi.Uint8> _createIPv4SockAddr(String ip, int port) {
  final ptr = malloc<ffi.Uint8>(16);
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

String _uuid() => (DateTime.now().microsecondsSinceEpoch).toString();
