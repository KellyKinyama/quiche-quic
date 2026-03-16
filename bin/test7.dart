import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:quiche_quic/quiche_bindings.dart';

/// ==== Constants for WebTransport over H3 (per current drafts) ====
/// First frame on a *bidi* stream: H3 frame WEBTRANSPORT_STREAM (0x41).
/// See: https://github.com/cloudflare/quiche/issues/1150
const int WT_H3_FRAME_WEBTRANSPORT_STREAM = 0x41; // varint
/// Unidirectional stream type for WebTransport (0x54).
/// See: https://github.com/ietf-wg-webtrans/draft-ietf-webtrans-http3/issues/189
const int WT_H3_UNI_STREAM_TYPE = 0x54; // varint

/// Debug log callback from quiche
void debugCallback(ffi.Pointer<ffi.Char> line, ffi.Pointer<ffi.Void> argp) {
  try {
    final s = line.cast<Utf8>().toDartString();
    print("🛠️ [QUICHE] $s");
  } catch (_) {}
}

Future<void> main() async {
  // ===== 0) Load DLL and bind =====
  final dylib = ffi.DynamicLibrary.open('quich/quiche.dll');
  final quiche = QuicheBindings(dylib);

  // ===== 1) Enable quiche debug logging =====
  final logCb =
      ffi.Pointer.fromFunction<
        ffi.Void Function(ffi.Pointer<ffi.Char>, ffi.Pointer<ffi.Void>)
      >(debugCallback);
  quiche.quiche_enable_debug_logging(logCb, ffi.nullptr);

  // ===== 2) QUIC config =====
  final config = quiche.quiche_config_new(1);
  if (config == ffi.nullptr) {
    print('❌ Failed to create quiche_config');
    exit(1);
  }

  // Lift flow control a bit for app traffic
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

  // **DATAGRAMS** ON (WebTransport datagrams use QUIC DATAGRAM frames)
  // quiche C FFI: quiche_config_enable_dgram(config, enabled, recv_q_len, send_q_len)
  quiche.quiche_config_enable_dgram(config, true, 65536, 65536);
  // (C FFI exists and is widely used, see Jetty and docs)  [3](https://javadoc.jetty.org/jetty-12/org/eclipse/jetty/quic/quiche/foreign/quiche_h.html)

  // **Disable peer verification** for local dev with self-signed certs
  quiche.quiche_config_verify_peer(config, false);

  // ALPN: HTTP/3
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

  // ===== 3) Socket / addresses =====
  final serverAddr = InternetAddress.loopbackIPv4;
  const serverPort = 4433;
  final sni = "localhost";

  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  print(
    '🚀 Target: ${serverAddr.address}:$serverPort | Local Port: ${socket.port}',
  );

  final localAddrPtr = _createIPv4SockAddr(socket.address.address, socket.port);
  final peerAddrPtr = _createIPv4SockAddr(serverAddr.address, serverPort);

  // Source Connection ID
  final scid = Uint8List.fromList(List.generate(16, (i) => i));
  final scidPtr = malloc<ffi.Uint8>(16)..asTypedList(16).setAll(0, scid);

  // ===== 4) Connect QUIC =====
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

  // ===== 5) HTTP/3 config + enable Extended CONNECT =====
  final h3Config = quiche.quiche_h3_config_new();
  if (h3Config == ffi.nullptr) {
    print("❌ quiche_h3_config_new failed");
    exit(1);
  }
  // ⚠ One of these two names will exist depending on your bindings:
  // quiche_h3_config_enable_connect_protocol(h3Config, true)
  // OR quiche_h3_config_enable_extended_connect(h3Config, true)
  // Elixir bindings expose `config_enable_extended_connect/2`.  [2](https://hexdocs.pm/quichex/Quichex.H3.html)
  try {
    // Try the first (common) variant
    // quiche.quiche_h3_config_enable_connect_protocol(h3Config, true);
    quiche.quiche_h3_config_enable_extended_connect(h3Config, true);
  } catch (_) {
    // Fallback to the alternate name if your generator used it
    try {
      quiche.quiche_h3_config_enable_extended_connect(h3Config, true);
    } catch (e) {
      print(
        "❌ Your bindings must expose H3 Extended CONNECT enable function "
        "(enable_connect_protocol / enable_extended_connect).",
      );
      exit(1);
    }
  }

  // === Pump helper ===
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

  // === Create H3 connection over the QUIC transport ===
  final h3 = quiche.quiche_h3_conn_new_with_transport(conn, h3Config);
  if (h3 == ffi.nullptr) {
    print("❌ quiche_h3_conn_new_with_transport failed");
    exit(1);
  }

  // === Some state we need for WT ===
  int? connectStreamId; // WT session id == CONNECT stream id
  // Next local client-initiated stream ids
  int nextClientUni = 2; // per QUIC: client-uni stream ids are 2,6,10,..
  int nextClientBidi = 0; // client-bidi ids are 0,4,8,..

  // === App helpers (UI-independent) ===

  // Encode QUIC varint (uses standard QUIC varint rules)
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
      // 8-byte varint (we only need up to 32-bit for stream IDs now)
      final b = ByteData(8);
      b.setUint64(0, v);
      final bytes = b.buffer.asUint8List();
      bytes[0] = 0xC0 | (bytes[0] & 0x3f);
      return bytes;
    }
  }

  // Decode QUIC varint from [data] at [offset]. Returns (value, bytesRead).
  (int, int) _varintDecode(Uint8List data, int offset) {
    final first = data[offset];
    final prefix = first >> 6;
    final len = 1 << prefix; // 1,2,4,8
    int v = first & 0x3f;
    if (len > 1) {
      for (int i = 1; i < len; i++) {
        v = (v << 8) | data[offset + i];
      }
    }
    return (v, len);
  }

  // H3: send CONNECT to create WT session at "/"
  void _sendConnect() {
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
    setH(2, ":authority", "localhost"); // for 127.0.0.1:4433
    setH(3, ":path", "/");
    setH(4, ":protocol", "webtransport");
    setH(5, "origin", "https://localhost:4433");

    final sid = quiche.quiche_h3_send_request(
      h3,
      conn,
      headers,
      6,
      false /* keep open */,
    );
    connectStreamId = sid;
    print("🌐 WT CONNECT stream opened: $sid");

    for (final p in toFree) malloc.free(p);
    malloc.free(headers);
    pump();
  }

  // === Incoming handling ===
  // Decode UTF-8 JSON quickly
  Uint8List _utf8(Map<String, dynamic> j) =>
      Uint8List.fromList(utf8.encode(jsonEncode(j)));

  // Send a WebTransport DATAGRAM with flow_id=CONNECT stream id + JSON payload
  void sendPresence(String status) {
    if (connectStreamId == null) return;
    final stanza = {
      "type": "presence",
      "data": {"from": "me", "status": status},
    };
    final payload = Uint8List.fromList(
      _varintEncode(connectStreamId!) + _utf8(stanza),
    );
    // quiche_conn_dgram_send(conn, buf, buf_len) via FFI
    final ptr = malloc<ffi.Uint8>(payload.length)
      ..asTypedList(payload.length).setAll(0, payload);
    final rc = quiche.quiche_conn_dgram_send(conn, ptr, payload.length);
    malloc.free(ptr);
    if (rc >= 0) {
      // ok
    }
  }

  // === Transport-level stream send (raw) ===
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
    if (rc < 0) {
      print("❌ stream_send rc=$rc on $streamId");
    }
    pump();
  }

  // Send a WT Uni stream (chat message) => stream type 0x54, session-id varint, JSON
  void sendChat(String from, String body, {String to = "all"}) {
    if (connectStreamId == null) return;
    final streamId = nextClientUni;
    nextClientUni += 4; // next client-uni
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

  // Send a WT Bidi IQ (sync_history) => write frame 0x41 + sid + JSON, then read reply
  Future<void> sendIqSyncHistory() async {
    if (connectStreamId == null) return;
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
    // The server replies on the same bidi stream; we'll receive it in the
    // transport-level reader below and call handleStanza().
  }

  final _encoder = Utf8Encoder();
  final _decoder = Utf8Decoder();

  void _handleStanza(Map<String, dynamic> stanza) {
    // Mirror your JS handlers; here just log
    print("📥 Stanza: $stanza");
  }

  Map<String, dynamic> _parseJson(String s) {
    // minimal JSON decode w/o imports
    return jsonDecode(s) as Map<String, dynamic>;
  }

  // Process a full WT unidirectional stream body (server->client broadcast)
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
    if (connectStreamId != null && sid != connectStreamId) {
      print("ℹ️ uni stream $streamId for different session=$sid");
      return;
    }
    final jsonBytes = body.sublist(off);
    try {
      _handleStanza(_parseJson(_decoder.convert(jsonBytes)));
    } catch (e) {
      print("⚠️ bad JSON on uni stream $streamId: $e");
    }
  }

  // Process a WT bidi frame payload (server reply to our IQ)
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
    if (connectStreamId != null && sid != connectStreamId) {
      print("ℹ️ bidi stream $streamId for different session=$sid");
      return;
    }
    final jsonBytes = body.sublist(off);
    try {
      _handleStanza(_parseJson(_decoder.convert(jsonBytes)));
    } catch (e) {
      print("⚠️ bad JSON on bidi stream $streamId: $e");
    }
  }

  // === Socket receive loop ===
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

      // QUIC established?
      if (quiche.quiche_conn_is_established(conn) != 0) {
        // If we haven't sent CONNECT yet, do it now
        if (connectStreamId == null) {
          // Create H3 (already created), send CONNECT
          _sendConnect();
        }

        // === H3 control polling: look for CONNECT response headers ===
        final evOut = malloc<ffi.Pointer<quiche_h3_event>>();
        try {
          while (true) {
            final sid = quiche.quiche_h3_conn_poll(h3, conn, evOut);
            if (sid < 0) break;
            final ev = evOut.value;
            if (ev == ffi.nullptr) continue;
            final evType = quiche.quiche_h3_event_type1(ev);
            if (evType == 0 /*HEADERS*/ ) {
              // You could iterate headers here and read :status.
              print("📩 H3 HEADERS on stream $sid");
            } else if (evType == 1 /*DATA*/ ) {
              // WT doesn’t use DATA on CONNECT stream; ignore
            } else if (evType == 2 /*FINISHED*/ ) {
              print("🏁 H3 stream $sid FINISHED");
            }
            quiche.quiche_h3_event_free(ev);
          }
        } finally {
          malloc.free(evOut);
        }

        // === DATAGRAMS: read any WT datagrams ===
        while (true) {
          final buf = malloc<ffi.Uint8>(65535);
          final rc = quiche.quiche_conn_dgram_recv(conn, buf, 65535);
          if (rc <= 0) {
            malloc.free(buf);
            break;
          }
          final data = buf.asTypedList(rc);
          // Expect: flow_id(varint) + JSON
          int off = 0;
          final (flowId, l1) = _varintDecode(data, off);
          off += l1;
          // Optionally check flowId == connectStreamId
          if (connectStreamId != null && flowId == connectStreamId) {
            final json = data.sublist(off);
            try {
              _handleStanza(_parseJson(_decoder.convert(json)));
            } catch (e) {
              print("⚠️ bad JSON in datagram: $e");
            }
          }
          malloc.free(buf);
        }

        // === RAW STREAMS: read uni/bidi payloads for WT ===
        while (true) {
          final next = quiche.quiche_conn_stream_readable_next(conn);
          if (next < 0) break;
          final sid = next; // 64-bit, fits in Dart int
          // Pull all bytes available
          final accum = BytesBuilder();
          final tmp = malloc<ffi.Uint8>(65535);
          bool fin = false;
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
            if (rc > 0) {
              accum.add(tmp.asTypedList(rc));
            }
            fin = fin || (finPtr.value != 0);
            malloc.free(finPtr);
            if (isDone) break;
          }
          malloc.free(tmp);

          // Ignore CONNECT control stream payloads if any
          if (connectStreamId != null && sid == connectStreamId) {
            continue;
          }

          final bytes = accum.takeBytes();
          final isServerUni = (sid & 0x3) == 0x3; // server-initiated uni
          if (isServerUni) {
            _processIncomingUni(sid, bytes);
          } else {
            // Could be our bidi IQ stream reply
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

  // Timer for PTO/handshake
  Timer.periodic(const Duration(milliseconds: 50), (t) {
    quiche.quiche_conn_on_timeout(conn);
    pump();
    if (quiche.quiche_conn_is_closed(conn) != 0) {
      print("🔒 QUIC Closed");
      t.cancel();
      // Minimal cleanup
      malloc.free(scidPtr);
      malloc.free(localAddrPtr);
      malloc.free(peerAddrPtr);
      exit(0);
    }
  });

  // === Example usage (mirror your JS buttons) ===
  // After a small delay, ask history and simulate typing on presence
  Future.delayed(const Duration(seconds: 1), () {
    sendPresence("online");
    sendPresence("typing...");
    Future.delayed(const Duration(seconds: 2), () => sendPresence("online"));
    sendIqSyncHistory();
    // sendChat("Guest", "Hello from Dart WT client!");
  });
}

/// sockaddr_in builder (16 bytes) for quiche FFI
ffi.Pointer<ffi.Uint8> _createIPv4SockAddr(String ip, int port) {
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

String _uuid() => (DateTime.now().microsecondsSinceEpoch).toString();
