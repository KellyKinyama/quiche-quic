// dart run bin/test11.dart
import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:quiche_quic/quiche_bindings.dart';

/// ================= WebTransport client settings =================
/// Match your server's routing. Path can include a query (server should accept it).
const String WT_PATH = "/?secret=xoq_secret_2026";
const String WT_AUTH = "localhost:4433"; // :authority (host:port)
const String WT_ORIGIN = "https://localhost:4433"; // Origin header (dev/demo)

/// WT framing constants
const int WT_H3_FRAME_WEBTRANSPORT_STREAM = 0x41; // bidi frame type
const int WT_H3_UNI_STREAM_TYPE = 0x54; // uni stream type

/// ================= Debug logging =================
void debugCallback(ffi.Pointer<ffi.Char> line, ffi.Pointer<ffi.Void> argp) {
  try {
    final s = line.cast<Utf8>().toDartString();
    print("🛠️ [QUICHE] $s");
  } catch (_) {}
}

/// H3 header callback typedef for for_each_header
typedef H3HeaderCbNative =
    ffi.Int Function(
      ffi.Pointer<ffi.Uint8>,
      ffi.Size, // name, name_len
      ffi.Pointer<ffi.Uint8>,
      ffi.Size, // value, value_len
      ffi.Pointer<ffi.Void>, // arg
    );

/// Prints headers and captures :status into arg (an Int32*), if provided.
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
  if (name == ':status' && arg != ffi.nullptr) {
    final ip = arg.cast<ffi.Int32>();
    ip.value = int.tryParse(value) ?? 0;
  }
  return 0;
}

/// ================= Helpers: varint / json / sockaddr =================
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
  for (int i = 1; i < len; i++) v = (v << 8) | data[offset + i];
  return (v, len);
}

Uint8List _utf8(Map<String, dynamic> j) =>
    Uint8List.fromList(utf8.encode(jsonEncode(j)));

ffi.Pointer<ffi.Uint8> _createIPv4SockAddr(String ip, int port) {
  final ptr = malloc<ffi.Uint8>(16);
  final view = ptr.asTypedList(16)..fillRange(0, 16, 0);
  view[0] = 2; // AF_INET
  view[2] = (port >> 8) & 0xFF;
  view[3] = port & 0xFF;
  final parts = ip.split('.').map(int.parse).toList();
  for (var i = 0; i < 4; i++) view[4 + i] = parts[i] & 0xFF;
  return ptr;
}

String _uuid() => DateTime.now().microsecondsSinceEpoch.toString();

/// ================= MAIN =================
Future<void> main() async {
  // --- Load quiche + enable debug ---
  final dylib = ffi.DynamicLibrary.open('quich/quiche.dll');
  final quiche = QuicheBindings(dylib);
  final logCb =
      ffi.Pointer.fromFunction<
        ffi.Void Function(ffi.Pointer<ffi.Char>, ffi.Pointer<ffi.Void>)
      >(debugCallback);
  quiche.quiche_enable_debug_logging(logCb, ffi.nullptr);

  // --- QUIC config (client) ---
  final config = quiche.quiche_config_new(1);
  if (config == ffi.nullptr) {
    print('❌ Failed to create quiche_config');
    exit(1);
  }

  // Transport & flow control
  quiche.quiche_config_set_max_idle_timeout(config, 60000);
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

  // *** CRITICAL: allow server to open control/QPACK/GREASE streams (+ app) ***
  quiche.quiche_config_set_initial_max_streams_bidi(config, 100);
  quiche.quiche_config_set_initial_max_streams_uni(config, 100);

  // QUIC DATAGRAM transport capability; H3 layer is negotiated later
  quiche.quiche_config_enable_dgram(config, true, 65536, 65536);

  // DEV: disable certificate verification for local self-signed testing
  quiche.quiche_config_verify_peer(config, false);

  // ALPN: "h3"
  final alpn = "\x02h3".toNativeUtf8();
  final alpnRc = quiche.quiche_config_set_application_protos(
    config,
    alpn.cast(),
    3,
  );
  malloc.free(alpn);
  if (alpnRc != 0) {
    print("❌ Failed to set ALPN");
    exit(1);
  }

  // --- UDP socket ---
  final serverAddr = InternetAddress.loopbackIPv4; // 127.0.0.1
  const serverPort = 4433;
  final sni = "localhost";
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  print(
    '🚀 Target: ${serverAddr.address}:$serverPort | Local Port: ${socket.port}',
  );

  final localAddrPtr = _createIPv4SockAddr(socket.address.address, socket.port);
  final peerAddrPtr = _createIPv4SockAddr(serverAddr.address, serverPort);

  // --- QUIC connect ---
  final scid = Uint8List.fromList(List.generate(16, (i) => i));
  final scidPtr = malloc<ffi.Uint8>(16)..asTypedList(16).setAll(0, scid);
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

  // --- H3 config (once); enable Extended CONNECT ---
  final h3Config = quiche.quiche_h3_config_new();
  if (h3Config == ffi.nullptr) {
    print("❌ quiche_h3_config_new failed");
    exit(1);
  }
  try {
    quiche.quiche_h3_config_enable_extended_connect(h3Config, true);
  } catch (_) {
    print("❌ This quiche build lacks Extended CONNECT enable symbol");
    exit(1);
  }

  // --- Send pump helper ---
  void pump() {
    final outBuf = malloc<ffi.Uint8>(1500);
    final sendInfo = malloc<quiche_send_info>();
    try {
      while (true) {
        final n = quiche.quiche_conn_send(conn, outBuf, 1500, sendInfo);
        if (n <= 0) break;
        socket.send(outBuf.asTypedList(n), serverAddr, serverPort);
      }
    } finally {
      malloc
        ..free(outBuf)
        ..free(sendInfo);
    }
  }

  // Kick the first flight
  pump();

  // --- WT state ---
  ffi.Pointer<quiche_h3_conn>? h3;
  int? connectStreamId; // WT session id (CONNECT stream)
  int nextClientUni = 2; // client uni ids: 2,6,10,...
  int nextClientBidi = 4; // client bidi ids: 0,4,8,... (0 used by CONNECT)
  bool wtReady = false;
  bool h3DgramByPeer = false;

  // --- CONNECT sender ---
  void _sendConnect(ffi.Pointer<quiche_h3_conn> h3c) {
    // We may include the legacy draft header; allocate 7 if used, else 6.
    const includeDraftHeader = true;
    final count = includeDraftHeader ? 7 : 6;
    final headers = malloc<quiche_h3_header>(count);
    final toFree = <ffi.Pointer<Utf8>>[];

    void setH(int i, String n, String v) {
      final nPtr = n.toNativeUtf8(), vPtr = v.toNativeUtf8();
      toFree
        ..add(nPtr)
        ..add(vPtr);
      headers[i].name = nPtr.cast();
      headers[i].name_len = n.length; // ASCII names: byte length == char length
      headers[i].value = vPtr.cast();
      headers[i].value_len = v.length;
    }

    setH(0, ":method", "CONNECT");
    setH(1, ":scheme", "https");
    setH(2, ":authority", WT_AUTH);
    setH(3, ":path", WT_PATH);
    setH(4, ":protocol", "webtransport");
    setH(5, "origin", WT_ORIGIN);
    if (includeDraftHeader) {
      setH(6, "sec-webtransport-http3-draft", "draft02");
    }

    final sid = quiche.quiche_h3_send_request(
      h3c,
      conn,
      headers,
      count,
      false /* no FIN: CONNECT stays open */,
    );
    connectStreamId = sid;
    print("🌐 WT CONNECT stream opened: $sid");

    for (final p in toFree) malloc.free(p);
    malloc.free(headers);
    pump(); // ensure CONNECT goes out immediately
  }

  // --- Raw stream sender ---
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

  // --- Presence via DATAGRAM (if negotiated), else fallback to WT UNI ---
  void sendPresence(String status) {
    if (!wtReady || connectStreamId == null) return;
    final stanza = {
      "type": "presence",
      "data": {"from": "me", "status": status},
    };
    if (h3DgramByPeer) {
      final payload = Uint8List.fromList(
        _varintEncode(connectStreamId!) + _utf8(stanza),
      );
      final ptr = malloc<ffi.Uint8>(payload.length)
        ..asTypedList(payload.length).setAll(0, payload);
      final rc = quiche.quiche_conn_dgram_send(conn, ptr, payload.length);
      malloc.free(ptr);
      if (rc < 0) print("⚠️ dgram_send rc=$rc");
    } else {
      // Fallback: WT uni stream (0x54 + session-id + JSON)
      final streamId = nextClientUni;
      nextClientUni += 4;
      final content = Uint8List.fromList(
        _varintEncode(WT_H3_UNI_STREAM_TYPE) +
            _varintEncode(connectStreamId!) +
            _utf8(stanza),
      );
      _sendStream(streamId, content, fin: true);
      print("📤 Presence fallback via UNI $streamId");
    }
  }

  // Simple chat via WT UNI
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
    print("📤 Chat UNI on $streamId");
  }

  // Example IQ via WT BIDI
  void sendIqSyncHistory() {
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
    print("📤 BIDI IQ on $streamId");
  }

  // Incoming stanza printer
  final _decoder = Utf8Decoder();
  void _handleStanza(Map<String, dynamic> stanza) {
    print("📥 Stanza: $stanza");
  }

  void _processIncomingUni(int streamId, Uint8List body) {
    int off = 0;
    final (frameType, l1) = _varintDecode(body, off);
    off += l1;
    if (frameType != WT_H3_UNI_STREAM_TYPE) {
      print("ℹ️ uni stream $streamId unknown type=$frameType");
      return;
    }
    final (sid, l2) = _varintDecode(body, off);
    off += l2;
    if (connectStreamId != null && sid != connectStreamId) return;
    final jsonBytes = body.sublist(off);
    try {
      _handleStanza(jsonDecode(_decoder.convert(jsonBytes)));
    } catch (e) {
      print("⚠️ bad JSON on uni $streamId: $e");
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
      print("⚠️ bad JSON on bidi $streamId: $e");
    }
  }

  // --- UDP receive loop ---
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

      // When QUIC established, create H3 and send CONNECT (once)
      if (quiche.quiche_conn_is_established(conn) != false) {
        if (h3 == null) {
          final h3Ptr = quiche.quiche_h3_conn_new_with_transport(
            conn,
            h3Config,
          );
          if (h3Ptr == ffi.nullptr) {
            // Not ready yet; next packet will retry
          } else {
            h3 = h3Ptr;
            // Check H3 DATAGRAM capability immediately (may flip later after SETTINGS)
            try {
              h3DgramByPeer = quiche.quiche_h3_dgram_enabled_by_peer(h3!, conn);
              print('ℹ️ H3 DATAGRAM by peer: $h3DgramByPeer');
            } catch (_) {}
          }
        }

        if (h3 != null && connectStreamId == null) {
          _sendConnect(h3!);
        }

        // Poll H3 events (CONNECT response etc.)
        if (h3 != null) {
          final evOut = malloc<ffi.Pointer<quiche_h3_event>>();
          try {
            while (true) {
              final sid = quiche.quiche_h3_conn_poll(h3!, conn, evOut);
              if (sid < 0) break;
              final ev = evOut.value;
              if (ev == ffi.nullptr) continue;

              final evType = quiche.quiche_h3_event_type1(ev);
              if (evType == 0 /* HEADERS */ ) {
                print("📩 H3 HEADERS on stream $sid");
                try {
                  final statusPtr = malloc<ffi.Int32>()..value = 0;
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
                  /* ok if symbol missing */
                }
              } else if (evType == 1 /* DATA */ ) {
                // DATA on CONNECT => helpful to print (some servers send error body on rejection)
                if (sid == connectStreamId) {
                  try {
                    final bodyBuf = malloc<ffi.Uint8>(4096);
                    final n = quiche.quiche_h3_recv_body(
                      h3!,
                      conn,
                      sid,
                      bodyBuf,
                      4096,
                    );
                    if (n > 0) {
                      final text = utf8.decode(
                        bodyBuf.asTypedList(n),
                        allowMalformed: true,
                      );
                      print("❗ CONNECT body: $text");
                    }
                    malloc.free(bodyBuf);
                  } catch (_) {}
                }
              } else if (evType == 2 /* FINISHED */ ) {
                print("🏁 H3 stream $sid FINISHED");
              }
              quiche.quiche_h3_event_free(ev);
            }
          } finally {
            malloc.free(evOut);
          }

          // SETTINGS can arrive after H3 creation; re-check DATAGRAM capability
          try {
            final enabled = quiche.quiche_h3_dgram_enabled_by_peer(h3!, conn);
            if (enabled != h3DgramByPeer) {
              h3DgramByPeer = enabled;
              print('ℹ️ H3 DATAGRAM by peer (updated): $h3DgramByPeer');
            }
          } catch (_) {}

          // Process WT raw streams
          while (true) {
            final next = quiche.quiche_conn_stream_readable_next(conn);
            if (next < 0) break;
            final sid = next;

            // Skip CONNECT stream; H3 emits events for it already
            if (connectStreamId != null && sid == connectStreamId) {
              // Drain to keep state clean (usually empty)
              final tmp = malloc<ffi.Uint8>(1);
              quiche.quiche_conn_stream_recv(
                conn,
                sid,
                tmp,
                1,
                ffi.nullptr,
                ffi.nullptr,
              );
              malloc.free(tmp);
              continue;
            }

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
              final done = rc == -1;
              if (rc > 0) accum.add(tmp.asTypedList(rc));
              malloc.free(finPtr);
              if (done) break;
            }
            malloc.free(tmp);

            final bytes = accum.takeBytes();
            final isServerUni = (sid & 0x3) == 0x3;
            if (isServerUni) {
              _processIncomingUni(sid, bytes);
            } else {
              _processIncomingBidi(sid, bytes);
            }
          }

          // DATAGRAM receive (if negotiated)
          if (h3DgramByPeer) {
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
              if (wtReady &&
                  connectStreamId != null &&
                  flowId == connectStreamId) {
                final jsonBytes = data.sublist(off);
                try {
                  _handleStanza(jsonDecode(_decoder.convert(jsonBytes)));
                } catch (e) {
                  print("⚠️ bad JSON in datagram: $e");
                }
              }
              malloc.free(buf);
            }
          }
        }
      }

      // Always pump after recv to flush ACKs / responses promptly
      pump();
    } finally {
      malloc
        ..free(inPtr)
        ..free(recvInfo)
        ..free(fromAddr)
        ..free(toAddr);
    }
  });

  // --- Timeouts ---
  Timer? timeout;
  timeout = Timer.periodic(const Duration(milliseconds: 50), (_) {
    quiche.quiche_conn_on_timeout(conn);
    pump();
    if (quiche.quiche_conn_is_closed(conn) != false) {
      print("🔒 QUIC Closed");
      timeout?.cancel();
      malloc
        ..free(scidPtr)
        ..free(localAddrPtr)
        ..free(peerAddrPtr);
      exit(0);
    }
  });

  // --- Demo actions: send after CONNECT 200 only ---
  bool demoSent = false;
  Timer.periodic(const Duration(milliseconds: 250), (timer) {
    if (wtReady && !demoSent) {
      demoSent = true;
      // Presence
      sendPresence("online");
      Future.delayed(
        const Duration(milliseconds: 600),
        () => sendPresence("typing…"),
      );
      Future.delayed(const Duration(seconds: 2), () => sendPresence("online"));
      // BIDI IQ + a chat message
      sendIqSyncHistory();
      sendChat("Guest", "Hello from Dart WT client!");
      timer.cancel();
    }
  });
}
