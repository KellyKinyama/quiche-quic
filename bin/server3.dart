// dart run bin/server.dart
import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:quiche_quic/quiche_bindings.dart';

/// ==== WT framing constants (match client) ====
const int WT_H3_FRAME_WEBTRANSPORT_STREAM = 0x41; // bidi frame type
const int WT_H3_UNI_STREAM_TYPE = 0x54; // uni stream type

/// ==== Server endpoint ====
const String WT_PATH = "/"; // matches your client requests
const String WT_AUTH = "localhost:4433";

/// Basic stanza storage
final List<String> _messageHistory = <String>["SYSTEM: Dart WT server ready."];

/// Random client id generator
int _nextClientId() => 1000 + Random.secure().nextInt(9000);

void debugCallback(ffi.Pointer<ffi.Char> line, ffi.Pointer<ffi.Void> argp) {
  // Print all quiche log lines so we can see early closes / alerts
  try {
    final s = line.cast<Utf8>().toDartString();
    print("🛠️ [QUICHE] $s");
  } catch (_) {}
}

/// ===== varint + JSON helpers =====
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

Uint8List _utf8(Map<String, dynamic> j) =>
    Uint8List.fromList(utf8.encode(jsonEncode(j)));

/// Returns the negotiated ALPN (e.g., "h3" or "h3-29"), or "" if not available.
String _negotiatedAlpn(QuicheBindings quiche, ffi.Pointer<quiche_conn> conn) {
  try {
    final outPtrPtr = malloc<ffi.Pointer<ffi.Uint8>>();
    final outLenPtr = malloc<ffi.Size>();
    outPtrPtr.value = ffi.nullptr;
    outLenPtr.value = 0;

    quiche.quiche_conn_application_proto(conn, outPtrPtr, outLenPtr);

    final len = outLenPtr.value;
    final outPtr = outPtrPtr.value;
    String alpn = '';
    if (outPtr != ffi.nullptr && len > 0) {
      alpn = utf8.decode(outPtr.asTypedList(len));
    }

    malloc
      ..free(outPtrPtr)
      ..free(outLenPtr);

    return alpn;
  } catch (_) {
    return '';
  }
}

/// ===== Header capture (top-level FFI callback) =====
class _Hdrs {
  String method = '';
  String path = '';
  String protocol = '';
  String authority = '';
  String status = '';
}

final Map<int, _Hdrs> _headersBox = <int, _Hdrs>{};

int h3HeaderCapture(
  ffi.Pointer<ffi.Uint8> name,
  int nameLen,
  ffi.Pointer<ffi.Uint8> value,
  int valueLen,
  ffi.Pointer<ffi.Void> arg,
) {
  try {
    final n = name.cast<Utf8>().toDartString(length: nameLen);
    final v = value.cast<Utf8>().toDartString(length: valueLen);
    final tokenAddr = arg.address;
    final hdrs = _headersBox[tokenAddr];
    if (hdrs == null) return 0;

    switch (n) {
      case ':method':
        hdrs.method = v;
        break;
      case ':path':
        hdrs.path = v;
        break;
      case ':protocol':
        hdrs.protocol = v;
        break;
      case ':authority':
        hdrs.authority = v;
        break;
      case ':status':
        hdrs.status = v;
        break;
      default:
        break;
    }
  } catch (_) {}
  return 0;
}

/// ===== Main entry =====
Future<void> main() async {
  // Load quiche
  final dylib = ffi.DynamicLibrary.open('quich/quiche.dll');
  final quiche = QuicheBindings(dylib);

  // Enable debug (print all)
  final logCb =
      ffi.Pointer.fromFunction<
        ffi.Void Function(ffi.Pointer<ffi.Char>, ffi.Pointer<ffi.Void>)
      >(debugCallback);
  quiche.quiche_enable_debug_logging(logCb, ffi.nullptr);

  // ===== QUIC config (server) =====
  final config = quiche.quiche_config_new(1);
  if (config == ffi.nullptr) {
    print('❌ Failed to create quiche_config');
    exit(1);
  }

  quiche.quiche_config_set_max_idle_timeout(config, 600000);
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

  // Explicit UDP payload sizes
  quiche.quiche_config_set_max_recv_udp_payload_size(config, 1350);
  quiche.quiche_config_set_max_send_udp_payload_size(config, 1350);

  // Enable QUIC DATAGRAM
  quiche.quiche_config_enable_dgram(config, true, 65536, 65536);

  // Load cert / key
  final certPath = 'cert.pem'.toNativeUtf8();
  final keyPath = 'key.pem'.toNativeUtf8();
  try {
    quiche.quiche_config_load_cert_chain_from_pem_file(config, certPath.cast());
    quiche.quiche_config_load_priv_key_from_pem_file(config, keyPath.cast());
  } catch (_) {
    print('❌ Failed to load cert.pem / key.pem — place them near this script.');
    malloc.free(certPath);
    malloc.free(keyPath);
    exit(1);
  }
  malloc
    ..free(certPath)
    ..free(keyPath);

  // === ALPN: accept final and drafts ===
  final alpnList = <int>[
    0x02, 0x68, 0x33, // "h3"
    0x05, 0x68, 0x33, 0x2d, 0x32, 0x39, // "h3-29"
    0x05, 0x68, 0x33, 0x2d, 0x33, 0x32, // "h3-32"
    0x05, 0x68, 0x33, 0x2d, 0x33, 0x31, // "h3-31"
    0x05, 0x68, 0x33, 0x2d, 0x33, 0x30, // "h3-30"
  ];
  final alpnPtr = malloc<ffi.Uint8>(alpnList.length)
    ..asTypedList(alpnList.length).setAll(0, alpnList);
  final alpnRc = quiche.quiche_config_set_application_protos(
    config,
    alpnPtr,
    alpnList.length,
  );
  malloc.free(alpnPtr);
  if (alpnRc != 0) {
    print("❌ Failed to set ALPN list");
    exit(1);
  }

  // UDP socket
  final socket = await RawDatagramSocket.bind(
    InternetAddress("127.0.0.1"),
    4433,
  );
  print(
    '🟢 WT/H3 server listening on ${socket.address.address}:${socket.port}',
  );

  // Maintain connections by remote address:port
  final Map<String, _ConnCtx> conns = <String, _ConnCtx>{};

  // Periodic on_timeout
  Timer.periodic(const Duration(milliseconds: 50), (t) {
    for (final entry in conns.entries) {
      final ctx = entry.value;
      quiche.quiche_conn_on_timeout(ctx.conn);
      _flush(quiche, socket, ctx);
      if (quiche.quiche_conn_is_closed(ctx.conn) != 0) {
        print('🔒 Closed ${entry.key}');
        ctx.free();
        conns.remove(entry.key);
        break;
      }
    }
  });

  // Receive loop
  socket.listen((ev) {
    if (ev != RawSocketEvent.read) return;

    final dg = socket.receive();
    if (dg == null) return;

    final peerKey = '${dg.address.address}:${dg.port}';
    final peerAddr = _sockAddr(dg.address.address, dg.port);
    final localAddr = _sockAddr(socket.address.address, socket.port);

    // Find or create connection (LOCAL first, then PEER)
    _ConnCtx ctx =
        conns[peerKey] ?? _acceptConn(quiche, config, localAddr, peerAddr);
    if (!conns.containsKey(peerKey)) conns[peerKey] = ctx;

    // Refresh real peer endpoint (for send)
    final oldAddr = ctx.peerAddr;
    final oldPort = ctx.peerPort;
    ctx.peerAddr = dg.address;
    ctx.peerPort = dg.port;
    if (oldAddr.address != ctx.peerAddr.address || oldPort != ctx.peerPort) {
      print('🔎 peer endpoint set to ${ctx.peerAddr.address}:${ctx.peerPort}');
    }

    // Feed packet
    final inPtr = malloc<ffi.Uint8>(dg.data.length)
      ..asTypedList(dg.data.length).setAll(0, dg.data);
    final recvInfo = malloc<quiche_recv_info>();
    recvInfo.ref
      ..from = peerAddr
          .cast() // peer
      ..from_len = 16
      ..to = localAddr
          .cast() // local
      ..to_len = 16;
    quiche.quiche_conn_recv(ctx.conn, inPtr, dg.data.length, recvInfo);
    malloc
      ..free(inPtr)
      ..free(recvInfo);

    // If established, ensure H3 exists
    final established = quiche.quiche_conn_is_established(ctx.conn) != 0;

    if (established) {
      if (!ctx._dbgEstablishedPrinted) {
        ctx._dbgEstablishedPrinted = true;
        print(
          '✅ QUIC established with ${ctx.peerAddr.address}:${ctx.peerPort}',
        );
      }

      // Try to log ALPN (may be empty early on some builds)
      final alpn = _negotiatedAlpn(quiche, ctx.conn);
      if (alpn.isEmpty) {
        print('🔐 ALPN not available (yet) — proceeding to try H3 anyway');
      } else {
        print('🔐 ALPN negotiated: "$alpn"');
      }

      // Try to create H3 regardless of ALPN string
      if (ctx.h3 == null) {
        final h3cfg = quiche.quiche_h3_config_new();
        if (h3cfg == ffi.nullptr) {
          print("❌ quiche_h3_config_new failed (will retry)");
        } else {
          try {
            quiche.quiche_h3_config_enable_extended_connect(h3cfg, true);
          } catch (e) {
            print('❌ quiche_h3_config_enable_extended_connect missing: $e');
          }

          final h3 = quiche.quiche_h3_conn_new_with_transport(ctx.conn, h3cfg);
          if (h3 == ffi.nullptr) {
            print("ℹ️ H3 not ready yet (will retry)");
          } else {
            ctx.h3 = h3;
            // Free config after success
            try {
              quiche.quiche_h3_config_free(h3cfg);
            } catch (_) {}

            // Detect H3 DATAGRAM capability
            try {
              ctx.h3Dgram = quiche.quiche_h3_dgram_enabled_by_peer(
                h3,
                ctx.conn,
              );
            } catch (_) {
              ctx.h3Dgram = false;
            }
            print('ℹ️ Peer H3 DATAGRAM: ${ctx.h3Dgram}');

            // Flush now so SETTINGS go out immediately
            _flush(quiche, socket, ctx);
          }
        }
      }

      // Only poll H3 / streams if H3 exists
      if (ctx.h3 != null) {
        _pollH3(quiche, socket, ctx);
        _drainStreams(quiche, socket, ctx);
        _drainDgrams(quiche, socket, ctx);
      }
    }

    _flush(quiche, socket, ctx);

    malloc
      ..free(peerAddr)
      ..free(localAddr);
  });
}

/// Connection context
class _ConnCtx {
  _ConnCtx({
    required this.conn,
    required this.scid,
    required this.serverAddr,
    required this.peerAddr,
  });

  final ffi.Pointer<quiche_conn> conn;
  final Uint8List scid;
  final InternetAddress serverAddr;
  InternetAddress peerAddr;
  int peerPort = 0;

  ffi.Pointer<quiche_h3_conn>? h3;
  bool h3Dgram = false;

  // WebTransport session state per CONNECT stream id
  final Map<int, _Session> sessions = <int, _Session>{};

  // Server-initiated uni stream allocator:
  // Skip reserved/control/QPACK/GREASE: 3, 7, 11, 15
  // First safe app uni stream is 19, then 23, 27, ...
  int nextServerUni = 19;

  // DEBUG bookkeeping
  bool _dbgEstablishedPrinted = false;

  void free() {}
}

class _Session {
  _Session({required this.streamId, required this.clientId});

  final int streamId; // CONNECT stream id
  final int clientId;
}

/// Build a minimal IPv4 sockaddr_in (16 bytes)
ffi.Pointer<ffi.Uint8> _sockAddr(String ip, int port) {
  final ptr = malloc<ffi.Uint8>(16);
  final v = ptr.asTypedList(16)..fillRange(0, 16, 0);
  v[0] = 0x02; // AF_INET low byte
  v[1] = 0x00; // AF_INET high byte
  v[2] = (port >> 8) & 0xFF; // network order
  v[3] = port & 0xFF;
  final parts = ip.split('.').map(int.parse).toList();
  for (var i = 0; i < 4; i++) v[4 + i] = parts[i] & 0xFF;
  return ptr;
}

/// Accept a new QUIC connection. (local, peer) address order is critical.
_ConnCtx _acceptConn(
  QuicheBindings quiche,
  ffi.Pointer<quiche_config> config,
  ffi.Pointer<ffi.Uint8> localAddr,
  ffi.Pointer<ffi.Uint8> peerAddr,
) {
  final scid = Uint8List.fromList(
    List<int>.generate(16, (i) => Random.secure().nextInt(256)),
  );
  final scidPtr = malloc<ffi.Uint8>(scid.length)
    ..asTypedList(scid.length).setAll(0, scid);

  final conn = quiche.quiche_accept(
    scidPtr,
    scid.length,
    ffi.nullptr, // odcid
    0, // odcid_len
    localAddr.cast(), // LOCAL first
    16,
    peerAddr.cast(), // PEER second
    16,
    config,
  );

  if (conn == ffi.nullptr) {
    print('❌ quiche_accept failed');
    malloc.free(scidPtr);
    throw StateError('quiche_accept failed');
  }
  malloc.free(scidPtr);

  final ctx = _ConnCtx(
    conn: conn,
    scid: scid,
    serverAddr: InternetAddress('127.0.0.1'),
    peerAddr: InternetAddress.anyIPv4,
  );
  return ctx;
}

/// Send pending packets from quiche to the correct peer (using last-seen addr)
void _flush(QuicheBindings quiche, RawDatagramSocket sock, _ConnCtx ctx) {
  final outBuf = malloc<ffi.Uint8>(1500);
  final sendInfo = malloc<quiche_send_info>(); // kept to satisfy API
  try {
    while (true) {
      final written = quiche.quiche_conn_send(ctx.conn, outBuf, 1500, sendInfo);
      if (written <= 0) break;

      print(
        '📡 sending ${written}B to ${ctx.peerAddr.address}:${ctx.peerPort}',
      );

      final sent = sock.send(
        outBuf.asTypedList(written),
        ctx.peerAddr,
        ctx.peerPort,
      );
      if (sent <= 0) {
        print(
          '⚠️ send() returned $sent to ${ctx.peerAddr.address}:${ctx.peerPort}',
        );
      }
    }
  } finally {
    malloc
      ..free(outBuf)
      ..free(sendInfo);
  }
}

/// Poll H3 events; accept CONNECT and reply 200 (no body)
void _pollH3(QuicheBindings quiche, RawDatagramSocket sock, _ConnCtx ctx) {
  final evOut = malloc<ffi.Pointer<quiche_h3_event>>();
  try {
    while (true) {
      final sid = quiche.quiche_h3_conn_poll(ctx.h3!, ctx.conn, evOut);
      if (sid < 0) break;

      final ev = evOut.value;
      if (ev == ffi.nullptr) continue;

      final evType = quiche.quiche_h3_event_type1(ev);
      print('🔔 H3 event on stream $sid => type=$evType');

      if (evType == 0 /* HEADERS */ ) {
        // Capture request headers using a top-level FFI callback
        final token = malloc<ffi.Uint8>(1);
        _headersBox[token.address] = _Hdrs();

        final cb =
            ffi.Pointer.fromFunction<
              ffi.Int Function(
                ffi.Pointer<ffi.Uint8>,
                ffi.Size,
                ffi.Pointer<ffi.Uint8>,
                ffi.Size,
                ffi.Pointer<ffi.Void>,
              )
            >(h3HeaderCapture, 0);

        quiche.quiche_h3_event_for_each_header(ev, cb, token.cast());

        final req = _headersBox[token.address]!;
        _headersBox.remove(token.address);
        malloc.free(token);

        print(
          '🧭 H3 request on $sid  method=${req.method}  path=${req.path}  proto=${req.protocol}',
        );

        final isConnect = req.method == 'CONNECT';
        final isWT = req.protocol == 'webtransport';
        // Accept "/" with OPTIONAL query string (e.g., "/?secret=...")
        final reqPathOnly = req.path.split('?').first;
        final isPathOk = reqPathOnly == WT_PATH;

        if (isConnect && isWT && isPathOk) {
          if (req.path.contains('?')) {
            print('ℹ️ Accepting CONNECT with query: ${req.path}');
          }
          // Send 200 (no body)
          final headers = malloc<quiche_h3_header>(2);
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

          setH(0, ':status', '200');
          setH(1, 'server', 'dart-quiche-wt');

          final rc = quiche.quiche_h3_send_response(
            ctx.h3!,
            ctx.conn,
            sid,
            headers,
            2,
            false,
          );
          if (rc < 0) {
            print('❌ Failed to send 200 CONNECT response: rc=$rc');
          } else {
            print('📤 Sent CONNECT 200 on stream $sid');
            _flush(quiche, sock, ctx); // ensure HEADERS go out now
          }

          for (final p in toFree) malloc.free(p);
          malloc.free(headers);

          final clientId = _nextClientId();
          ctx.sessions[sid] = _Session(streamId: sid, clientId: clientId);
          print('✅ WT accepted on stream $sid (clientId=$clientId)');
          _broadcastRoster(quiche, ctx);
        } else {
          // Not a WT CONNECT — send 404 + small body
          final headers = malloc<quiche_h3_header>(2);
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

          setH(0, ':status', '404');
          setH(1, 'server', 'dart-quiche-wt');

          final rcHdr = quiche.quiche_h3_send_response(
            ctx.h3!,
            ctx.conn,
            sid,
            headers,
            2,
            false,
          );
          if (rcHdr < 0) {
            print('❌ Failed to send 404 headers: rc=$rcHdr');
          } else {
            print('📤 Sent 404 headers on stream $sid');
            _flush(quiche, sock, ctx);
          }

          const bodyText = 'not found';
          final bodyBytes = Uint8List.fromList(utf8.encode(bodyText));
          final bodyPtr = malloc<ffi.Uint8>(bodyBytes.length)
            ..asTypedList(bodyBytes.length).setAll(0, bodyBytes);

          final rcBody = quiche.quiche_h3_send_body(
            ctx.h3!,
            ctx.conn,
            sid,
            bodyPtr,
            bodyBytes.length,
            true,
          );
          if (rcBody < 0) {
            print('❌ Failed to send 404 body: rc=$rcBody');
          } else {
            _flush(quiche, sock, ctx);
          }
          malloc.free(bodyPtr);

          for (final p in toFree) malloc.free(p);
          malloc.free(headers);
        }
      } else if (evType == 1 /* DATA */ ) {
        // Ignore DATA on CONNECT.
      } else if (evType == 2 /* FINISHED */ ) {
        print('🏁 H3 stream $sid FINISHED');
      }

      quiche.quiche_h3_event_free(ev);
    }
  } finally {
    malloc.free(evOut);
  }
}

/// Drain readable app streams (uni/bidi) with our JSON protocol
void _drainStreams(
  QuicheBindings quiche,
  RawDatagramSocket sock,
  _ConnCtx ctx,
) {
  while (true) {
    final next = quiche.quiche_conn_stream_readable_next(ctx.conn);
    if (next < 0) break;

    final sid = next;
    final accum = BytesBuilder();
    final tmp = malloc<ffi.Uint8>(65535);

    while (true) {
      final finPtr = malloc<ffi.Uint8>(1);
      final rc = quiche.quiche_conn_stream_recv(
        ctx.conn,
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

    // Skip CONNECT streams
    if (ctx.sessions.containsKey(sid)) continue;

    final bytes = accum.takeBytes();
    if (bytes.isEmpty) continue;

    int off = 0;
    try {
      final (t, l1) = _varintDecode(bytes, off);
      off += l1;

      if (t == WT_H3_UNI_STREAM_TYPE) {
        final (flowId, l2) = _varintDecode(bytes, off);
        off += l2;

        if (!ctx.sessions.containsKey(flowId)) continue;
        final jsonBytes = bytes.sublist(off);
        final stanza = jsonDecode(utf8.decode(jsonBytes));
        _handleUni(quiche, ctx, flowId, stanza);
        continue;
      }

      if (t == WT_H3_FRAME_WEBTRANSPORT_STREAM) {
        final (flowId, l2) = _varintDecode(bytes, off);
        off += l2;

        if (!ctx.sessions.containsKey(flowId)) continue;
        final jsonBytes = bytes.sublist(off);
        final stanza = jsonDecode(utf8.decode(jsonBytes));
        _handleBidi(quiche, ctx, flowId, sid, stanza);
        continue;
      }
    } catch (e) {
      print('⚠️ stream $sid parse error: $e');
    }
  }
}

/// Drain DATAGRAMs (flow-id varint + JSON)
void _drainDgrams(QuicheBindings quiche, RawDatagramSocket sock, _ConnCtx ctx) {
  if (!ctx.h3Dgram) return;
  while (true) {
    final buf = malloc<ffi.Uint8>(65535);
    final rc = quiche.quiche_conn_dgram_recv(ctx.conn, buf, 65535);
    if (rc <= 0) {
      malloc.free(buf);
      break;
    }
    final data = buf.asTypedList(rc);
    int off = 0;
    try {
      final (flowId, l1) = _varintDecode(data, off);
      off += l1;
      if (!ctx.sessions.containsKey(flowId)) {
        malloc.free(buf);
        continue;
      }
      final jsonBytes = data.sublist(off);
      final stanza = jsonDecode(utf8.decode(jsonBytes));
      _rebroadcastPresence(quiche, ctx, flowId, stanza);
    } catch (e) {
      print('⚠️ bad JSON in datagram: $e');
    }
    malloc.free(buf);
  }
}

/// Handle UNI JSON stanzas (chat + roster)
void _handleUni(
  QuicheBindings quiche,
  _ConnCtx ctx,
  int flowId,
  dynamic stanza,
) {
  print('📥 UNI on session=$flowId: $stanza');
  final type = stanza['type'] as String?;

  if (type == 'message') {
    final body = stanza['data']?['body'];
    final from = stanza['data']?['from'];
    if (body is String) {
      _messageHistory.add('$from: $body');
    }
    _broadcast(quiche, ctx, excludeFlowId: flowId, stanza: stanza);
  } else if (type == 'iq') {
    _broadcast(quiche, ctx, excludeFlowId: flowId, stanza: stanza);
  }
}

/// Handle BIDI JSON stanzas (iq sync_history)
void _handleBidi(
  QuicheBindings quiche,
  _ConnCtx ctx,
  int flowId,
  int bidiStreamId,
  dynamic stanza,
) async {
  print('📥 BIDI on session=$flowId stream=$bidiStreamId: $stanza');
  final type = stanza['type'] as String?;
  if (type == 'iq') {
    final action = stanza['data']?['action'];
    if (action == 'sync_history') {
      final res = {
        "type": "iq",
        "data": {
          "msg": "History Loaded",
          "payload": jsonEncode(_messageHistory),
        },
      };
      final payload = _frameBidi(flowId, res);
      _streamSend(quiche, ctx, bidiStreamId, payload, fin: true);
    }
  }
}

/// Build BIDI frame: 0x41 + session-id + JSON
Uint8List _frameBidi(int flowId, Map<String, dynamic> json) =>
    Uint8List.fromList(
      _varintEncode(WT_H3_FRAME_WEBTRANSPORT_STREAM) +
          _varintEncode(flowId) +
          _utf8(json),
    );

/// Build UNI frame: 0x54 + session-id + JSON
Uint8List _frameUni(int flowId, Map<String, dynamic> json) =>
    Uint8List.fromList(
      _varintEncode(WT_H3_UNI_STREAM_TYPE) +
          _varintEncode(flowId) +
          _utf8(json),
    );

/// Send bytes on an existing stream id
void _streamSend(
  QuicheBindings quiche,
  _ConnCtx ctx,
  int streamId,
  Uint8List data, {
  required bool fin,
}) {
  final ptr = malloc<ffi.Uint8>(data.length)
    ..asTypedList(data.length).setAll(0, data);
  final rc = quiche.quiche_conn_stream_send(
    ctx.conn,
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
}

/// Create a server-initiated uni stream (IDs: 19,23,27,...) and send
int _openServerUni(QuicheBindings quiche, _ConnCtx ctx) {
  var id = ctx.nextServerUni;
  // Guard against reserved/control/QPACK/GREASE ids
  const reserved = {3, 7, 11, 15};
  if (reserved.contains(id)) id = 19;
  ctx.nextServerUni = id + 4;
  return id;
}

/// Broadcast JSON stanza to all sessions except one (by flowId)
void _broadcast(
  QuicheBindings quiche,
  _ConnCtx ctx, {
  required int? excludeFlowId,
  required Map<String, dynamic> stanza,
}) {
  for (final entry in ctx.sessions.entries) {
    final flowId = entry.key;
    if (excludeFlowId != null && flowId == excludeFlowId) continue;

    final isPresence = stanza['type'] == 'presence';
    if (isPresence && ctx.h3Dgram) {
      final payload = Uint8List.fromList(_varintEncode(flowId) + _utf8(stanza));
      final ptr = malloc<ffi.Uint8>(payload.length)
        ..asTypedList(payload.length).setAll(0, payload);
      final rc = quiche.quiche_conn_dgram_send(ctx.conn, ptr, payload.length);
      malloc.free(ptr);
      if (rc < 0) {
        print('⚠️ dgram_send rc=$rc (flow $flowId)');
      }
    } else {
      final streamId = _openServerUni(quiche, ctx);
      final frame = _frameUni(flowId, stanza);
      _streamSend(quiche, ctx, streamId, frame, fin: true);
      print('📤 UNI to flow=$flowId on stream=$streamId');
    }
  }
}

/// Broadcast roster (list of clientIds) to all sessions
void _broadcastRoster(QuicheBindings quiche, _ConnCtx ctx) {
  final ids = <int>[];
  for (final s in ctx.sessions.values) ids.add(s.clientId);
  final stanza = {
    "type": "iq",
    "data": {"action": "roster_update", "payload": jsonEncode(ids)},
  };
  _broadcast(quiche, ctx, excludeFlowId: null, stanza: stanza);
}

/// Rebroadcast presence datagrams from one session to others
void _rebroadcastPresence(
  QuicheBindings quiche,
  _ConnCtx ctx,
  int flowId,
  dynamic stanza,
) {
  final s = ctx.sessions[flowId];
  if (s != null) {
    try {
      stanza['data']['from'] = s.clientId;
    } catch (_) {}
  }
  _broadcast(
    quiche,
    ctx,
    excludeFlowId: flowId,
    stanza: Map<String, dynamic>.from(stanza),
  );
}
