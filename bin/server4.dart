// dart run bin/server.dart
import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:quiche_quic/quiche_bindings.dart';

const String WT_PATH = "/";
const int WT_H3_FRAME_WEBTRANSPORT_STREAM = 0x41;
const int WT_H3_UNI_STREAM_TYPE = 0x54;

void debugCallback(ffi.Pointer<ffi.Char> line, ffi.Pointer<ffi.Void> argp) {
  try {
    print("🛠️ [QUICHE] ${line.cast<Utf8>().toDartString()}");
  } catch (_) {}
}

Uint8List _varintEncode(int v) {
  if (v < (1 << 6)) return Uint8List.fromList([v & 0x3f]);
  if (v < (1 << 14))
    return Uint8List.fromList([0x40 | ((v >> 8) & 0x3f), v & 0xff]);
  if (v < (1 << 30)) {
    return Uint8List.fromList([
      0x80 | ((v >> 24) & 0x3f),
      (v >> 16) & 0xff,
      (v >> 8) & 0xff,
      v & 0xff,
    ]);
  }
  final b = ByteData(8)..setUint64(0, v);
  final bytes = b.buffer.asUint8List();
  bytes[0] = 0xC0 | (bytes[0] & 0x3f);
  return bytes;
}

class _Hdrs {
  String method = '', path = '', protocol = '', authority = '', status = '';
}

final Map<int, _Hdrs> _headersBox = {};

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
    final h = _headersBox[arg.address];
    if (h == null) return 0;
    switch (n) {
      case ':method':
        h.method = v;
        break;
      case ':path':
        h.path = v;
        break;
      case ':protocol':
        h.protocol = v;
        break;
      case ':authority':
        h.authority = v;
        break;
      case ':status':
        h.status = v;
        break;
    }
  } catch (_) {}
  return 0;
}

Future<void> main() async {
  final dylib = ffi.DynamicLibrary.open('quich/quiche.dll');
  final quiche = QuicheBindings(dylib);

  final logCb =
      ffi.Pointer.fromFunction<
        ffi.Void Function(ffi.Pointer<ffi.Char>, ffi.Pointer<ffi.Void>)
      >(debugCallback);
  quiche.quiche_enable_debug_logging(logCb, ffi.nullptr);

  final cfg = quiche.quiche_config_new(1);
  quiche.quiche_config_set_max_idle_timeout(cfg, 600000);
  quiche.quiche_config_set_initial_max_data(cfg, 10 * 1024 * 1024);
  quiche.quiche_config_set_initial_max_streams_bidi(cfg, 100);
  quiche.quiche_config_set_initial_max_streams_uni(cfg, 100);
  quiche.quiche_config_set_initial_max_stream_data_bidi_local(cfg, 1024 * 1024);
  quiche.quiche_config_set_initial_max_stream_data_bidi_remote(
    cfg,
    1024 * 1024,
  );
  quiche.quiche_config_set_initial_max_stream_data_uni(cfg, 1024 * 1024);
  quiche.quiche_config_enable_dgram(cfg, true, 65536, 65536);
  quiche.quiche_config_set_max_recv_udp_payload_size(cfg, 1350);
  quiche.quiche_config_set_max_send_udp_payload_size(cfg, 1350);

  final cert = 'cert.pem'.toNativeUtf8(), key = 'key.pem'.toNativeUtf8();
  quiche.quiche_config_load_cert_chain_from_pem_file(cfg, cert.cast());
  quiche.quiche_config_load_priv_key_from_pem_file(cfg, key.cast());
  malloc
    ..free(cert)
    ..free(key);

  final alpn = <int>[0x02, 0x68, 0x33]; // "h3"
  final alpnPtr = malloc<ffi.Uint8>(alpn.length)
    ..asTypedList(alpn.length).setAll(0, alpn);
  quiche.quiche_config_set_application_protos(cfg, alpnPtr, alpn.length);
  malloc.free(alpnPtr);

  final sock = await RawDatagramSocket.bind(InternetAddress('127.0.0.1'), 4433);
  print('🟢 Server listening');

  final conns = <String, _ConnCtx>{};

  // Periodic timeouts & flush
  Timer.periodic(const Duration(milliseconds: 50), (_) {
    for (final key in List<String>.from(conns.keys)) {
      final ctx = conns[key]!;
      quiche.quiche_conn_on_timeout(ctx.conn);
      _flush(quiche, sock, ctx);
      if (quiche.quiche_conn_is_closed(ctx.conn) != 0) {
        print('🔒 Closed $key');
        conns.remove(key);
      }
    }
  });

  sock.listen((ev) {
    if (ev != RawSocketEvent.read) return;
    final dg = sock.receive();
    if (dg == null) return;

    final peerKey = '${dg.address.address}:${dg.port}';
    final localSA = _sockAddr(sock.address.address, sock.port);
    final peerSA = _sockAddr(dg.address.address, dg.port);

    final ctx = conns[peerKey] ?? _accept(quiche, cfg, localSA, peerSA);
    conns.putIfAbsent(peerKey, () => ctx);
    ctx.peerAddr = dg.address;
    ctx.peerPort = dg.port;

    final inPtr = malloc<ffi.Uint8>(dg.data.length)
      ..asTypedList(dg.data.length).setAll(0, dg.data);
    final rcv = malloc<quiche_recv_info>();
    rcv.ref
      ..from = peerSA.cast()
      ..from_len = 16
      ..to = localSA.cast()
      ..to_len = 16;

    quiche.quiche_conn_recv(ctx.conn, inPtr, dg.data.length, rcv);

    malloc
      ..free(inPtr)
      ..free(rcv)
      ..free(localSA)
      ..free(peerSA);

    // Bring up H3 once established
    if (quiche.quiche_conn_is_established(ctx.conn) != 0) {
      if (!ctx.estLogged) {
        ctx.estLogged = true;
        print(
          '✅ QUIC established with ${ctx.peerAddr.address}:${ctx.peerPort}',
        );
      }
      if (ctx.h3 == null) {
        final h3cfg = quiche.quiche_h3_config_new();
        if (h3cfg != ffi.nullptr) {
          try {
            quiche.quiche_h3_config_enable_extended_connect(h3cfg, true);
          } catch (_) {}
          final h3 = quiche.quiche_h3_conn_new_with_transport(ctx.conn, h3cfg);
          if (h3 == ffi.nullptr) {
            print('ℹ️ H3 not ready yet (will retry)');
          } else {
            ctx.h3 = h3;
            _flush(quiche, sock, ctx); // push SETTINGS immediately
          }
          try {
            quiche.quiche_h3_config_free(h3cfg);
          } catch (_) {}
        }
      }
      if (ctx.h3 != null) _pollH3(quiche, sock, ctx);
    }

    _flush(quiche, sock, ctx);
  });
}

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
  bool estLogged = false;
  // start after control/QPACK/GREASE: 19,23,27...
  int nextServerUni = 19;
}

_ConnCtx _accept(
  QuicheBindings quiche,
  ffi.Pointer<quiche_config> cfg,
  ffi.Pointer<ffi.Uint8> localSA,
  ffi.Pointer<ffi.Uint8> peerSA,
) {
  final scid = Uint8List.fromList(
    List<int>.generate(16, (_) => Random.secure().nextInt(256)),
  );
  final scidPtr = malloc<ffi.Uint8>(scid.length)
    ..asTypedList(scid.length).setAll(0, scid);
  final conn = quiche.quiche_accept(
    scidPtr,
    scid.length,
    ffi.nullptr,
    0,
    localSA.cast(),
    16,
    peerSA.cast(),
    16,
    cfg,
  );
  malloc.free(scidPtr);
  return _ConnCtx(
    conn: conn,
    scid: scid,
    serverAddr: InternetAddress('127.0.0.1'),
    peerAddr: InternetAddress.anyIPv4,
  );
}

void _flush(QuicheBindings quiche, RawDatagramSocket sock, _ConnCtx ctx) {
  final out = malloc<ffi.Uint8>(1500);
  final si = malloc<quiche_send_info>();
  while (true) {
    final n = quiche.quiche_conn_send(ctx.conn, out, 1500, si);
    if (n <= 0) break;
    sock.send(out.asTypedList(n), ctx.peerAddr, ctx.peerPort);
  }
  malloc
    ..free(out)
    ..free(si);
}

void _pollH3(QuicheBindings quiche, RawDatagramSocket sock, _ConnCtx ctx) {
  final evOut = malloc<ffi.Pointer<quiche_h3_event>>();
  try {
    while (true) {
      final sid = quiche.quiche_h3_conn_poll(ctx.h3!, ctx.conn, evOut);
      if (sid < 0) break;
      final ev = evOut.value;
      if (ev == ffi.nullptr) continue;

      final evType = quiche.quiche_h3_event_type1(ev);
      if (evType == 0) {
        // HEADERS
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

        final isConnect = req.method == 'CONNECT';
        final isWT = req.protocol == 'webtransport';
        final isPathOk = req.path.split('?').first == WT_PATH;

        if (isConnect && isWT && isPathOk) {
          final hdrs = malloc<quiche_h3_header>(2);
          final n0 = ':status'.toNativeUtf8(), v0 = '200'.toNativeUtf8();
          final n1 = 'server'.toNativeUtf8(),
              v1 = 'dart-quiche-wt'.toNativeUtf8();
          hdrs[0].name = n0.cast();
          hdrs[0].name_len = 7;
          hdrs[0].value = v0.cast();
          hdrs[0].value_len = 3;
          hdrs[1].name = n1.cast();
          hdrs[1].name_len = 6;
          hdrs[1].value = v1.cast();
          hdrs[1].value_len = 13;

          final rc = quiche.quiche_h3_send_response(
            ctx.h3!,
            ctx.conn,
            sid,
            hdrs,
            2,
            false,
          );
          malloc
            ..free(n0)
            ..free(v0)
            ..free(n1)
            ..free(v1)
            ..free(hdrs);

          if (rc >= 0) _flush(quiche, sock, ctx);
        } else {
          // 404 with small body
          final hdrs = malloc<quiche_h3_header>(2);
          final n0 = ':status'.toNativeUtf8(), v0 = '404'.toNativeUtf8();
          final n1 = 'server'.toNativeUtf8(),
              v1 = 'dart-quiche-wt'.toNativeUtf8();
          hdrs[0].name = n0.cast();
          hdrs[0].name_len = 7;
          hdrs[0].value = v0.cast();
          hdrs[0].value_len = 3;
          hdrs[1].name = n1.cast();
          hdrs[1].name_len = 6;
          hdrs[1].value = v1.cast();
          hdrs[1].value_len = 13;

          if (quiche.quiche_h3_send_response(
                ctx.h3!,
                ctx.conn,
                sid,
                hdrs,
                2,
                false,
              ) >=
              0) {
            _flush(quiche, sock, ctx);
            final body = Uint8List.fromList(utf8.encode('not found'));
            final bodyPtr = malloc<ffi.Uint8>(body.length)
              ..asTypedList(body.length).setAll(0, body);
            quiche.quiche_h3_send_body(
              ctx.h3!,
              ctx.conn,
              sid,
              bodyPtr,
              body.length,
              true,
            );
            malloc.free(bodyPtr);
            _flush(quiche, sock, ctx);
          }
          malloc
            ..free(n0)
            ..free(v0)
            ..free(n1)
            ..free(v1)
            ..free(hdrs);
        }
      }
      quiche.quiche_h3_event_free(ev);
    }
  } finally {
    malloc.free(evOut);
  }
}

ffi.Pointer<ffi.Uint8> _sockAddr(String ip, int port) {
  final p = malloc<ffi.Uint8>(16);
  final v = p.asTypedList(16)..fillRange(0, 16, 0);
  v[0] = 0x02;
  v[1] = 0x00;
  v[2] = (port >> 8) & 0xff;
  v[3] = port & 0xff;
  final a = ip.split('.').map(int.parse).toList();
  for (var i = 0; i < 4; i++) v[4 + i] = a[i] & 0xff;
  return p;
}
