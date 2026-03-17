// dart run bin/server6.dart
import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:quiche_quic/quiche_bindings.dart';

// ----------------------------
//  SAME CONSTANTS AS BEFORE
// ----------------------------
const String WT_PATH = "/";
const int WT_STREAM_TYPE_UNI = 0x54;
const String WT_DRAFT_HEADER = "sec-webtransport-http3-draft02";
const String WT_DRAFT_VALUE = "1";

final Map<int, _Session> sessions = {};
int _nextClientId = 1000;
final _messageHistory = <String>["SYSTEM: Silo 1 nodes active."];

// ----------------------------
//  DEBUG
// ----------------------------
void debugCallback(ffi.Pointer<ffi.Char> line, ffi.Pointer<ffi.Void> argp) {
  try {
    print("🛠️ [QUICHE] ${line.cast<Utf8>().toDartString()}");
  } catch (_) {}
}

bool _asBool(dynamic v) {
  if (v is bool) return v;
  if (v is int) return v != 0;
  return false;
}

bool _isEstablished(QuicheBindings q, ffi.Pointer<quiche_conn> c) =>
    _asBool(q.quiche_conn_is_established(c));

bool _isClosed(QuicheBindings q, ffi.Pointer<quiche_conn> c) =>
    _asBool(q.quiche_conn_is_closed(c));

bool _inEarlyData(QuicheBindings q, ffi.Pointer<quiche_conn> c) =>
    _asBool(q.quiche_conn_is_in_early_data(c));

String _negotiatedAlpn(QuicheBindings q, ffi.Pointer<quiche_conn> conn) {
  final p = malloc<ffi.Pointer<ffi.Uint8>>();
  final l = malloc<ffi.Size>();
  q.quiche_conn_application_proto(conn, p, l);

  String result = "";
  if (p.value != ffi.nullptr && l.value > 0) {
    result = utf8.decode(p.value.asTypedList(l.value));
  }

  malloc
    ..free(p)
    ..free(l);
  return result;
}

// ----------------------------
//  VARINT
// ----------------------------
List<int> _encodeVarint(int v) {
  if (v < 64) return [v & 0x3f];
  final hi = 0x40 | ((v >> 8) & 0x3f);
  final lo = v & 0xff;
  return [hi, lo];
}

// ----------------------------
//  HEADER PARSING (FIXED)
// ----------------------------
class _Hdrs {
  String method = "", path = "", protocol = "", authority = "", status = "";
}

final Map<int, _Hdrs> _headersBox = {};

/// FIX 2: Correct header parsing for quiche 0.24.x
int h3HeaderCapture(
  ffi.Pointer<ffi.Uint8> name,
  int nameLen,
  ffi.Pointer<ffi.Uint8> value,
  int valueLen,
  ffi.Pointer<ffi.Void> arg,
) {
  final hdr = _headersBox[arg.address];
  if (hdr == null) return 0;

  try {
    final n = utf8.decode(name.asTypedList(nameLen), allowMalformed: true);
    final v = utf8.decode(value.asTypedList(valueLen), allowMalformed: true);

    switch (n) {
      case ':method':
        hdr.method = v;
        break;
      case ':path':
        hdr.path = v;
        break;
      case ':protocol':
        hdr.protocol = v;
        break;
      case ':authority':
        hdr.authority = v;
        break;
      case ':status':
        hdr.status = v;
        break;
    }
  } catch (_) {}

  return 0;
}

// ----------------------------
//  CONNECTION CONTEXT
// ----------------------------
class _ConnCtx {
  _ConnCtx({
    required this.conn,
    required this.scid,
    required this.serverAddr,
    required this.peerAddr,
  });

  final ffi.Pointer<quiche_conn> conn;
  final List<int> scid;
  final InternetAddress serverAddr;

  InternetAddress peerAddr;
  int peerPort = 0;

  ffi.Pointer<quiche_h3_conn>? h3;
  bool estLogged = false;
  DateTime? establishedAt;

  int nextServerUni = 19;
  Timer? h3RetryTick;

  final Map<int, _Session> sessions = {};
}

class _Session {
  _Session({required this.sid, required this.clientId, required this.connKey});

  final int sid;
  final int clientId;
  final String connKey;
}

final _conns = <String, _ConnCtx>{};

// ----------------------------
//  MAIN
// ----------------------------
Future<void> main() async {
  final dylib = ffi.DynamicLibrary.open('quich/quiche.dll');
  final quiche = QuicheBindings(dylib);

  final cb =
      ffi.Pointer.fromFunction<
        ffi.Void Function(ffi.Pointer<ffi.Char>, ffi.Pointer<ffi.Void>)
      >(debugCallback);
  quiche.quiche_enable_debug_logging(cb, ffi.nullptr);

  final cfg = quiche.quiche_config_new(1);

  quiche.quiche_config_set_max_idle_timeout(cfg, 600000);
  quiche.quiche_config_set_initial_max_data(cfg, 10 * 1024 * 1024);
  quiche.quiche_config_set_initial_max_streams_bidi(cfg, 1024);
  quiche.quiche_config_set_initial_max_streams_uni(cfg, 1024);
  quiche.quiche_config_set_initial_max_stream_data_bidi_local(
    cfg,
    1 * 1024 * 1024,
  );
  quiche.quiche_config_set_initial_max_stream_data_bidi_remote(
    cfg,
    1 * 1024 * 1024,
  );
  quiche.quiche_config_set_initial_max_stream_data_uni(cfg, 1 * 1024 * 1024);
  quiche.quiche_config_enable_dgram(cfg, true, 65536, 65536);

  final cert = 'cert.pem'.toNativeUtf8();
  final key = 'key.pem'.toNativeUtf8();
  quiche.quiche_config_load_cert_chain_from_pem_file(cfg, cert.cast());
  quiche.quiche_config_load_priv_key_from_pem_file(cfg, key.cast());
  malloc
    ..free(cert)
    ..free(key);

  // ----------------------------------------------------------
  // FIX 1: CORRECT ALPN ORDER + CORRECT LENGTHS
  // ----------------------------------------------------------
  // final alpn = <int>[
  //   // webtransport (12 bytes)
  //   0x0c,
  //   0x77, 0x65, 0x62, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74,

  //   // h3
  //   0x02, 0x68, 0x33,
  // ];
  final alpn = <int>[
    // webtransport (12 bytes)
    0x0c,
    0x77, 0x65, 0x62, 0x74, 0x72,
    0x61, 0x6e, 0x73, 0x70, 0x6f,
    0x72, 0x74,

    // h3 (2 bytes)
    0x02,
    0x68, 0x33,

    // h3-29 (5 bytes)
    0x05,
    0x68, 0x33, 0x2d, 0x32, 0x39,
  ];

  final alpnPtr = malloc<ffi.Uint8>(alpn.length)
    ..asTypedList(alpn.length).setAll(0, alpn);
  quiche.quiche_config_set_application_protos(cfg, alpnPtr, alpn.length);
  malloc.free(alpnPtr);

  final sock = await RawDatagramSocket.bind(InternetAddress('0.0.0.0'), 4433);
  print("🟢 Server listening on 0.0.0.0:4433");

  // ----------------------------
  //  PERIODIC TIMER
  // ----------------------------
  Timer.periodic(const Duration(milliseconds: 20), (_) {
    final keys = List<String>.from(_conns.keys);
    for (final k in keys) {
      final ctx = _conns[k]!;
      quiche.quiche_conn_on_timeout(ctx.conn);

      _tryCreateH3(quiche, sock, ctx);
      _pollH3(quiche, sock, ctx);
      _drainDatagrams(quiche, sock, ctx);
      _flush(quiche, sock, ctx);

      if (_isClosed(quiche, ctx.conn)) {
        print("🔒 Closed $k");
        ctx.sessions.values.forEach((s) => sessions.remove(s.sid));
        _conns.remove(k);
      }
    }
  });

  // ----------------------------
  //  RECV LOOP
  // ----------------------------
  sock.listen((ev) {
    if (ev != RawSocketEvent.read) return;
    final dg = sock.receive();
    if (dg == null) return;

    final peerKey = "${dg.address.address}:${dg.port}";

    final localSA = _sockAddr(sock.address.address, sock.port);
    final peerSA = _sockAddr(dg.address.address, dg.port);

    final ctx = _conns[peerKey] ?? _accept(quiche, cfg, localSA, peerSA);
    _conns.putIfAbsent(peerKey, () => ctx);

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

    if (_isEstablished(quiche, ctx.conn)) {
      if (!ctx.estLogged) {
        ctx.estLogged = true;
        ctx.establishedAt = DateTime.now();
        print(
          "✅ QUIC established with ${ctx.peerAddr}:${ctx.peerPort} "
          "(ALPN=\"${_negotiatedAlpn(quiche, ctx.conn)}\")",
        );
      }

      _tryCreateH3(quiche, sock, ctx);
    }

    _flush(quiche, sock, ctx);
  });
}

// ----------------------------
//  ACCEPT
// ----------------------------
_ConnCtx _accept(
  QuicheBindings quiche,
  ffi.Pointer<quiche_config> cfg,
  ffi.Pointer<ffi.Uint8> local,
  ffi.Pointer<ffi.Uint8> peer,
) {
  final scid = List<int>.generate(16, (_) => Random.secure().nextInt(255));
  final p = malloc<ffi.Uint8>(scid.length)
    ..asTypedList(scid.length).setAll(0, scid);

  final conn = quiche.quiche_accept(
    p,
    scid.length,
    ffi.nullptr,
    0,
    local.cast(),
    16,
    peer.cast(),
    16,
    cfg,
  );

  malloc.free(p);

  return _ConnCtx(
    conn: conn,
    scid: scid,
    serverAddr: InternetAddress("127.0.0.1"),
    peerAddr: InternetAddress.anyIPv4,
  );
}

// ----------------------------
//  H3 CREATION
// ----------------------------
void _tryCreateH3(
  QuicheBindings q,
  RawDatagramSocket sock,
  _ConnCtx ctx, {
  int debounceMs = 50,
}) {
  if (ctx.h3 != null) return;
  if (!_isEstablished(q, ctx.conn)) return;
  if (_inEarlyData(q, ctx.conn)) return;

  if (ctx.establishedAt == null ||
      DateTime.now().difference(ctx.establishedAt!).inMilliseconds < debounceMs)
    return;

  print("🧪 Trying H3 creation…");

  final h3cfg = q.quiche_h3_config_new();
  q.quiche_h3_config_enable_extended_connect(h3cfg, true);

  final h3 = q.quiche_h3_conn_new_with_transport(ctx.conn, h3cfg);
  if (h3 != ffi.nullptr) {
    ctx.h3 = h3;
    print("✅ H3 created (SETTINGS sent)");
  }

  q.quiche_h3_config_free(h3cfg);
}

// ----------------------------
//  H3 POLLING
// ----------------------------
void _pollH3(QuicheBindings q, RawDatagramSocket sock, _ConnCtx ctx) {
  if (ctx.h3 == null) return;

  final evPtr = malloc<ffi.Pointer<quiche_h3_event>>();

  try {
    while (true) {
      final sid = q.quiche_h3_conn_poll(ctx.h3!, ctx.conn, evPtr);
      if (sid < 0) break;

      final ev = evPtr.value;
      if (ev == ffi.nullptr) continue;

      final evType = q.quiche_h3_event_type1(ev);

      // -------- HEADERS --------
      if (evType == 0) {
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

        q.quiche_h3_event_for_each_header(ev, cb, token.cast());

        final req = _headersBox.remove(token.address)!;
        malloc.free(token);

        print(
          "🧭 HEADERS stream=$sid method='${req.method}' "
          "path='${req.path}' proto='${req.protocol}'",
        );

        final isConnect = req.method.toUpperCase() == "CONNECT";
        final isWT = req.protocol == "webtransport";
        final isPathOk = req.path == WT_PATH;

        if (isConnect && isWT && isPathOk) {
          // ---- send OK response ----
          final hdrs = malloc<quiche_h3_header>(3);

          final fields = <(String, String)>[
            (":status", "200"),
            ("server", "dart-quiche-wt"),
            (WT_DRAFT_HEADER, WT_DRAFT_VALUE),
          ];

          for (int i = 0; i < fields.length; i++) {
            final (n, v) = fields[i];
            final np = n.toNativeUtf8();
            final vp = v.toNativeUtf8();

            hdrs[i].name = np.cast();
            hdrs[i].name_len = n.codeUnits.length;
            hdrs[i].value = vp.cast();
            hdrs[i].value_len = v.codeUnits.length;
          }

          q.quiche_h3_send_response(ctx.h3!, ctx.conn, sid, hdrs, 3, false);
          _flush(q, sock, ctx);

          // register new session
          final cid = _nextClientId++;
          final session = _Session(
            sid: sid,
            clientId: cid,
            connKey: "${ctx.peerAddr.address}:${ctx.peerPort}",
          );
          ctx.sessions[sid] = session;
          sessions[sid] = session;

          print("🎉 WebTransport CONNECT accepted → clientId=$cid");

          malloc.free(hdrs);
        }
      }

      q.quiche_h3_event_free(ev);
    }
  } finally {
    malloc.free(evPtr);
  }
}

// ----------------------------
//  DATAGRAM RECEIVING (unchanged)
// ----------------------------
void _drainDatagrams(QuicheBindings q, RawDatagramSocket sock, _ConnCtx ctx) {
  final buf = malloc<ffi.Uint8>(65536);
  try {
    while (true) {
      final n = q.quiche_conn_dgram_recv(ctx.conn, buf, 65536);
      if (n <= 0) break;

      final raw = buf.asTypedList(n);
      try {
        final stanza = jsonDecode(utf8.decode(raw)) as Map<String, dynamic>;
        if (stanza['type'] == 'presence') {
          final out = utf8.encode(jsonEncode(stanza));
          for (final other in _conns.values) {
            q.quiche_conn_dgram_send(other.conn, out.asPtr(), out.length);
          }
        }
      } catch (_) {}
    }
  } finally {
    malloc.free(buf);
  }
}

// ----------------------------
//  STREAM SEND (unchanged ABI)
// ----------------------------
void _sendWTUniToSession(QuicheBindings q, _Session s, List<int> payload) {
  final ctx = _conns[s.connKey];
  if (ctx == null) return;

  final header = <int>[]
    ..addAll(_encodeVarint(WT_STREAM_TYPE_UNI))
    ..addAll(_encodeVarint(s.sid));

  final full = Uint8List.fromList([...header, ...payload]);
  final p = malloc<ffi.Uint8>(full.length)
    ..asTypedList(full.length).setAll(0, full);

  final sentPtr = malloc<ffi.Uint64>();

  q.quiche_conn_stream_send(
    ctx.conn,
    ctx.nextServerUni,
    p,
    full.length,
    true,
    sentPtr,
  );

  ctx.nextServerUni += 4;

  malloc
    ..free(p)
    ..free(sentPtr);
}

void _flush(QuicheBindings q, RawDatagramSocket sock, _ConnCtx ctx) {
  final out = malloc<ffi.Uint8>(1500);
  final si = malloc<quiche_send_info>();

  while (true) {
    final n = q.quiche_conn_send(ctx.conn, out, 1500, si);
    if (n <= 0) break;
    sock.send(out.asTypedList(n), ctx.peerAddr, ctx.peerPort);
  }

  malloc
    ..free(out)
    ..free(si);
}

ffi.Pointer<ffi.Uint8> _sockAddr(String ip, int port) {
  final p = malloc<ffi.Uint8>(16);
  final v = p.asTypedList(16)..fillRange(0, 16, 0);

  v[0] = 0x02;
  v[2] = (port >> 8) & 0xff;
  v[3] = port & 0xff;

  final nums = ip.split('.').map(int.parse).toList();
  for (int i = 0; i < 4; i++) v[4 + i] = nums[i];

  return p;
}

extension _AsPtr on List<int> {
  ffi.Pointer<ffi.Uint8> asPtr() {
    final p = malloc<ffi.Uint8>(length);
    p.asTypedList(length).setAll(0, this);
    return p;
  }
}
