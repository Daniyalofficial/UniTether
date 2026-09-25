/**
 * Node ULP conformance test: runs every golden vector from
 * protocol/vectors/*.json through the Node codec, plus the full
 * session-key equality gate (X25519 + HKDF) that proves the Node stack
 * derives identical keys to the Python reference (and the Rust host).
 *
 *   node tests/node/test.mjs
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as ulp from './ulplink.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vecDir = join(here, '..', '..', 'protocol', 'vectors');
const load = (n) => JSON.parse(readFileSync(join(vecDir, n), 'utf8'));

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { pass++; }
  else { fail++; failures.push(`${name}${detail ? `: ${detail}` : ''}`); }
}
const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));

// ---------------------------------------------------------------- frames
for (const v of load('frames.json').vectors) {
  const { header, wire } = ulp.encodeFrame(v.channel, v.flags, unhex(v.payload));
  check(`frame:${v.name}`, hex(wire) === v.expected, `${hex(wire)} != ${v.expected}`);
  const d = ulp.decodeFrame(unhex(v.expected));
  check(`frame:${v.name}:decode`,
    d.channel === v.channel && d.flags === v.flags && hex(d.payload) === v.payload && d.next === v.expected.length / 2);
}

// ---------------------------------------------------------------- crypto
for (const v of load('crypto.json').vectors) {
  switch (v.kind) {
    case 'x25519_pub': {
      check(`crypto:${v.name}`, hex(ulp.x25519PublicKey(unhex(v.secret))) === v.expected);
      break;
    }
    case 'x25519': {
      check(`crypto:${v.name}`, hex(ulp.x25519(unhex(v.secret), unhex(v.pub))) === v.expected);
      break;
    }
    case 'hkdf': {
      const { createHmac } = await import('node:crypto');
      const { hkdfSync } = await import('node:crypto');
      const out = hkdfSync('sha256', unhex(v.ikm), unhex(v.salt), unhex(v.info), v.length);
      check(`crypto:${v.name}`, hex(out) === v.expected);
      break;
    }
    case 'interop': {
      const ct = ulp.interopEncrypt(unhex(v.key_aead), unhex(v.key_mac), unhex(v.nonce), unhex(v.aad), unhex(v.pt));
      check(`crypto:${v.name}`, hex(ct) === v.expected, `${hex(ct)} != ${v.expected}`);
      const pt = ulp.interopDecrypt(unhex(v.key_aead), unhex(v.key_mac), unhex(v.nonce), unhex(v.aad), unhex(v.expected));
      check(`crypto:${v.name}:decrypt`, hex(pt) === v.pt);
      break;
    }
    case 'frame_nonce': {
      check(`crypto:${v.name}`, hex(ulp.frameNonce(v.counter, v.channel, v.direction)) === v.expected);
      break;
    }
  }
}

// --------------------------------------------- SESSION-KEY EQUALITY GATE
// X25519(secret, peer) + HKDF must equal the Python reference's 64 B keys.
{
  const crypto = load('crypto.json').vectors;
  const x = crypto.find((c) => c.name === 'rfc7748_shared');
  const k = crypto.find((c) => c.name === 'hkdf_session_keys');
  const shared = ulp.x25519(unhex(x.secret), unhex(x.pub));
  check('session:shared', hex(shared) === x.expected);
  const keys = ulp.sessionKeys(shared,
    unhex(k.salt.slice(0, 32)), unhex(k.salt.slice(32, 64)), 0x01);
  check('session:key_aead', hex(keys.keyAead) === k.expected.slice(0, 64),
    `${hex(keys.keyAead)} != ${k.expected.slice(0, 64)}`);
  check('session:key_mac', hex(keys.keyMac) === k.expected.slice(64, 128),
    `${hex(keys.keyMac)} != ${k.expected.slice(64, 128)}`);
}

// --------------------------------------------------------------- messages
for (const v of load('messages.json').vectors) {
  switch (v.kind) {
    case 'hello': {
      const body = ulp.helloBody(v.role, v.feature_mask, v.cipher_pref, unhex(v.ecdh_pub), unhex(v.nonce_a), unhex(v.secret));
      check(`msg:${v.name}`, hex(body) === v.expected);
      break;
    }
    case 'hello_ack': {
      const body = ulp.helloAckBody(v.negotiated, v.cipher_sel, unhex(v.ecdh_pub), unhex(v.nonce_b), unhex(v.nonce_a), unhex(v.secret));
      check(`msg:${v.name}`, hex(body) === v.expected);
      break;
    }
    case 'config': {
      const body = ulp.configBody({
        v4Prefix: v.v4_prefix, v4Device: unhex(v.v4_device), v4Host: unhex(v.v4_host),
        v6Prefix: v.v6_prefix, v6Device: unhex(v.v6_device), v6Host: unhex(v.v6_host),
        dns: v.dns.map(unhex), routes: v.routes.map(([p, a]) => [p, unhex(a)]),
      });
      check(`msg:${v.name}`, hex(body) === v.expected);
      break;
    }
    case 'qos': {
      const body = ulp.qosBody(v.profile, v.up_kbps, v.down_kbps, v.latency_ms, v.jitter_ms, v.loss_pct);
      check(`msg:${v.name}`, hex(body) === v.expected);
      break;
    }
    case 'stats': {
      const body = ulp.statsBody({
        bytesIn: v.bytes_in, bytesOut: v.bytes_out, pktsIn: v.pkts_in, pktsOut: v.pkts_out,
        bytesVideo: v.bytes_video, bytesAudio: v.bytes_audio, bytesFile: v.bytes_file,
        drops: v.drops, errors: v.errors, framesVideo: v.frames_video,
        rttMs: v.rtt_ms, lossPctX100: v.loss_pct_x100, cpuPctX100: v.cpu_pct_x100,
        fpsVideo: v.fps_video, audioLevel: v.audio_level,
      });
      check(`msg:${v.name}`, hex(body) === v.expected);
      break;
    }
    case 'mute': {
      const body = ulp.msgEncode(ulp.MSG.MUTE, Uint8Array.from([v.mask]));
      check(`msg:${v.name}`, hex(body) === v.expected);
      break;
    }
    case 'msg': {
      const d = ulp.msgDecode(unhex(v.expected));
      const want = { auth_ok: [4, 0], ping: [5, 8], bye: [15, 1], error_auth: [16, 14] }[v.name];
      check(`msg:${v.name}`, want && d.mtype === want[0] && d.body.length === want[1]);
      break;
    }
  }
}

// --------------------------------------------------------------- channels
for (const v of load('channels.json').vectors) {
  switch (v.kind) {
    case 'video': {
      const body = ulp.VideoFrame.encode({ kind: v.kind_field, codec: v.codec, width: v.width, height: v.height, fps: v.fps, pts_ms: v.pts_ms, seq: v.seq, nal: unhex(v.nal) });
      check(`ch:${v.name}`, hex(body) === v.expected);
      break;
    }
    case 'audio': {
      const body = ulp.AudioFrame.encode({ codec: v.codec, rate: v.rate, ch: v.ch, seq: v.seq, pts_ms: v.pts_ms, data: unhex(v.data) });
      check(`ch:${v.name}`, hex(body) === v.expected);
      break;
    }
    case 'input': {
      const body = ulp.InputEvent.encode({ ty: v.type_field, action: v.action, x: v.x, y: v.y, key: 0, text: v.text ?? '' });
      check(`ch:${v.name}`, hex(body) === v.expected);
      break;
    }
    case 'file_meta': {
      const body = ulp.FileOp.meta(v.direction, v.file_id, v.total_size, v.name);
      check(`ch:${v.name}`, hex(body) === v.expected);
      break;
    }
    case 'file_data': {
      const body = ulp.FileOp.data(v.direction, v.file_id, v.seq, v.offset, unhex(v.chunk));
      check(`ch:${v.name}`, hex(body) === v.expected);
      break;
    }
    case 'clipboard': {
      const body = ulp.ClipboardUpdate.encode(v.direction, v.kind_field, Buffer.from(v.data, 'utf8'));
      check(`ch:${v.name}`, hex(body) === v.expected);
      break;
    }
    case 'notification': {
      const body = ulp.Notification.encode({ id: v.id, ts_ms: v.ts_ms, action: v.action, app: v.app, title: v.title, body: v.body });
      check(`ch:${v.name}`, hex(body) === v.expected);
      break;
    }
  }
}

// ---------------------------------------------------------------- pairing
for (const v of load('pairing.json').vectors) {
  const blob = ulp.pairingBlob(unhex(v.secret), v.name);
  check(`pairing:${v.name}`, blob === v.expected, `${blob} != ${v.expected}`);
  const { secret, name } = ulp.pairingParse(blob);
  check(`pairing:${v.name}:parse`, hex(secret) === v.secret && name === v.name);
}

// ---------------------------------------------------------------- summary
console.log(`NODE ULP CONFORMANCE: ${pass} pass, ${fail} fail`);
if (failures.length) {
  console.log('failures:');
  for (const f of failures) console.log('  ' + f);
  process.exit(1);
}
console.log('  - frames, crypto, session keys, messages, channels, pairing: ALL PASS');
