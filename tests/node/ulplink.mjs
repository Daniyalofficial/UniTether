/**
 * UniLink Protocol (ULP) v1 — Node.js conformance codec.
 *
 * Third independent implementation of docs/02-PROTOCOL.md, alongside the
 * Python reference and the Rust host crate. Node 18+ (crypto.hkdfSync,
 * crypto.diffieHellman with X25519). No dependencies.
 */
import { createHash, createHmac, hkdfSync, diffieHellman, createPrivateKey, createPublicKey } from 'node:crypto';

// ---------------------------------------------------------------- constants
export const MAGIC0 = 0x55, MAGIC1 = 0x4c, VERSION = 0x01;
export const MAX_PAYLOAD = 0x0010_0000;

export const CH = {
  CONTROL: 0x00, VIDEO: 0x01, AUDIO_IN: 0x02, AUDIO_OUT: 0x03, INPUT: 0x04,
  FILE: 0x05, CLIPBOARD: 0x06, NOTIFICATION: 0x07, STATS: 0x08, TUN_V4: 0x09,
  TUN_V6: 0x0a, PROXY: 0x0b, CAMERA: 0x0c, USER: 0x0d,
};
export const F = { COMPRESSED: 0x01, ENCRYPTED: 0x02, FRAG: 0x04, PRIORITY: 0x08, ACK: 0x10 };

export const MSG = {
  HELLO: 0x01, HELLO_ACK: 0x02, AUTH_OK: 0x04, PING: 0x05, PONG: 0x06,
  CONFIG: 0x07, TUN_UP: 0x08, TUN_DOWN: 0x09, STATS_REQ: 0x0a, STATS_RSP: 0x0b,
  MUTE: 0x0c, QOS: 0x0d, RESUME: 0x0e, BYE: 0x0f, ERROR: 0x10,
};
export const CIPHER = { NONE: 0, INTEROP: 1, AESGCM: 2, CHACHA: 3 };

// ----------------------------------------------------------------- framing
export function encodeFrame(channel, flags, payload) {
  if (payload.length > MAX_PAYLOAD) throw new Error('payload exceeds 1 MiB');
  const h = new Uint8Array(payload.length >= 0x8000 ? 11 : 7);
  h[0] = MAGIC0; h[1] = MAGIC1; h[2] = VERSION; h[3] = channel; h[4] = flags;
  if (payload.length >= 0x8000) {
    h[5] = 0x80; h[6] = 0x00;
    h[7] = 0; h[8] = 0; h[9] = (payload.length >>> 8) & 0xff; h[10] = payload.length & 0xff;
  } else {
    h[5] = (payload.length >>> 8) & 0xff; h[6] = payload.length & 0xff;
  }
  const out = new Uint8Array(h.length + payload.length);
  out.set(h, 0); out.set(payload, h.length);
  return { header: h, wire: out };
}

export function decodeFrame(buf, off = 0) {
  if (buf.length - off < 7) throw new Error('incomplete header');
  const d = (i) => buf[off + i];
  if (d(0) !== MAGIC0 || d(1) !== MAGIC1) throw new Error('bad magic');
  if (d(2) !== VERSION) throw new Error('bad version');
  const channel = d(3), flags = d(4);
  const ln = (d(5) << 8) | d(6);
  let size, headerLen;
  if (ln < 0x8000) { size = ln; headerLen = 7; }
  else if (ln === 0x8000) {
    if (buf.length - off < 11) throw new Error('incomplete extended length');
    size = (d(7) << 24) | (d(8) << 16) | (d(9) << 8) | d(10);
    if (size > MAX_PAYLOAD) throw new Error('bad extended length');
    headerLen = 11;
  } else throw new Error(`bad length field ${ln.toString(16)}`);
  if (buf.length - off < headerLen + size) throw new Error('incomplete frame');
  const header = buf.slice(off, off + headerLen);
  const payload = buf.slice(off + headerLen, off + headerLen + size);
  return { channel, flags, payload, header, next: off + headerLen + size };
}

export function frameNonce(counter, channel, direction) {
  const c = BigInt(counter);
  const hi = (BigInt(direction & 1) << 63n) | (c & ((1n << 63n) - 1n));
  const n = new Uint8Array(12);
  const hi64 = hi.toString(16).padStart(16, '0');
  for (let i = 0; i < 8; i++) n[i] = parseInt(hi64.slice(i * 2, i * 2 + 2), 16);
  n[8] = 0; n[9] = 0; n[10] = (channel >> 8) & 0xff; n[11] = channel & 0xff;
  return n;
}

// --------------------------------------------------------------- messages
export function msgEncode(mtype, body) {
  const out = new Uint8Array(4 + body.length);
  out[0] = mtype; out[1] = 0;
  out[2] = (body.length >> 8) & 0xff; out[3] = body.length & 0xff;
  out.set(body, 4);
  return out;
}
export function msgDecode(payload) {
  if (payload.length < 4) throw new Error('short message');
  const mtype = payload[0], flags = payload[1];
  const blen = (payload[2] << 8) | payload[3];
  if (payload.length < 4 + blen) throw new Error('short message body');
  return { mtype, flags, body: payload.slice(4, 4 + blen) };
}

// ---------------------------------------------------------------- channel
export const VideoFrame = {
  encode(f) {
    const b = new Uint8Array(15 + f.nal.length);
    b[0] = f.kind; b[1] = f.codec;
    b[2] = (f.width >> 8) & 0xff; b[3] = f.width & 0xff;
    b[4] = (f.height >> 8) & 0xff; b[5] = f.height & 0xff;
    b[6] = f.fps;
    b[7] = (f.pts_ms >> 24) & 0xff; b[8] = (f.pts_ms >> 16) & 0xff;
    b[9] = (f.pts_ms >> 8) & 0xff; b[10] = f.pts_ms & 0xff;
    b[11] = (f.seq >> 24) & 0xff; b[12] = (f.seq >> 16) & 0xff;
    b[13] = (f.seq >> 8) & 0xff; b[14] = f.seq & 0xff;
    b.set(f.nal, 15);
    return b;
  },
  parse(body) {
    if (body.length < 15) throw new Error('short video');
    return {
      kind: body[0], codec: body[1],
      width: (body[2] << 8) | body[3], height: (body[4] << 8) | body[5],
      fps: body[6],
      pts_ms: (body[7] << 24) >>> 0 | (body[8] << 16) | (body[9] << 8) | body[10],
      seq: (body[11] << 24) >>> 0 | (body[12] << 16) | (body[13] << 8) | body[14],
      nal: body.slice(15),
    };
  },
};

export const AudioFrame = {
  encode(f) {
    const b = new Uint8Array(12 + f.data.length);
    b[0] = f.codec; b[1] = (f.rate >> 8) & 0xff; b[2] = f.rate & 0xff; b[3] = f.ch;
    b[4] = (f.seq >>> 24) & 0xff; b[5] = (f.seq >> 16) & 0xff;
    b[6] = (f.seq >> 8) & 0xff; b[7] = f.seq & 0xff;
    b[8] = (f.pts_ms >>> 24) & 0xff; b[9] = (f.pts_ms >> 16) & 0xff;
    b[10] = (f.pts_ms >> 8) & 0xff; b[11] = f.pts_ms & 0xff;
    b.set(f.data, 12);
    return b;
  },
  parse(body) {
    if (body.length < 12) throw new Error('short audio');
    return {
      codec: body[0], rate: (body[1] << 8) | body[2], ch: body[3],
      seq: (body[4] << 24) >>> 0 | (body[5] << 16) | (body[6] << 8) | body[7],
      pts_ms: (body[8] << 24) >>> 0 | (body[9] << 16) | (body[10] << 8) | body[11],
      data: body.slice(12),
    };
  },
};

export const InputEvent = {
  encode(ev) {
    const t = Buffer.from(ev.text, 'utf8');
    const b = new Uint8Array(10 + t.length);
    b[0] = ev.ty; b[1] = ev.action;
    b[2] = (ev.x >> 8) & 0xff; b[3] = ev.x & 0xff;
    b[4] = (ev.y >> 8) & 0xff; b[5] = ev.y & 0xff;
    b[6] = (ev.key >> 8) & 0xff; b[7] = ev.key & 0xff;
    b[8] = (t.length >> 8) & 0xff; b[9] = t.length & 0xff;
    b.set(t, 10);
    return b;
  },
  parse(body) {
    if (body.length < 10) throw new Error('short input');
    const tl = (body[8] << 8) | body[9];
    return {
      ty: body[0], action: body[1],
      x: (body[2] << 8) | body[3], y: (body[4] << 8) | body[5],
      key: (body[6] << 8) | body[7],
      text: Buffer.from(body.slice(10, 10 + tl)).toString('utf8'),
    };
  },
};

export const FileOp = {
  meta(d, id, total, name) {
    const n = Buffer.from(name, 'utf8');
    const b = new Uint8Array(16 + n.length);
    b[0] = 0x00; b[1] = d;
    b[2] = (id >>> 24) & 0xff; b[3] = (id >> 16) & 0xff; b[4] = (id >> 8) & 0xff; b[5] = id & 0xff;
    const ts = BigInt(total);
    b[6] = Number((ts >> 56n) & 0xffn); b[7] = Number((ts >> 48n) & 0xffn);
    b[8] = Number((ts >> 40n) & 0xffn); b[9] = Number((ts >> 32n) & 0xffn);
    b[10] = Number((ts >> 24n) & 0xffn); b[11] = Number((ts >> 16n) & 0xffn);
    b[12] = Number((ts >> 8n) & 0xffn); b[13] = Number(ts & 0xffn);
    b[14] = (n.length >> 8) & 0xff; b[15] = n.length & 0xff;
    b.set(n, 16);
    return b;
  },
  data(d, id, seq, offset, chunk) {
    const b = new Uint8Array(18 + chunk.length);
    b[0] = 0x01; b[1] = d;
    b[2] = (id >>> 24) & 0xff; b[3] = (id >> 16) & 0xff; b[4] = (id >> 8) & 0xff; b[5] = id & 0xff;
    b[6] = (seq >>> 24) & 0xff; b[7] = (seq >> 16) & 0xff; b[8] = (seq >> 8) & 0xff; b[9] = seq & 0xff;
    const o = BigInt(offset);
    b[10] = Number((o >> 56n) & 0xffn); b[11] = Number((o >> 48n) & 0xffn);
    b[12] = Number((o >> 40n) & 0xffn); b[13] = Number((o >> 32n) & 0xffn);
    b[14] = Number((o >> 24n) & 0xffn); b[15] = Number((o >> 16n) & 0xffn);
    b[16] = Number((o >> 8n) & 0xffn); b[17] = Number(o & 0xffn);
    b.set(chunk, 18);
    return b;
  },
  parse(body) {
    if (body.length < 6) throw new Error('short file');
    const op = body[0], d = body[1];
    const id = (body[2] << 24) >>> 0 | (body[3] << 16) | (body[4] << 8) | body[5];
    switch (op) {
      case 0x00: {
        let total = 0n;
        for (let i = 6; i < 14; i++) total = (total << 8n) | BigInt(body[i]);
        const nl = (body[14] << 8) | body[15];
        return { op: 'meta', d, id, total, name: Buffer.from(body.slice(16, 16 + nl)).toString('utf8') };
      }
      case 0x01: {
        const seq = (body[6] << 24) >>> 0 | (body[7] << 16) | (body[8] << 8) | body[9];
        let offset = 0n;
        for (let i = 10; i < 18; i++) offset = (offset << 8n) | BigInt(body[i]);
        return { op: 'data', d, id, seq, offset, chunk: body.slice(18) };
      }
      case 0x02: return { op: 'ack', d, id, seqAck: (body[6] << 24) >>> 0 | (body[7] << 16) | (body[8] << 8) | body[9] };
      case 0x03: return { op: 'cancel', d, id };
      case 0x04: return { op: 'done', d, id };
      default: throw new Error(`bad file op ${op.toString(16)}`);
    }
  },
};

export const ClipboardUpdate = {
  encode(d, kind, data) {
    const b = new Uint8Array(2 + data.length);
    b[0] = d; b[1] = kind; b.set(data, 2);
    return b;
  },
  parse(body) {
    if (body.length < 2) throw new Error('short clipboard');
    return { d: body[0], kind: body[1], data: body.slice(2) };
  },
};

export const Notification = {
  encode(n) {
    const app = Buffer.from(n.app, 'utf8'), title = Buffer.from(n.title, 'utf8'), bodyB = Buffer.from(n.body, 'utf8');
    const b = new Uint8Array(13 + 2 * 3 + app.length + title.length + bodyB.length);
    b[0] = (n.id >>> 24) & 0xff; b[1] = (n.id >> 16) & 0xff; b[2] = (n.id >> 8) & 0xff; b[3] = n.id & 0xff;
    const ts = BigInt(n.ts_ms);
    for (let i = 0; i < 8; i++) b[4 + i] = Number((ts >> BigInt((7 - i) * 8)) & 0xffn);
    b[12] = n.action;
    let off = 13;
    for (const s of [app, title, bodyB]) {
      b[off] = (s.length >> 8) & 0xff; b[off + 1] = s.length & 0xff;
      b.set(s, off + 2); off += 2 + s.length;
    }
    return b;
  },
  parse(body) {
    if (body.length < 13) throw new Error('short notification');
    const id = (body[0] << 24) >>> 0 | (body[1] << 16) | (body[2] << 8) | body[3];
    let ts = 0n;
    for (let i = 4; i < 12; i++) ts = (ts << 8n) | BigInt(body[i]);
    const fields = [];
    let off = 13;
    for (let i = 0; i < 3; i++) {
      const l = (body[off] << 8) | body[off + 1]; off += 2;
      fields.push(Buffer.from(body.slice(off, off + l)).toString('utf8')); off += l;
    }
    return { id, ts_ms: Number(ts), action: body[12], app: fields[0], title: fields[1], body: fields[2] };
  },
};

// ------------------------------------------------------------------- crypto
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
export function base64urlEncode(buf) {
  const b = Buffer.from(buf);
  let out = '';
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i] << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    out += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63]
      + (i + 1 < b.length ? B64URL[(n >> 6) & 63] : '=')
      + (i + 2 < b.length ? B64URL[n & 63] : '=');
  }
  return out;
}
export function base64urlDecode(s) {
  let n = s.length;
  while (n > 0 && s[n - 1] === '=') n--;
  if (n % 4 === 1) throw new Error('bad base64 length');
  let acc = 0, bits = 0;
  const out = [];
  for (let i = 0; i < n; i++) {
    const c = s[i];
    const v = c >= 'A' && c <= 'Z' ? c.charCodeAt(0) - 65
      : c >= 'a' && c <= 'z' ? c.charCodeAt(0) - 71
      : c >= '0' && c <= '9' ? c.charCodeAt(0) - 48 + 52
      : c === '-' || c === '+' ? 62
      : c === '_' || c === '/' ? 63
      : (() => { throw new Error('bad base64 char'); })();
    acc = ((acc & ((1 << bits) - 1)) << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
  }
  return Uint8Array.from(out);
}

export function pairingBlob(secret, name) {
  const nb = Buffer.from(name, 'utf8').subarray(0, 32).toString('utf8');
  return `UNITETHER1:${base64urlEncode(secret)}|${nb}`;
}
export function pairingParse(blob) {
  if (!blob.startsWith('UNITETHER1:')) throw new Error('bad pairing prefix');
  const rest = blob.slice('UNITETHER1:'.length);
  const idx = rest.indexOf('|');
  const b64 = idx >= 0 ? rest.slice(0, idx) : rest;
  const name = idx >= 0 ? rest.slice(idx + 1) : '';
  const secret = base64urlDecode(b64);
  if (secret.length !== 32) throw new Error('bad secret length');
  return { secret, name };
}

// X25519 via node:crypto
const X25519_OID = '2b656e';
function pkcs8Wrap(raw32) {
  return Buffer.concat([
    Buffer.from('302e020100300506032b656e04220420', 'hex'), raw32,
  ]);
}
function spkiWrap(raw32) {
  return Buffer.concat([
    Buffer.from('302a300506032b656e032100', 'hex'), raw32,
  ]);
}
export function x25519PublicKey(secret) {
  const priv = createPrivateKey({ key: pkcs8Wrap(Buffer.from(secret)), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(priv);
  const spki = pub.export({ format: 'der', type: 'spki' });
  return spki.subarray(spki.length - 32);
}
export function x25519(secret, peerPub) {
  const priv = createPrivateKey({ key: pkcs8Wrap(Buffer.from(secret)), format: 'der', type: 'pkcs8' });
  const pubKeyObj = createPublicKey({ key: spkiWrap(Buffer.from(peerPub)), format: 'der', type: 'spki' });
  const shared = diffieHellman({ privateKey: priv, publicKey: pubKeyObj });
  return new Uint8Array(shared);
}

export function sessionKeys(shared, nonceA, nonceB, cipherSel) {
  const salt = Buffer.concat([Buffer.from(nonceA), Buffer.from(nonceB)]);
  const info = Buffer.concat([Buffer.from('unilink-v1'), Buffer.from([cipherSel])]);
  const keys = new Uint8Array(hkdfSync('sha256', Buffer.from(shared), salt, info, 64));
  return { keyAead: keys.slice(0, 32), keyMac: keys.slice(32, 64) };
}

// INTEROP AEAD
export function interopKeystream(keyAead, nonce, n) {
  const out = [];
  let i = 0;
  while (out.length < n) {
    const block = createHash('sha256')
      .update(keyAead).update(nonce)
      .update(Buffer.from([(i >> 24) & 0xff, (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff]))
      .digest();
    out.push(block); i++;
  }
  return Buffer.concat(out).subarray(0, n);
}
export function interopEncrypt(keyAead, keyMac, nonce, aad, pt) {
  const ks = interopKeystream(keyAead, nonce, pt.length);
  const ct = Buffer.from(pt);
  for (let i = 0; i < ct.length; i++) ct[i] ^= ks[i];
  const tag = createHmac('sha256', Buffer.from(keyMac)).update(Buffer.from(nonce)).update(aad).update(ct).digest().subarray(0, 16);
  return Buffer.concat([ct, tag]);
}
export function interopDecrypt(keyAead, keyMac, nonce, aad, ctTag) {
  if (ctTag.length < 16) throw new Error('interop: too short');
  const ct = ctTag.subarray(0, ctTag.length - 16);
  const tag = ctTag.subarray(ctTag.length - 16);
  const expect = createHmac('sha256', Buffer.from(keyMac)).update(Buffer.from(nonce)).update(aad).update(ct).digest().subarray(0, 16);
  if (!expect.equals(Buffer.from(tag))) throw new Error('interop: tag mismatch');
  const ks = interopKeystream(keyAead, nonce, ct.length);
  const pt = Buffer.from(ct);
  for (let i = 0; i < pt.length; i++) pt[i] ^= ks[i];
  return pt;
}

// HELLO / HELLO_ACK
const AUTH_INFO = 'unilink-auth-v1';
export function pairingMac(secret, pub, nonce) {
  return createHmac('sha256', Buffer.from(secret)).update(AUTH_INFO).update(Buffer.from(pub)).update(Buffer.from(nonce)).digest();
}
export function helloBody(role, featureMask, cipherPref, pub, nonceA, secret) {
  const mac = pairingMac(secret, pub, nonceA);
  const b = new Uint8Array(84);
  b[0] = role; b[1] = (featureMask >> 8) & 0xff; b[2] = featureMask & 0xff;
  b[3] = cipherPref;
  b.set(pub, 4); b.set(nonceA, 36); b.set(mac, 52);
  return b;
}
export function helloAckBody(negotiated, cipherSel, pub, nonceB, nonceA, secret) {
  const mac = createHmac('sha256', Buffer.from(secret))
    .update(AUTH_INFO).update(Buffer.from(pub)).update(Buffer.from(nonceB)).update(Buffer.from(nonceA)).digest();
  const b = new Uint8Array(83);
  b[0] = (negotiated >> 8) & 0xff; b[1] = negotiated & 0xff; b[2] = cipherSel;
  b.set(pub, 3); b.set(nonceB, 35); b.set(mac, 51);
  return b;
}

// CONFIG / QOS / STATS
export function configBody(cfg) {
  const dns = cfg.dns ?? [];
  const routes = cfg.routes ?? [];
  const parts = [];
  parts.push(Buffer.from([cfg.v4Prefix]));
  parts.push(Buffer.from(cfg.v4Device));
  parts.push(Buffer.from(cfg.v4Host));
  parts.push(Buffer.from([cfg.v6Prefix]));
  if (cfg.v6Prefix > 0) { parts.push(Buffer.from(cfg.v6Device)); parts.push(Buffer.from(cfg.v6Host)); }
  const dcnt = Buffer.alloc(2); dcnt.writeUInt16BE(dns.length);
  parts.push(dcnt); dns.forEach((d) => parts.push(Buffer.from(d)));
  const rcnt = Buffer.alloc(2); rcnt.writeUInt16BE(routes.length);
  parts.push(rcnt); routes.forEach(([p, a]) => parts.push(Buffer.concat([Buffer.from([p]), Buffer.from(a)])));
  return Buffer.concat(parts);
}
export function qosBody(profile, upKbps, downKbps, latencyMs, jitterMs, lossPct) {
  const b = Buffer.alloc(13);
  b[0] = profile;
  b.writeUInt32BE(upKbps, 1); b.writeUInt32BE(downKbps, 5);
  b.writeUInt16BE(latencyMs, 9); b[11] = jitterMs; b[12] = lossPct;
  return b;
}
export function statsBody(s) {
  const b = Buffer.alloc(104);
  const u64s = [s.bytesIn, s.bytesOut, s.pktsIn, s.pktsOut, s.bytesVideo, s.bytesAudio, s.bytesFile, s.drops, s.errors, s.framesVideo];
  u64s.forEach((v, i) => b.writeBigUInt64BE(BigInt(v), i * 8));
  b.writeUInt32BE(s.rttMs, 80);
  b.writeUInt32BE(s.lossPctX100, 84);
  b.writeUInt32BE(s.cpuPctX100, 88);
  b.writeUInt32BE(s.fpsVideo, 92);
  b.writeUInt32BE(s.audioLevel, 96);
  return b;
}
