/**
 * Node E2E host: speaks ULP over real TCP to the Python simulated device
 * (tests/e2e/device_sim.py). This is the cross-language interop gate:
 * Node X25519/HKDF/INTEROP-AEAD session vs the Python reference.
 *
 *   node tests/node/e2e.mjs --port 41887 --secret <64-hex>
 */
import net from 'node:net';
import * as ulp from './ulplink.mjs';

const args = Object.fromEntries(process.argv.slice(2).reduce((a, c, i, arr) => (c.startsWith('--') ? (a.push([c.slice(2), arr[i + 1]]), a) : a), []));
const PORT = Number(args.port ?? 41887);
const SECRET = Uint8Array.from(Buffer.from(args.secret ?? Buffer.alloc(32).toString('hex'), 'hex'));

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) pass++;
  else { fail++; failures.push(`${name}${detail ? `: ${detail}` : ''}`); }
  console.log(`  ${cond ? 'PASS' : 'FAIL'} ${name}`);
}

// ------------------------------------------------------- checksum helpers
function ipChecksum(buf) {
  if (buf.length % 2) buf = Buffer.concat([buf, Buffer.from([0])]);
  let s = 0;
  for (let i = 0; i < buf.length; i += 2) s += (buf[i] << 8) | buf[i + 1];
  while (s >> 16) s = (s & 0xffff) + (s >> 16);
  return (~s) & 0xffff;
}
function icmpv6Checksum(icmp, src, dst) {
  // Pseudo-header matching tests/e2e/device_sim.py exactly:
  // src(16) + dst(16) + u32be(plen) + 00 00 + u16be(58)
  const plen = Buffer.alloc(4);
  plen.writeUInt32BE(icmp.length);
  const pseudo = Buffer.concat([src, dst, plen, Buffer.from([0, 0, 0, 0x3a])]);
  return ipChecksum(Buffer.concat([pseudo, icmp]));
}

function buildIpv4Echo(seq, data) {
  const icmp = Buffer.alloc(8 + data.length);
  icmp[0] = 8; icmp[2] = 0; icmp[3] = 0;
  icmp.writeUInt16BE(0x1234, 4); icmp.writeUInt16BE(seq, 6);
  Buffer.from(data).copy(icmp, 8);
  const csum = ipChecksum(icmp);
  icmp.writeUInt16BE(csum, 2);
  const hdr = Buffer.alloc(20);
  hdr[0] = 0x45; hdr.writeUInt16BE(20 + icmp.length, 2); hdr.writeUInt16BE(0xBEEF, 4);
  hdr[8] = 64; hdr[9] = 1;
  hdr.writeUInt16BE(ipChecksum(hdr), 10);
  hdr.set([10, 8, 0, 1], 12); hdr.set([10, 8, 0, 2], 16);
  return Buffer.concat([hdr, icmp]);
}
function buildIpv6Echo(seq, data) {
  const icmp = Buffer.alloc(8 + data.length);
  icmp[0] = 128; icmp[2] = 0; icmp[3] = 0;
  icmp.writeUInt16BE(0x1234, 4); icmp.writeUInt16BE(seq, 6);
  Buffer.from(data).copy(icmp, 8);
  const src = Buffer.from('fd004c55010000000000000000000001', 'hex');
  const dst = Buffer.from('fd004c55010000000000000000000002', 'hex');
  icmp.writeUInt16BE(icmpv6Checksum(icmp, src, dst), 2);
  const hdr = Buffer.alloc(40);
  hdr[0] = 0x60; hdr.writeUInt16BE(icmp.length, 4); hdr[6] = 58; hdr[7] = 64;
  src.copy(hdr, 8); dst.copy(hdr, 24);
  return Buffer.concat([hdr, icmp]);
}

// -------------------------------------------------------------- link layer
class NodeLink {
  constructor(sock) {
    this.sock = sock;
    this.buf = Buffer.alloc(0);
    this.waiters = [];
    this.tx = 0; // host direction = 0
    this.rx = 0;
    this.ka = null; this.km = null;
    this.encrypted = false;
    sock.on('data', (d) => {
      this.buf = Buffer.concat([this.buf, d]);
      this._drain();
    });
    sock.on('error', (e) => this.waiters.splice(0).forEach((w) => w.reject(e)));
    sock.on('close', () => this.waiters.splice(0).forEach((w) => w.reject(new Error('closed'))));
  }
  _drain() {
    while (this.waiters.length) {
      const w = this.waiters[0];
      if (this.buf.length >= w.n) {
        const out = this.buf.subarray(0, w.n);
        this.buf = this.buf.subarray(w.n);
        this.waiters.shift();
        w.resolve(out);
      } else break;
    }
  }
  _need(n) {
    if (this.buf.length >= n) {
      const out = this.buf.subarray(0, n);
      this.buf = this.buf.subarray(n);
      return Promise.resolve(out);
    }
    return new Promise((resolve, reject) => this.waiters.push({ n, resolve, reject }));
  }
  async readFrame() {
    const hdr7 = await this._need(7);
    const ln = (hdr7[5] << 8) | hdr7[6];
    let hdr;
    if (ln === 0x8000) {
      const ext = await this._need(4);
      hdr = Buffer.concat([hdr7, ext]);
    } else hdr = hdr7;
    const size = ln === 0x8000
      ? (hdr[7] << 24) | (hdr[8] << 16) | (hdr[9] << 8) | hdr[10]
      : ln;
    const payload = await this._need(size);
    const channel = hdr[3], flags = hdr[4];
    const isEnc = (flags & ulp.F.ENCRYPTED) !== 0;
    if (isEnc) {
      const nonce = ulp.frameNonce(this.rx, channel, 1); // peer = device dir 1
      this.rx++;
      const pt = ulp.interopDecrypt(this.ka, this.km, nonce, hdr, payload);
      return { channel, flags: flags & ~ulp.F.ENCRYPTED, payload: pt };
    }
    return { channel, flags, payload };
  }
  sendFrame(channel, flags, payload) {
    if (this.encrypted) {
      const wireLen = payload.length + 16;
      const { header } = ulp.encodeFrame(channel, flags | ulp.F.ENCRYPTED,
        Buffer.alloc(wireLen));
      const nonce = ulp.frameNonce(this.tx, channel, 0);
      this.tx++;
      const ct = ulp.interopEncrypt(this.ka, this.km, nonce, header, payload);
      if (ct.length !== wireLen) throw new Error('interop length mismatch');
      this.sock.write(Buffer.concat([header, ct]));
    } else {
      const { wire } = ulp.encodeFrame(channel, flags, payload);
      this.sock.write(wire);
    }
  }
  sendMsg(mtype, body) { this.sendFrame(ulp.CH.CONTROL, 0, ulp.msgEncode(mtype, body)); }
  async recvMsg() {
    const f = await this.readFrame();
    if (f.channel !== ulp.CH.CONTROL) throw new Error(`expected control got ${f.channel.toString(16)}`);
    return ulp.msgDecode(f.payload);
  }
}

// ---------------------------------------------------------------- scenario
async function main() {
  console.log(`=== Node E2E host -> Python device (port ${PORT}) ===`);
  const sock = net.createConnection({ port: PORT, host: '127.0.0.1' });
  await new Promise((res, rej) => { sock.once('connect', res); sock.once('error', rej); });
  const link = new NodeLink(sock);

  // 1) handshake
  const priv = crypto.getRandomValues(new Uint8Array(32));
  const pub = ulp.x25519PublicKey(priv);
  const nonceA = crypto.getRandomValues(new Uint8Array(16));
  link.sendMsg(ulp.MSG.HELLO, ulp.helloBody(0, 0x00FF, ulp.CIPHER.INTEROP, pub, nonceA, SECRET));
  const helloAck = await link.recvMsg();
  check('handshake:HELLO_ACK', helloAck.mtype === ulp.MSG.HELLO_ACK);
  const ackBody = helloAck.body;
  check('handshake:mac', ackBody.length === 83);
  const shared = ulp.x25519(priv, Uint8Array.from(ackBody.subarray(3, 35)));
  const nonceB = ackBody.subarray(35, 51);
  const cipherSel = ackBody[2];
  const keys = ulp.sessionKeys(shared, nonceA, nonceB, cipherSel);
  link.ka = keys.keyAead; link.km = keys.keyMac;
  // AUTH_OK itself travels in plaintext; encryption starts AFTER both
  // AUTH_OKs are exchanged (spec 7.2).
  link.sendMsg(ulp.MSG.AUTH_OK, Buffer.alloc(0));
  const peerAuth = await link.recvMsg();
  check('handshake:AUTH_OK mutual', peerAuth.mtype === ulp.MSG.AUTH_OK);
  link.encrypted = true;

  // 2) CONFIG + TUN_UP
  link.sendMsg(ulp.MSG.CONFIG, ulp.configBody({
    v4Prefix: 20,
    v4Device: Buffer.from([10, 8, 0, 2]), v4Host: Buffer.from([10, 8, 0, 1]),
    v6Prefix: 64,
    v6Device: Buffer.from('fd004c55010000000000000000000002', 'hex'),
    v6Host: Buffer.from('fd004c55010000000000000000000001', 'hex'),
    dns: [Buffer.from([1, 1, 1, 1]), Buffer.from([9, 9, 9, 9])],
    routes: [[0, Buffer.from([0, 0, 0, 0])], [64, Buffer.from([0, 0, 0, 0])]],
  }));
  link.sendMsg(ulp.MSG.TUN_UP, Buffer.alloc(0));
  console.log('  sent CONFIG + TUN_UP');

  // 3) proactive media (device -> host)
  const v1 = await link.readFrame();
  check('video:keyframe', v1.channel === ulp.CH.VIDEO, `ch=${v1.channel.toString(16)}`);
  const vf1 = ulp.VideoFrame.parse(v1.payload);
  check('video:1920x1080 key', vf1.kind === 0 && vf1.width === 1920 && vf1.height === 1080 && vf1.seq === 1);
  const v2 = await link.readFrame();
  const vf2 = ulp.VideoFrame.parse(v2.payload);
  check('video:delta', vf2.kind === 1 && vf2.seq === 2);
  const a1 = ulp.AudioFrame.parse((await link.readFrame()).payload);
  check('audio:opus 48k', a1.codec === 0 && a1.rate === 48000 && a1.seq === 1);
  const a2 = ulp.AudioFrame.parse((await link.readFrame()).payload);
  check('audio:seq2', a2.seq === 2);
  const clip = ulp.ClipboardUpdate.parse((await link.readFrame()).payload);
  check('clipboard:device->host', clip.d === 0 && Buffer.from(clip.data).toString('utf8').includes('from device'));
  const note = ulp.Notification.parse((await link.readFrame()).payload);
  check('notification:sms', note.app === 'com.example.sms' && note.title === 'Bob');

  // 4) IPv4 ICMP echo
  link.sendFrame(ulp.CH.TUN_V4, 0, buildIpv4Echo(7, Buffer.from('node-e2e')));
  const r4 = (await link.readFrame());
  check('tun:ipv4 reply ch', r4.channel === ulp.CH.TUN_V4);
  {
    const pkt = r4.payload;
    const ihl = (pkt[0] & 0xF) * 4;
    const icmpCsum = (pkt[ihl + 2] << 8) | pkt[ihl + 3];
    const c = Buffer.from(pkt.slice(ihl)); c.writeUInt16BE(0, 2);
    check('ipv4:icmp csum', ipChecksum(c) === icmpCsum,
      `computed=${ipChecksum(c).toString(16)} inpkt=${icmpCsum.toString(16)}`);
    check('ipv4:echo reply', pkt[ihl] === 0 && ((pkt[ihl + 4] << 8) | pkt[ihl + 5]) === 0x1234 && ((pkt[ihl + 6] << 8) | pkt[ihl + 7]) === 7);
    check('ipv4:addrs swapped', Buffer.from(pkt.slice(12, 16)).equals(Buffer.from([10, 8, 0, 2])));
  }

  // 5) IPv6 ICMPv6 echo
  link.sendFrame(ulp.CH.TUN_V6, 0, buildIpv6Echo(9, Buffer.from('node6')));
  const r6 = (await link.readFrame());
  check('tun:ipv6 reply ch', r6.channel === ulp.CH.TUN_V6);
  {
    const pkt = r6.payload;
    const plen = (pkt[4] << 8) | pkt[5];
    check('ipv6:echo reply', plen + 40 === pkt.length && pkt[40] === 129,
      `plen=${plen} type=${pkt[40]}`);
    check('ipv6:icmpv6 csum', icmpv6Checksum(Buffer.from(pkt.slice(40)),
      pkt.slice(8, 24), pkt.slice(24, 40)) === 0);
    check('ipv6:id+seq+data',
      ((pkt[44] << 8) | pkt[45]) === 0x1234 && ((pkt[46] << 8) | pkt[47]) === 9
      && Buffer.from(pkt.slice(48)).equals(Buffer.from('node6')));
  }

  // 6) input + clipboard host->device
  link.sendFrame(ulp.CH.INPUT, 0, ulp.InputEvent.encode({ ty: 0, action: 0, x: 500, y: 500, key: 0, text: '' }));
  link.sendFrame(ulp.CH.INPUT, 0, ulp.InputEvent.encode({ ty: 3, action: 0, x: 0, y: 0, key: 0, text: 'from node 🧵' }));
  link.sendFrame(ulp.CH.CLIPBOARD, 0, ulp.ClipboardUpdate.encode(1, 0, Buffer.from('from node', 'utf8')));

  // 7) QOS + MUTE
  link.sendMsg(ulp.MSG.QOS, ulp.qosBody(4, 30000, 50000, 15, 0, 0));
  link.sendMsg(ulp.MSG.MUTE, Uint8Array.from([0x0F]));

  // 8) STATS
  link.sendMsg(ulp.MSG.STATS_REQ, Buffer.alloc(0));
  const stats = await link.recvMsg();
  check('stats:rsp', stats.mtype === ulp.MSG.STATS_RSP && stats.body.length === 104,
    `mtype=${stats.mtype} len=${stats.body.length}`);
  check('stats:fps60', stats.body.readUInt32BE(92) === 60);

  // 9) PING/PONG
  const pingBody = Buffer.from([0, 0, 0, 0, 0, 0, 0, 42]);
  link.sendMsg(ulp.MSG.PING, pingBody);
  const pong = await link.recvMsg();
  check('ping:pong', pong.mtype === ulp.MSG.PONG && Buffer.from(pong.body).equals(pingBody));

  // 10) BYE
  link.sendMsg(ulp.MSG.BYE, Buffer.from([1]));
  const bye = await link.recvMsg();
  check('bye:mutual', bye.mtype === ulp.MSG.BYE);
  sock.end();

  console.log(`NODE E2E: ${pass - fail} pass, ${fail} fail`);
  if (failures.length) {
    for (const f of failures) console.log('  FAIL ' + f);
    process.exit(1);
  }
  console.log('NODE E2E: ALL PASS');
  process.exit(0);
}

main().catch((e) => { console.error('E2E error:', e.message); process.exit(2); });
