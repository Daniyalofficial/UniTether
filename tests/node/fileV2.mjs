/**
 * ULP file transfer v2 codec (CH_FILE payloads).
 * Conformance port of tests/protocol/file_transfer.py — golden
 * vectors in protocol/vectors/file_vectors.json pin the byte shapes.
 *
 * v1 ops (unchanged): 0x00 meta, 0x01 data, 0x02 ack, 0x03 cancel,
 *                     0x04 done
 * v2 ops:             0x05 resume_req, 0x06 resume_rsp, 0x07 checksum
 */
import { createHash } from 'node:crypto';

export const OP_META = 0x00;
export const OP_DATA = 0x01;
export const OP_ACK = 0x02;
export const OP_CANCEL = 0x03;
export const OP_DONE = 0x04;
export const OP_RESUME_REQ = 0x05;
export const OP_RESUME_RSP = 0x06;
export const OP_CHECKSUM = 0x07;

export const STATE_NONE = 0;
export const STATE_PARTIAL = 1;
export const STATE_COMPLETE = 2;

function asBuf(p) { return Buffer.isBuffer(p) ? p : Buffer.from(p); }
function u32(v) { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0); return b; }
function u64(v) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b; }
function readU32(b, o) { return asBuf(b).readUInt32BE(o); }
function readU64(b, o) { return asBuf(b).readBigUInt64BE(o); }

export function meta(direction, fileId, total, name) {
  const n = Buffer.from(name, 'utf8');
  if (n.length > 255) throw new Error('name too long');
  const nl = Buffer.alloc(2); nl.writeUInt16BE(n.length);
  const head = Buffer.concat([Buffer.from([OP_META, direction & 0xff]),
    u32(fileId), u64(total), nl]);
  return new Uint8Array(Buffer.concat([head, n]));
}

export function metaParse(p) {
  if (p.length < 16) throw new Error('meta: short');
  const bb = asBuf(p);
  const name = Buffer.from(bb.subarray(16, 16 + readU32(bb, 14))).toString('utf8');
  return { direction: bb[1], fileId: readU32(bb, 2), total: Number(readU64(bb, 6)), name };
}

export function data(direction, fileId, seq, offset, chunk) {
  const head = Buffer.concat([Buffer.from([OP_DATA, direction & 0xff]),
    u32(fileId), u32(seq), u64(offset)]);
  return new Uint8Array(Buffer.concat([head, Buffer.from(chunk)]));
}

export function dataParse(p) {
  if (p.length < 18) throw new Error('data: short');
  const bb = asBuf(p);
  return { direction: bb[1], fileId: readU32(bb, 2), seq: readU32(bb, 6),
    offset: Number(readU64(bb, 10)), chunk: bb.subarray(18) };
}

export function ack(direction, fileId, seqAck) {
  return new Uint8Array(Buffer.concat([
    Buffer.from([OP_ACK, direction & 0xff]), u32(fileId), u32(seqAck)]));
}

export function cancel(direction, fileId) {
  return new Uint8Array(Buffer.concat([
    Buffer.from([OP_CANCEL, direction & 0xff]), u32(fileId)]));
}

export function done(direction, fileId) {
  return new Uint8Array(Buffer.concat([
    Buffer.from([OP_DONE, direction & 0xff]), u32(fileId)]));
}

export function resumeReq(direction, fileId, expectedOffset) {
  return new Uint8Array(Buffer.concat([
    Buffer.from([OP_RESUME_REQ, direction & 0xff]), u32(fileId),
    u64(expectedOffset)]));
}

export function resumeReqParse(p) {
  if (p.length !== 14) throw new Error('resume_req: bad length');
  const bb = asBuf(p);
  return { direction: bb[1], fileId: readU32(bb, 2),
    expectedOffset: Number(readU64(bb, 6)) };
}

export function resumeRsp(direction, fileId, offset, state) {
  return new Uint8Array(Buffer.concat([
    Buffer.from([OP_RESUME_RSP, direction & 0xff]), u32(fileId),
    u64(offset), Buffer.from([state & 0xff])]));
}

export function resumeRspParse(p) {
  if (p.length !== 15) throw new Error('resume_rsp: bad length');
  const bb = asBuf(p);
  return { direction: bb[1], fileId: readU32(bb, 2),
    offset: Number(readU64(bb, 6)), state: bb[14] };
}

export function checksum(direction, fileId, sha256Digest) {
  if (sha256Digest.length !== 32) throw new Error('checksum: bad digest');
  return new Uint8Array(Buffer.concat([
    Buffer.from([OP_CHECKSUM, direction & 0xff]), u32(fileId),
    Buffer.from(sha256Digest)]));
}

export function checksumParse(p) {
  if (p.length !== 38) throw new Error('checksum: bad length');
  const bb = asBuf(p);
  return { direction: bb[1], fileId: readU32(bb, 2),
    sha256: Buffer.from(bb.subarray(6, 38)) };
}

export function sha256(buf) {
  return createHash('sha256').update(buf).digest();
}
