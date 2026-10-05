// ULP v1.1 conformance — golden vectors (protocol/vectors/v11.json) +
// negative tests. Byte-level interop with the Python reference.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import * as v11 from "./ulplink.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SPEC = JSON.parse(readFileSync(
  path.join(__dirname, "..", "..", "protocol", "vectors", "v11.json"), "utf8"));

const hx = (s) => Buffer.from(s, "hex");

export function selfTest(check) {
  // constants
  const c = SPEC.constants;
  check("v11:feat_versioned", v11.FEAT_VERSIONED === c.feat_versioned);
  check("v11:msg ids", v11.MSG_DEVICE_ID === c.msg_device_id &&
    v11.MSG_DEVICE_AUTH === c.msg_device_auth &&
    v11.MSG_RESUME_REQ === c.msg_resume_req &&
    v11.MSG_RESUME_OK === c.msg_resume_ok);
  for (const [k, v] of Object.entries(c.err_codes)) {
    check(`v11:err_code ${k}`, v11.ERR[k.toUpperCase()] === v);
  }
  check("v11:decisions", v11.DECISION.TRUSTED === c.decisions.trusted &&
    v11.DECISION.TRUSTED_NEW === c.decisions.trusted_new &&
    v11.DECISION.REVOKED === c.decisions.revoked &&
    v11.DECISION.THROTTLED === c.decisions.throttled);

  for (const v of SPEC.vectors) {
    if (v.kind === "device_id") {
      const got = v11.deviceIdBody(hx(v.device_id), hx(v.identity_pub),
        v.name, v.platform, v.app_ver, v.caps, hx(v.transcript),
        hx(v.key_mac));
      check(`v11:${v.name}:encode`, got.toString("hex") === v.expected,
        `${got.toString("hex")} != ${v.expected}`);
      const d = v11.deviceIdParse(hx(v.expected), hx(v.transcript), hx(v.key_mac));
      check(`v11:${v.name}:decode`, d.name === v.name &&
        d.platform === v.platform && d.appVer === v.app_ver &&
        d.caps === v.caps &&
        Buffer.from(d.deviceId).toString("hex") === v.device_id);
      // tamper: last byte
      const bad = Buffer.from(hx(v.expected));
      bad[bad.length - 1] ^= 1;
      try { v11.deviceIdParse(bad, hx(v.transcript), hx(v.key_mac)); check(`v11:${v.name}:tamper`, false); }
      catch { check(`v11:${v.name}:tamper`, true); }
      // tamper: transcript
      try { v11.deviceIdParse(hx(v.expected), hx("cafebabe" + v.transcript.slice(32)), hx(v.key_mac)); check(`v11:${v.name}:transcript`, false); }
      catch { check(`v11:${v.name}:transcript`, true); }
    } else if (v.kind === "device_auth") {
      const got = v11.deviceAuthBody(v.decision, hx(v.session_id),
        hx(v.sender_id), hx(v.transcript), hx(v.key_mac));
      check(`v11:${v.name}:encode`, got.toString("hex") === v.expected);
      const d = v11.deviceAuthParse(hx(v.expected), hx(v.transcript), hx(v.key_mac));
      check(`v11:${v.name}:decode`, d.decision === v.decision);
      // wrong key
      const wrongKey = hx(v.key_mac.replace(/[0-9a-f][0-9a-f]/, "ff"));
      try { v11.deviceAuthParse(hx(v.expected), hx(v.transcript), wrongKey); check(`v11:${v.name}:wrong_key`, false); }
      catch { check(`v11:${v.name}:wrong_key`, true); }
    } else if (v.kind === "resume_req") {
      const got = v11.resumeReqBody(hx(v.session_id), hx(v.fresh_pub),
        hx(v.resume_nonce), hx(v.secret));
      check(`v11:${v.name}:encode`, got.toString("hex") === v.expected);
      const d = v11.resumeReqParse(hx(v.expected), hx(v.secret));
      check(`v11:${v.name}:decode`,
        Buffer.from(d.sessionId).toString("hex") === v.session_id);
      try { v11.resumeReqParse(hx(v.expected), hx(v.secret.replace(/[0-9a-f]/, "0").replace(/^0+/, "1") || "11".repeat(32))); check(`v11:${v.name}:wrong_secret`, false); }
      catch { check(`v11:${v.name}:wrong_secret`, true); }
    } else if (v.kind === "resume_ok") {
      const got = v11.resumeOkBody(hx(v.fresh_pub), hx(v.session_id),
        hx(v.req_pub), hx(v.secret));
      check(`v11:${v.name}:encode`, got.toString("hex") === v.expected);
      const pub = v11.resumeOkParse(hx(v.expected), hx(v.session_id),
        hx(v.req_pub), hx(v.secret));
      check(`v11:${v.name}:decode`, Buffer.from(pub).toString("hex") === v.fresh_pub);
      // wrong req_pub
      const wrongReq = hx(v.req_pub.replace(/[0-9a-f]/, "0"));
      try { v11.resumeOkParse(hx(v.expected), hx(v.session_id), wrongReq, hx(v.secret)); check(`v11:${v.name}:wrong_req_pub`, false); }
      catch { check(`v11:${v.name}:wrong_req_pub`, true); }
    } else if (v.kind === "error") {
      const got = v11.errorBody(v.fatal, v.code, v.msg);
      check(`v11:${v.name}:encode`, got.toString("hex") === v.expected);
      const d = v11.errorParse(hx(v.expected));
      check(`v11:${v.name}:decode`, d.fatal === v.fatal && d.code === v.code && d.msg === v.msg);
    }
  }

  // device_id derivation
  const did = v11.deviceIdFromPub(hx(SPEC.vectors[0].identity_pub));
  check("v11:device_id derivation",
    did.toString("hex") === SPEC.vectors[0].device_id);

  // resume keys: HKDF with resume info (deterministic shape check)
  const shared = hx("ab".repeat(32));
  const k1 = v11.resumeSessionKeys(shared, hx(SPEC.vectors[2].resume_nonce),
    hx(SPEC.vectors[2].session_id), 1);
  const k2 = v11.resumeSessionKeys(shared, hx(SPEC.vectors[2].resume_nonce),
    hx(SPEC.vectors[2].session_id), 1);
  check("v11:resume keys deterministic",
    Buffer.from(k1.keyAead).equals(Buffer.from(k2.keyAead)) &&
    Buffer.from(k1.keyMac).equals(Buffer.from(k2.keyMac)));
}
