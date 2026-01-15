/**
 * beacon.js — Proof-of-Presence BLE Beacon (Ed25519 tokens + relay-defense loop)

 * Relay loop rule:
 *  - Pi derives k = sha256(tokenB) (32 bytes)
 *  - Each round: c_i = random 16 bytes
 *  - Phone response: r_i = sha256(k || c_i) (32 bytes)
 */

require("dotenv").config();
const bleno = require("@abandonware/bleno");
const nacl = require("tweetnacl");
const axios = require("axios");
const crypto = require("crypto");

// ========= ENV =========
const SERVICE_UUID    = (process.env.VITE_SERVICE_UUID || "").toLowerCase();
const ID_CHAR_UUID    = (process.env.VITE_ID_CHAR_UUID || "").toLowerCase();
const NONCE_CHAR_UUID = (process.env.VITE_SIGN_NONCE_UUID || "").toLowerCase();
const RESP_CHAR_UUID  = (process.env.VITE_SIGN_RESP_UUID || "").toLowerCase();

const ATTEMPT_TOKEN_UUID = (process.env.VITE_ATTEMPT_TOKEN_UUID || "").toLowerCase();
const CHALLENGE_UUID     = (process.env.VITE_CHALLENGE_UUID || "").toLowerCase();
const RESPONSE_UUID      = (process.env.VITE_RESPONSE_UUID || "").toLowerCase();
const RESULT_UUID        = (process.env.VITE_RESULT_UUID || "").toLowerCase();

const BACKEND_BASE_URL = process.env.BACKEND_BASE_URL || "http://172.20.10.7:5001";
const BACKEND_VERIFY_KEY_HEX = (process.env.BACKEND_VERIFY_KEY_HEX || "").toLowerCase();
const PI_ID = process.env.PI_ID || "";

const RELAY_M = Math.min(255, Math.max(1, parseInt(process.env.RELAY_M || "16", 10)));
const RELAY_TIMEOUT_MS = Math.max(10, parseInt(process.env.RELAY_TIMEOUT_MS || "250", 10));

const BEACON_ID_HEX = (process.env.BEACON_ID_HEX || "").toLowerCase();
if (!/^[0-9a-f]{16}$/.test(BEACON_ID_HEX)) throw new Error("BEACON_ID_HEX must be 16 hex chars (8 bytes)");
const BEACON_ID = Buffer.from(BEACON_ID_HEX, "hex");

// Pi keypair (must match Pi.pubkey_hex stored in DB)
const SEED_HEX = (process.env.ED25519_SEED_HEX || "").toLowerCase();
if (!/^[0-9a-f]{64}$/.test(SEED_HEX)) throw new Error("ED25519_SEED_HEX must be 32-byte hex");
const seed = Buffer.from(SEED_HEX, "hex");
const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(seed));

// ========= COMPACT ED25519 (match backend/crypto_utils.py) =========
function b64urlEncode(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}
function b64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}
function deepSort(obj) {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(deepSort);
  if (typeof obj !== "object") return obj;
  const keys = Object.keys(obj).sort();
  const out = {};
  for (const k of keys) out[k] = deepSort(obj[k]);
  return out;
}
function canonicalJsonBytes(obj) {
  // Python: json.dumps(..., separators=(",", ":"), sort_keys=True)
  // JS: JSON.stringify already uses "," and ":" without spaces; we ensure key ordering.
  return Buffer.from(JSON.stringify(deepSort(obj)), "utf8");
}
function sha256HexUtf8(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}
function sha256Buf(...parts) {
  const h = crypto.createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest(); // Buffer
}
function signCompactEd25519(payloadObj) {
  const msg = canonicalJsonBytes(payloadObj);
  const sig = nacl.sign.detached(new Uint8Array(msg), kp.secretKey);
  return `${b64urlEncode(msg)}.${b64urlEncode(Buffer.from(sig))}`;
}
function verifyCompactEd25519(compact, verifyKeyHex) {
  const parts = compact.split(".");
  if (parts.length !== 2) throw new Error("bad token format (expected 2 parts)");
  const msg = b64urlDecode(parts[0]);
  const sig = b64urlDecode(parts[1]);
  const vk = Buffer.from(verifyKeyHex, "hex");
  const ok = nacl.sign.detached.verify(new Uint8Array(msg), new Uint8Array(sig), new Uint8Array(vk));
  if (!ok) throw new Error("bad signature");
  return JSON.parse(msg.toString("utf8"));
}

// ========= OLD NONCE SIGNER (kept) =========
class IdCharacteristic extends bleno.Characteristic {
  constructor() {
    super({ uuid: ID_CHAR_UUID, properties: ["read"], value: null });
  }
  onReadRequest(offset, cb) {
    if (offset) return cb(this.RESULT_ATTR_NOT_LONG);
    cb(this.RESULT_SUCCESS, BEACON_ID);
  }
}

let lastNonce = null;
class NonceCharacteristic extends bleno.Characteristic {
  constructor() {
    super({ uuid: NONCE_CHAR_UUID, properties: ["writeWithoutResponse"], value: null });
  }
  onWriteRequest(data, offset, _withoutResponse, cb) {
    if (offset) return cb(this.RESULT_ATTR_NOT_LONG);
    lastNonce = Buffer.from(data);
    trySignAndNotify();
    cb(this.RESULT_SUCCESS);
  }
}

let notifyCb = null;
class ResponseCharacteristic extends bleno.Characteristic {
  constructor() {
    super({ uuid: RESP_CHAR_UUID, properties: ["notify"], value: null });
  }
  onSubscribe(_m, updateValueCallback) {
    notifyCb = updateValueCallback;
  }
  onUnsubscribe() {
    notifyCb = null;
  }
}

function be64(tsMs) {
  const b = Buffer.alloc(8);
  let n = BigInt(tsMs);
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return b;
}
function buildPayload(nonceBuf) {
  const tsBuf = be64(Date.now());
  const msg = Buffer.concat([nonceBuf, tsBuf]); // 24 bytes
  const sig = Buffer.from(nacl.sign.detached(new Uint8Array(msg), kp.secretKey)); // 64
  return Buffer.concat([tsBuf, sig]); // 72
}
function trySignAndNotify() {
  if (!notifyCb || !lastNonce) return;
  try {
    notifyCb(buildPayload(lastNonce));
  } catch (e) {
    console.error("nonce notify failed:", e.message);
  } finally {
    lastNonce = null;
  }
}

// ========= NEW PoP BLE CHARACTERISTICS =========
//
// CHALLENGE notify (binary):
//   INIT:  [0x00 || k(32) || m(1) || timeout_ms_u16le(2)]
//   ROUND: [0x01 || i(1) || c_i(16)]
//
// RESPONSE write (binary):
//   [i(1) || r_i(32)]  where r_i = sha256(k || c_i)
//
// RESULT notify (utf8 JSON):
//   {"ok":true,"proof_id":"...","result":"ok"}  OR {"ok":false,"step":"...","error":"..."}

let challengeNotifyCb = null;
class ChallengeCharacteristic extends bleno.Characteristic {
  constructor() {
    super({ uuid: CHALLENGE_UUID, properties: ["notify"], value: null });
  }
  onSubscribe(_m, cb) {
    challengeNotifyCb = cb;
  }
  onUnsubscribe() {
    challengeNotifyCb = null;
  }
}
function notifyChallenge(buf) {
  if (!challengeNotifyCb) return;
  try {
    challengeNotifyCb(buf);
  } catch (e) {
    console.error("challenge notify failed:", e.message);
  }
}

let resultNotifyCb = null;
class ResultCharacteristic extends bleno.Characteristic {
  constructor() {
    super({ uuid: RESULT_UUID, properties: ["notify"], value: null });
  }
  onSubscribe(_m, cb) {
    resultNotifyCb = cb;
  }
  onUnsubscribe() {
    resultNotifyCb = null;
  }
}
function notifyResult(obj) {
  if (!resultNotifyCb) return;
  try {
    resultNotifyCb(Buffer.from(JSON.stringify(obj), "utf8"));
  } catch (e) {
    console.error("result notify failed:", e.message);
  }
}

// Response handling
const pending = new Map(); // i -> { resolve, reject }
class ResponseWriteCharacteristic extends bleno.Characteristic {
  constructor() {
    super({ uuid: RESPONSE_UUID, properties: ["writeWithoutResponse", "write"], value: null });
  }
  onWriteRequest(data, offset, _withoutResponse, cb) {
    if (offset) return cb(this.RESULT_ATTR_NOT_LONG);
    try {
      const buf = Buffer.from(data);
      if (buf.length !== 33) {
        return cb(this.RESULT_UNLIKELY_ERROR);
      }
      const i = buf.readUInt8(0);
      const r = buf.subarray(1, 33);
      const waiter = pending.get(i);
      if (waiter) {
        pending.delete(i);
        waiter.resolve({ i, r });
      }
      cb(this.RESULT_SUCCESS);
    } catch {
      cb(this.RESULT_UNLIKELY_ERROR);
    }
  }
}

// Attempt token RX (chunked): write "LEN:<n>\n" then token bytes
let tokenExpectedLen = null;
let tokenChunks = [];
let tokenReceived = 0;

class AttemptTokenCharacteristic extends bleno.Characteristic {
  constructor() {
    super({ uuid: ATTEMPT_TOKEN_UUID, properties: ["write"], value: null });
  }
  async onWriteRequest(data, offset, _withoutResponse, cb) {
    if (offset) return cb(this.RESULT_ATTR_NOT_LONG);
    try {
      if (tokenExpectedLen === null) {
        const s = data.toString("utf8");
        const m = s.match(/^LEN:(\d+)\n$/);
        if (!m) {
          notifyResult({ ok: false, step: "rx", error: "expected LEN:<n>\\n" });
          return cb(this.RESULT_UNLIKELY_ERROR);
        }
        tokenExpectedLen = parseInt(m[1], 10);
        tokenChunks = [];
        tokenReceived = 0;
        return cb(this.RESULT_SUCCESS);
      }

      tokenChunks.push(Buffer.from(data));
      tokenReceived += data.length;

      if (tokenReceived > tokenExpectedLen) {
        resetTokenRx();
        notifyResult({ ok: false, step: "rx", error: "overflow" });
        return cb(this.RESULT_UNLIKELY_ERROR);
      }

      if (tokenReceived === tokenExpectedLen) {
        const token = Buffer.concat(tokenChunks, tokenExpectedLen).toString("utf8");
        resetTokenRx();
        runProtocol(token).catch((e) => notifyResult({ ok: false, step: "runProtocol", error: e.message }));
      }

      cb(this.RESULT_SUCCESS);
    } catch (e) {
      resetTokenRx();
      notifyResult({ ok: false, step: "rx", error: e.message });
      cb(this.RESULT_UNLIKELY_ERROR);
    }
  }
}
function resetTokenRx() {
  tokenExpectedLen = null;
  tokenChunks = [];
  tokenReceived = 0;
}

// ========= RELAY LOOP + BACKEND ATTEST =========
function u16le(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n & 0xffff, 0);
  return b;
}
function hrNowNs() {
  return process.hrtime.bigint(); // monotonic
}
function waitForResponse(i, timeoutMs) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      pending.delete(i);
      reject(new Error("timeout"));
    }, timeoutMs);
    pending.set(i, {
      resolve: (v) => {
        clearTimeout(t);
        resolve(v);
      },
      reject: (e) => {
        clearTimeout(t);
        reject(e);
      },
    });
  });
}

async function runProtocol(attempt_token) {
  // config checks
  if (!BACKEND_VERIFY_KEY_HEX || BACKEND_VERIFY_KEY_HEX.length !== 64) {
    return notifyResult({ ok: false, step: "config", error: "missing BACKEND_VERIFY_KEY_HEX" });
  }
  if (!PI_ID) {
    return notifyResult({ ok: false, step: "config", error: "missing PI_ID" });
  }
  if (!challengeNotifyCb) {
    // Not fatal, but useful to know
    console.warn("No subscriber on CHALLENGE characteristic (phone not listening?)");
  }

  // 1) Verify attempt_token
  let attemptPayload;
  try {
    attemptPayload = verifyCompactEd25519(attempt_token, BACKEND_VERIFY_KEY_HEX);
  } catch (e) {
    return notifyResult({ ok: false, step: "verify_attempt", error: e.message });
  }

  if (attemptPayload.iss !== "presence-backend" || attemptPayload.aud !== "presence-pi") {
    return notifyResult({ ok: false, step: "verify_attempt", error: "bad iss/aud" });
  }
  if (attemptPayload.pi_id !== PI_ID) {
    return notifyResult({ ok: false, step: "verify_attempt", error: "pi_id mismatch" });
  }
  const now = Math.floor(Date.now() / 1000);
  if (attemptPayload.exp_attempt && now >= Number(attemptPayload.exp_attempt)) {
    return notifyResult({ ok: false, step: "verify_attempt", error: "attempt expired" });
  }
  const attempt_id = attemptPayload.attempt_id;

  // 2) Create session -> sid + tokenB
  let sid, tokenB;
  try {
    const res = await axios.post(
      `${BACKEND_BASE_URL}/presence/session`,
      { pi_id: PI_ID, attempt_id },
      { timeout: 5000 }
    );
    sid = res.data.sid;
    tokenB = res.data.tokenB;
  } catch (e) {
    return notifyResult({ ok: false, step: "session", error: e.response?.data || e.message });
  }

  // 3) Verify tokenB (defense-in-depth)
  try {
    const tb = verifyCompactEd25519(tokenB, BACKEND_VERIFY_KEY_HEX);
    if (tb.iss !== "presence-backend" || tb.aud !== "presence-pi") throw new Error("bad iss/aud");
    if (tb.sid !== sid) throw new Error("sid mismatch");
  } catch (e) {
    return notifyResult({ ok: false, step: "verify_tokenB", error: e.message });
  }

  // 4) Derive k and send INIT
  // Use k = sha256(tokenB) where tokenB is the UTF-8 compact token string (same on both ends)
  const k = sha256Buf(Buffer.from(tokenB, "utf8")); // 32 bytes
  notifyChallenge(Buffer.concat([Buffer.from([0x00]), k, Buffer.from([RELAY_M & 0xff]), u16le(RELAY_TIMEOUT_MS)]));

  // 5) Relay rounds
  let success = 0;
  const rtts = [];
  const transcriptHasher = crypto.createHash("sha256");

  for (let i = 1; i <= RELAY_M; i++) {
    const ci = crypto.randomBytes(16);
    notifyChallenge(Buffer.concat([Buffer.from([0x01, i & 0xff]), ci]));

    const t0 = hrNowNs();
    let riBuf = null;
    let dtMs = null;

    try {
      const resp = await waitForResponse(i & 0xff, RELAY_TIMEOUT_MS);
      const t1 = hrNowNs();
      dtMs = Number(t1 - t0) / 1e6;
      riBuf = resp.r;
    } catch {
      dtMs = RELAY_TIMEOUT_MS;
      riBuf = Buffer.alloc(32, 0);
    }

    const expected = sha256Buf(k, ci); // sha256(k || ci)
    const ok = riBuf.equals(expected);
    if (ok) success += 1;
    rtts.push(dtMs);

    // transcript hash: i(1) || ci(16) || ri(32) || dt_ms_u32le(4)
    const dt_u32 = Buffer.alloc(4);
    dt_u32.writeUInt32LE(Math.max(0, Math.min(0xffffffff, Math.floor(dtMs * 1000))), 0);
    transcriptHasher.update(Buffer.from([i & 0xff]));
    transcriptHasher.update(ci);
    transcriptHasher.update(riBuf);
    transcriptHasher.update(dt_u32);
  }

  // 6) Summary + loose policy
  const sorted = [...rtts].sort((a, b) => a - b);
  const min = sorted[0] ?? null;
  const max = sorted[sorted.length - 1] ?? null;
  const avg = sorted.length ? sorted.reduce((a, b) => a + b, 0) / sorted.length : null;
  const p95 = sorted.length ? sorted[Math.floor(0.95 * (sorted.length - 1))] : null;

  const timing_summary = deepSort({
    m: RELAY_M,
    timeout_ms: RELAY_TIMEOUT_MS,
    rtt_ms_min: min,
    rtt_ms_avg: avg,
    rtt_ms_max: max,
    rtt_ms_p95: p95,
  });

  const transcript_hash = transcriptHasher.digest("hex");

  // loose pass rule: >= 70% correct
  const pass = success >= Math.ceil(0.7 * RELAY_M);
  const result = pass ? "ok" : "fail";

  // 7) attPi MUST include tokenB_hash
  const attPayload = deepSort({
    sid,
    tokenB_hash: sha256HexUtf8(tokenB),
    result,
    success_count: success,
    timing_summary,
    transcript_hash,
    // optional fields for debugging; backend doesn't require:
    attempt_id,
    pi_id: PI_ID,
  });
  const attPi = signCompactEd25519(attPayload);

  // 8) POST /presence/attest -> proof_id
  try {
    const res = await axios.post(
      `${BACKEND_BASE_URL}/presence/attest`,
      { tokenB, attPi },
      { timeout: 5000 }
    );
    return notifyResult({ ok: true, proof_id: res.data.proof_id, result: res.data.result });
  } catch (e) {
    return notifyResult({ ok: false, step: "attest", error: e.response?.data || e.message });
  }
}

// ========= BLE SERVICE =========
const characteristics = [
  new IdCharacteristic(),
  new NonceCharacteristic(),
  new ResponseCharacteristic(),
];

// Only enable PoP flow if all UUIDs exist
if (ATTEMPT_TOKEN_UUID && CHALLENGE_UUID && RESPONSE_UUID && RESULT_UUID) {
  characteristics.push(new AttemptTokenCharacteristic());
  characteristics.push(new ChallengeCharacteristic());
  characteristics.push(new ResponseWriteCharacteristic());
  characteristics.push(new ResultCharacteristic());
} else {
  console.warn(
    "PoP relay flow disabled: set VITE_ATTEMPT_TOKEN_UUID, VITE_CHALLENGE_UUID, VITE_RESPONSE_UUID, VITE_RESULT_UUID"
  );
}

const service = new bleno.PrimaryService({
  uuid: SERVICE_UUID,
  characteristics,
});

// ---- BLE lifecycle ----
bleno.on("stateChange", (state) => {
  console.log("bleno state:", state);
  if (state === "poweredOn") {
    bleno.startAdvertising("BeaconPresence", [SERVICE_UUID], (err) => {
      if (err) console.error("adv error:", err);
    });
  } else {
    bleno.stopAdvertising();
  }
});

bleno.on("advertisingStart", (err) => {
  if (err) return console.error("advertisingStart error:", err);
  console.log("advertising started");
  bleno.setServices([service], (err2) => {
    if (err2) console.error("setServices error:", err2);
  });
});

process.on("SIGINT", () => process.exit(0));
