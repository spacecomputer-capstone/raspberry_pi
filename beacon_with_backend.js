/**
 * beacon.js — Proof-of-Presence BLE Beacon (BASIC flow + relay-counter challenges) — FULL VERSION
 *
 * So we send result: true (boolean) in attPi.
 *
 * Flow:
 * 1) Browser/phone gets attempt_token from backend
 * 2) Browser/phone sends token over BLE: "LEN:<n>\n" + token bytes (chunked)
 * 3) Pi verifies token, POST /presence/session, verifies tokenB
 * 4) Pi runs 1–3 CSPRNG challenge/response RTT rounds with phone over BLE
 * 5) Pi signs attPi including timing_summary + transcript_hash, POST /presence/attest
 * 6) Pi notifies RESULT JSON over BLE: {ok:true, proof_id, result:true}
 *
 * IMPORTANT:
 * - ATTEMPT_TOKEN characteristic supports both "write" and "writeWithoutResponse"
 * - Token RX is robust even if header is fragmented or coalesced with first token chunk
 * - Challenge layer does NOT enforce any timing threshold yet (result stays true)
 */

require("dotenv").config();
const bleno = require("@abandonware/bleno");
const nacl = require("tweetnacl");
const axios = require("axios");
const crypto = require("crypto");

// ========= UUIDs (defaults match your Flutter PoP client) =========
const DEFAULT_SERVICE_UUID = "eb5c86a4-733c-4d9d-aab2-285c2dab09a1";
const DEFAULT_ID_CHAR_UUID = "eb5c86a4-733c-4d9d-aab2-285c2dab09a2";
const DEFAULT_ATTEMPT_TOKEN_UUID = "8c0b8f3e-1b7a-4e58-9b9e-6fbb4e3d2b01";
const DEFAULT_RESULT_UUID = "8c0b8f3e-1b7a-4e58-9b9e-6fbb4e3d2b02";

// NEW: relay-counter challenge UUIDs
const DEFAULT_CHALLENGE_UUID = "8c0b8f3e-1b7a-4e58-9b9e-6fbb4e3d2b03";
const DEFAULT_CHALLENGE_RESP_UUID = "8c0b8f3e-1b7a-4e58-9b9e-6fbb4e3d2b04";

// Optional legacy nonce signer UUIDs (only enabled if you set env vars)
const LEGACY_NONCE_UUID = (process.env.VITE_SIGN_NONCE_UUID || "").toLowerCase();
const LEGACY_RESP_UUID = (process.env.VITE_SIGN_RESP_UUID || "").toLowerCase();

// Use env override if set; otherwise defaults
const SERVICE_UUID = (process.env.VITE_SERVICE_UUID || DEFAULT_SERVICE_UUID).toLowerCase();
const ID_CHAR_UUID = (process.env.VITE_ID_CHAR_UUID || DEFAULT_ID_CHAR_UUID).toLowerCase();
const ATTEMPT_TOKEN_UUID = (process.env.VITE_ATTEMPT_TOKEN_UUID || DEFAULT_ATTEMPT_TOKEN_UUID).toLowerCase();
const RESULT_UUID = (process.env.VITE_RESULT_UUID || DEFAULT_RESULT_UUID).toLowerCase();

// NEW: challenge UUID overrides
const CHALLENGE_UUID = (process.env.VITE_CHALLENGE_UUID || DEFAULT_CHALLENGE_UUID).toLowerCase();
const CHALLENGE_RESP_UUID = (process.env.VITE_CHALLENGE_RESP_UUID || DEFAULT_CHALLENGE_RESP_UUID).toLowerCase();

const BACKEND_BASE_URL = process.env.BACKEND_BASE_URL || "http://172.20.10.7:5001";
const BACKEND_VERIFY_KEY_HEX = (process.env.BACKEND_VERIFY_KEY_HEX || "").toLowerCase();
const PI_ID = process.env.PI_ID || "";

// Beacon ID (8 bytes hex)
const BEACON_ID_HEX = (process.env.BEACON_ID_HEX || "").toLowerCase();
if (!/^[0-9a-f]{16}$/.test(BEACON_ID_HEX)) {
  throw new Error("BEACON_ID_HEX must be 16 hex chars (8 bytes)");
}
const BEACON_ID = Buffer.from(BEACON_ID_HEX, "hex");

// Pi ed25519 seed (32 bytes hex)
const SEED_HEX = (process.env.ED25519_SEED_HEX || "").toLowerCase();
if (!/^[0-9a-f]{64}$/.test(SEED_HEX)) throw new Error("ED25519_SEED_HEX must be 32-byte hex");
const seed = Buffer.from(SEED_HEX, "hex");
const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(seed));

// Helpful process instance label (makes it obvious if two beacons are running)
const INSTANCE = `${process.pid}-${Math.random().toString(16).slice(2, 8)}`;
function log(...a) {
  console.log(`[beacon ${INSTANCE}]`, ...a);
}
function err(...a) {
  console.error(`[beacon ${INSTANCE}]`, ...a);
}

log("=== PoP Beacon starting ===");
log("SERVICE_UUID        =", SERVICE_UUID);
log("ID_CHAR_UUID        =", ID_CHAR_UUID);
log("ATTEMPT_TOKEN_UUID  =", ATTEMPT_TOKEN_UUID);
log("RESULT_UUID         =", RESULT_UUID);
log("CHALLENGE_UUID      =", CHALLENGE_UUID);
log("CHALLENGE_RESP_UUID =", CHALLENGE_RESP_UUID);
log("BACKEND_BASE_URL    =", BACKEND_BASE_URL);
log("PI_ID               =", PI_ID);
log("BACKEND_VERIFY_KEY? =", BACKEND_VERIFY_KEY_HEX ? "set" : "MISSING");
log("===========================");

// ========= Compact Ed25519 helpers (must match backend/crypto_utils.py) =========
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
  return Buffer.from(JSON.stringify(deepSort(obj)), "utf8");
}
function sha256HexUtf8(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
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
  const ok = nacl.sign.detached.verify(
    new Uint8Array(msg),
    new Uint8Array(sig),
    new Uint8Array(vk)
  );
  if (!ok) throw new Error("bad signature");
  return JSON.parse(msg.toString("utf8"));
}

// ========= RESULT notify =========
let resultNotifyCb = null;

class ResultCharacteristic extends bleno.Characteristic {
  constructor() {
    super({ uuid: RESULT_UUID, properties: ["notify"], value: null });
  }
  onSubscribe(_maxValueSize, cb) {
    resultNotifyCb = cb;
    log("RESULT subscribed ✅");
  }
  onUnsubscribe() {
    resultNotifyCb = null;
    log("RESULT unsubscribed");
  }
}

function notifyResult(obj) {
  if (!resultNotifyCb) {
    log("notifyResult: No subscriber on RESULT characteristic");
    return;
  }
  log("notifyResult ->", obj);
  try {
    resultNotifyCb(Buffer.from(JSON.stringify(obj), "utf8"));
  } catch (e) {
    err("result notify failed:", e.message);
  }
}

// ========= ID characteristic =========
class IdCharacteristic extends bleno.Characteristic {
  constructor() {
    super({ uuid: ID_CHAR_UUID, properties: ["read"], value: null });
  }
  onReadRequest(offset, cb) {
    if (offset) return cb(this.RESULT_ATTR_NOT_LONG);
    cb(this.RESULT_SUCCESS, BEACON_ID);
  }
}

// ========= Optional legacy nonce signer (only if env UUIDs exist) =========
let legacyNotifyCb = null;
let lastNonce = null;

class NonceCharacteristic extends bleno.Characteristic {
  constructor() {
    super({ uuid: LEGACY_NONCE_UUID, properties: ["write", "writeWithoutResponse"], value: null });
  }
  onWriteRequest(data, offset, _withoutResponse, cb) {
    if (offset) return cb(this.RESULT_ATTR_NOT_LONG);
    lastNonce = Buffer.from(data);
    trySignAndNotifyLegacy();
    cb(this.RESULT_SUCCESS);
  }
}

class ResponseCharacteristic extends bleno.Characteristic {
  constructor() {
    super({ uuid: LEGACY_RESP_UUID, properties: ["notify"], value: null });
  }
  onSubscribe(_m, updateValueCallback) {
    legacyNotifyCb = updateValueCallback;
  }
  onUnsubscribe() {
    legacyNotifyCb = null;
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
function buildLegacyPayload(nonceBuf) {
  const tsBuf = be64(Date.now());
  const msg = Buffer.concat([nonceBuf, tsBuf]);
  const sig = Buffer.from(nacl.sign.detached(new Uint8Array(msg), kp.secretKey));
  return Buffer.concat([tsBuf, sig]);
}
function trySignAndNotifyLegacy() {
  if (!legacyNotifyCb || !lastNonce) return;
  try {
    legacyNotifyCb(buildLegacyPayload(lastNonce));
  } catch (e) {
    err("legacy nonce notify failed:", e.message);
  } finally {
    lastNonce = null;
  }
}

// ========= NEW: CHALLENGE notify + response RX =========
let challengeNotifyCb = null;

// pending challenges keyed by `${sid}:${i}`
// value: { nonceHex, sentMs, resolve, reject, timeoutId }
const pendingChallenges = new Map();

class ChallengeCharacteristic extends bleno.Characteristic {
  constructor() {
    super({ uuid: CHALLENGE_UUID, properties: ["notify"], value: null });
  }
  onSubscribe(_maxValueSize, cb) {
    challengeNotifyCb = cb;
    log("CHALLENGE subscribed ✅");
  }
  onUnsubscribe() {
    challengeNotifyCb = null;
    log("CHALLENGE unsubscribed");
  }
}

function notifyChallenge(obj) {
  if (!challengeNotifyCb) {
    log("notifyChallenge: No subscriber on CHALLENGE characteristic");
    return false;
  }
  try {
    challengeNotifyCb(Buffer.from(JSON.stringify(obj), "utf8"));
    return true;
  } catch (e) {
    err("challenge notify failed:", e.message);
    return false;
  }
}

class ChallengeRespCharacteristic extends bleno.Characteristic {
  constructor() {
    super({
      uuid: CHALLENGE_RESP_UUID,
      properties: ["write", "writeWithoutResponse"],
      value: null,
    });
  }

  onWriteRequest(data, offset, _withoutResponse, cb) {
    if (offset) return cb(this.RESULT_ATTR_NOT_LONG);

    try {
      const s = Buffer.from(data).toString("utf8");
      let msg;
      try {
        msg = JSON.parse(s);
      } catch {
        log("CHALLENGE_RESP non-JSON:", s.slice(0, 140));
        return cb(this.RESULT_SUCCESS);
      }

      // expected minimal: { sid, i, nonce }
      const sid = msg.sid;
      const i = msg.i;
      const nonce = msg.nonce;

      if (!sid || typeof i !== "number" || !nonce) {
        log("CHALLENGE_RESP missing fields:", msg);
        return cb(this.RESULT_SUCCESS);
      }

      const key = `${sid}:${i}`;
      const pending = pendingChallenges.get(key);
      if (!pending) {
        log("CHALLENGE_RESP no pending for", key);
        return cb(this.RESULT_SUCCESS);
      }

      // nonce must match (counter replay / mismatch)
      const nonceHex = String(nonce).toLowerCase();
      if (nonceHex !== pending.nonceHex) {
        log("CHALLENGE_RESP nonce mismatch:", { key, got: nonceHex, expected: pending.nonceHex });
        return cb(this.RESULT_SUCCESS);
      }

      clearTimeout(pending.timeoutId);
      pendingChallenges.delete(key);
      pending.resolve({ recvMs: Date.now(), resp: msg });

      cb(this.RESULT_SUCCESS);
    } catch (e) {
      err("CHALLENGE_RESP handler error:", e);
      cb(this.RESULT_SUCCESS);
    }
  }
}

// ========= Relay-challenge helpers =========
function percentile(arr, p) {
  if (!arr.length) return null;
  const xs = [...arr].sort((a, b) => a - b);
  const idx = Math.ceil((p / 100) * xs.length) - 1;
  return xs[Math.min(Math.max(idx, 0), xs.length - 1)];
}

async function performRelayChallenges({ sid, maxChallenges = 3, timeoutPerChallengeMs = 1200 }) {
  const startedAtMs = Date.now();
  const m = crypto.randomInt(1, maxChallenges + 1); // 1..3
  const transcript = [];
  const rtts = [];
  let successCount = 0;

  const hadSubscriber = !!challengeNotifyCb;

  for (let i = 0; i < m; i++) {
    const nonceHex = crypto.randomBytes(16).toString("hex"); // CSPRNG nonce
    const sentMs = Date.now();

    const chalMsg = {
      type: "chal",
      sid,
      i,
      nonce: nonceHex,
      ts_pi_send: sentMs,
    };

    const delivered = hadSubscriber ? notifyChallenge(chalMsg) : false;

    // Wait for response (even if not delivered, we'll just time out and log it)
    const key = `${sid}:${i}`;
    const outcome = await new Promise((resolve) => {
      const timeoutId = setTimeout(() => {
        pendingChallenges.delete(key);
        resolve({ ok: false, reason: "timeout", recvMs: null, resp: null });
      }, timeoutPerChallengeMs);

      pendingChallenges.set(key, {
        nonceHex,
        sentMs,
        timeoutId,
        resolve: ({ recvMs, resp }) => resolve({ ok: true, reason: "ok", recvMs, resp }),
        reject: () => resolve({ ok: false, reason: "reject", recvMs: null, resp: null }),
      });
    });

    const recvMs = outcome.recvMs;
    const rttMs = recvMs ? recvMs - sentMs : null;

    if (outcome.ok && typeof rttMs === "number") {
      rtts.push(rttMs);
      successCount += 1;
    }

    transcript.push({
      i,
      nonce: nonceHex,
      delivered,
      sent_ms: sentMs,
      recv_ms: recvMs,
      rtt_ms: rttMs,
      resp: outcome.resp,
      status: outcome.reason,
    });
  }

  const totalMs = Date.now() - startedAtMs;
  const avg = rtts.length ? Math.round(rtts.reduce((a, b) => a + b, 0) / rtts.length) : null;

  return {
    m,
    timeout_ms: timeoutPerChallengeMs,
    total_ms: totalMs,
    success_count: successCount,
    rtt_ms_min: rtts.length ? Math.min(...rtts) : null,
    rtt_ms_avg: avg,
    rtt_ms_max: rtts.length ? Math.max(...rtts) : null,
    rtt_ms_p95: rtts.length ? percentile(rtts, 95) : null,
    rtt_ms_list: rtts,
    transcript,
    had_challenge_subscriber: hadSubscriber,
  };
}

// ========= Attempt token RX (robust) =========
let inProgress = false;

let rxBuf = Buffer.alloc(0);
let tokenExpectedLen = null;
let tokenBytesBuf = Buffer.alloc(0);

function resetRx() {
  rxBuf = Buffer.alloc(0);
  tokenExpectedLen = null;
  tokenBytesBuf = Buffer.alloc(0);
}

class AttemptTokenCharacteristic extends bleno.Characteristic {
  constructor() {
    super({
      uuid: ATTEMPT_TOKEN_UUID,
      properties: ["write", "writeWithoutResponse"], // ✅ critical
      value: null,
    });
  }

  onWriteRequest(data, offset, _withoutResponse, cb) {
    if (offset) return cb(this.RESULT_ATTR_NOT_LONG);

    try {
      if (inProgress) {
        notifyResult({ ok: false, step: "busy", error: "beacon busy; try again" });
        return cb(this.RESULT_SUCCESS);
      }

      rxBuf = Buffer.concat([rxBuf, Buffer.from(data)]);

      if (tokenExpectedLen === null) {
        const newlineIdx = rxBuf.indexOf("\n");
        if (newlineIdx === -1) {
          return cb(this.RESULT_SUCCESS); // wait for more bytes
        }

        const header = rxBuf.slice(0, newlineIdx + 1).toString("utf8");
        const m = header.match(/^LEN:(\d+)\n$/);
        if (!m) {
          const bad = header.replace(/\n/g, "\\n");
          resetRx();
          notifyResult({ ok: false, step: "rx", error: `bad header '${bad}'` });
          return cb(this.RESULT_UNLIKELY_ERROR);
        }

        tokenExpectedLen = parseInt(m[1], 10);
        log("RX header parsed: tokenExpectedLen =", tokenExpectedLen);

        const remainder = rxBuf.slice(newlineIdx + 1);
        rxBuf = Buffer.alloc(0);

        if (remainder.length > 0) {
          tokenBytesBuf = Buffer.concat([tokenBytesBuf, remainder]);
        }
      } else {
        tokenBytesBuf = Buffer.concat([tokenBytesBuf, rxBuf]);
        rxBuf = Buffer.alloc(0);
      }

      if (tokenExpectedLen !== null) {
        if (tokenBytesBuf.length > tokenExpectedLen) {
          resetRx();
          notifyResult({ ok: false, step: "rx", error: "overflow" });
          return cb(this.RESULT_UNLIKELY_ERROR);
        }

        if (tokenBytesBuf.length === tokenExpectedLen) {
          const token = tokenBytesBuf.toString("utf8");
          log("Token fully received ✅ len=", token.length);
          resetRx();

          inProgress = true;
          runBasicProtocol(token)
            .catch((e) => {
              err("runBasicProtocol error:", e);
              notifyResult({ ok: false, step: "runBasicProtocol", error: e.message || String(e) });
            })
            .finally(() => {
              inProgress = false;
            });
        }
      }

      cb(this.RESULT_SUCCESS);
    } catch (e) {
      err("onWriteRequest error:", e);
      resetRx();
      notifyResult({ ok: false, step: "rx", error: e.message || String(e) });
      cb(this.RESULT_UNLIKELY_ERROR);
    }
  }
}

// ========= BASIC BACKEND FLOW =========
async function runBasicProtocol(attempt_token) {
  log("runBasicProtocol start");

  if (!BACKEND_VERIFY_KEY_HEX || BACKEND_VERIFY_KEY_HEX.length !== 64) {
    return notifyResult({ ok: false, step: "config", error: "missing/invalid BACKEND_VERIFY_KEY_HEX" });
  }
  if (!PI_ID) {
    return notifyResult({ ok: false, step: "config", error: "missing PI_ID" });
  }

  // 1) verify attempt token signature + claims
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
    return notifyResult({
      ok: false,
      step: "verify_attempt",
      error: `pi_id mismatch (token=${attemptPayload.pi_id} env=${PI_ID})`,
    });
  }

  const now = Math.floor(Date.now() / 1000);
  if (attemptPayload.exp_attempt && now >= Number(attemptPayload.exp_attempt)) {
    return notifyResult({ ok: false, step: "verify_attempt", error: "attempt expired" });
  }

  const attempt_id = attemptPayload.attempt_id;
  log("Attempt verified ✅ attempt_id=", attempt_id);

  // 2) create session
  let sid, tokenB;
  try {
    log("POST /presence/session", { pi_id: PI_ID, attempt_id });
    const res = await axios.post(
      `${BACKEND_BASE_URL}/presence/session`,
      { pi_id: PI_ID, attempt_id },
      { timeout: 8000 }
    );
    sid = res.data.sid;
    tokenB = res.data.tokenB;
    log("Session created ✅ sid=", sid);
  } catch (e) {
    const status = e.response?.status;
    const body = e.response?.data;
    err("Session error:", status, body || e.message);
    if (status === 409) {
      return notifyResult({ ok: false, step: "session", error: "attempt already consumed (need new attempt token)" });
    }
    return notifyResult({ ok: false, step: "session", error: body || e.message });
  }

  // 3) verify tokenB
  try {
    const tb = verifyCompactEd25519(tokenB, BACKEND_VERIFY_KEY_HEX);
    if (tb.iss !== "presence-backend" || tb.aud !== "presence-pi") throw new Error("bad iss/aud");
    if (tb.sid !== sid) throw new Error("sid mismatch");
  } catch (e) {
    return notifyResult({ ok: false, step: "verify_tokenB", error: e.message });
  }

  // 3.5) NEW: challenge/response RTT rounds with phone (1..3)
  // No threshold logic yet; we only log timing + transcript.
  const timing = await performRelayChallenges({ sid, maxChallenges: 3, timeoutPerChallengeMs: 1200 });
  log("Challenge summary:", {
    m: timing.m,
    success_count: timing.success_count,
    rtt_ms_min: timing.rtt_ms_min,
    rtt_ms_avg: timing.rtt_ms_avg,
    rtt_ms_max: timing.rtt_ms_max,
    rtt_ms_p95: timing.rtt_ms_p95,
    had_subscriber: timing.had_challenge_subscriber,
  });

  // 4) sign attPi immediately
  // ✅ IMPORTANT: result is BOOLEAN to match your Postgres schema (presence_proofs.result bool)
  // Also: "log everything in the time summary" -> include transcript.
  const transcriptJson = JSON.stringify(timing.transcript);

  const attPayload = deepSort({
    sid,
    tokenB_hash: sha256HexUtf8(tokenB),

    result: true, // <-- forced true for now (threshold later)
    success_count: timing.success_count,

    timing_summary: {
      m: timing.m,
      timeout_ms: timing.timeout_ms,
      total_ms: timing.total_ms,
      had_challenge_subscriber: timing.had_challenge_subscriber,
      rtt_ms_min: timing.rtt_ms_min,
      rtt_ms_avg: timing.rtt_ms_avg,
      rtt_ms_max: timing.rtt_ms_max,
      rtt_ms_p95: timing.rtt_ms_p95,
      rtt_ms_list: timing.rtt_ms_list,
      transcript: timing.transcript, // log everything for later analysis
    },

    transcript_hash: crypto.createHash("sha256").update(transcriptJson, "utf8").digest("hex"),

    attempt_id,
    pi_id: PI_ID,
  });

  const attPi = signCompactEd25519(attPayload);

  // 5) attest
  try {
    const res = await axios.post(
      `${BACKEND_BASE_URL}/presence/attest`,
      { tokenB, attPi },
      { timeout: 8000 }
    );
    log("Attest OK ✅ proof_id=", res.data.proof_id);
    return notifyResult({ ok: true, proof_id: res.data.proof_id, result: res.data.result });
  } catch (e) {
    const body = e.response?.data;
    err("Attest error:", body || e.message);
    return notifyResult({ ok: false, step: "attest", error: body || e.message });
  }
}

// ========= BLE SERVICE =========
const characteristics = [
  new IdCharacteristic(),
  new AttemptTokenCharacteristic(),

  // NEW: relay-counter challenge RTT layer
  new ChallengeCharacteristic(),
  new ChallengeRespCharacteristic(),

  new ResultCharacteristic(),
];

// include legacy nonce signer only if both UUIDs are provided
if (LEGACY_NONCE_UUID && LEGACY_RESP_UUID) {
  characteristics.push(new NonceCharacteristic());
  characteristics.push(new ResponseCharacteristic());
}

const service = new bleno.PrimaryService({
  uuid: SERVICE_UUID,
  characteristics,
});

// ---- BLE lifecycle ----
bleno.on("stateChange", (state) => {
  log("bleno state:", state);
  if (state === "poweredOn") {
    bleno.startAdvertising("BeaconPresence", [SERVICE_UUID], (errAdv) => {
      if (errAdv) err("adv error:", errAdv);
      else log("advertising...");
    });
  } else {
    bleno.stopAdvertising();
  }
});

bleno.on("advertisingStart", (errAdvStart) => {
  if (errAdvStart) return err("advertisingStart error:", errAdvStart);
  log("advertising started");
  bleno.setServices([service], (err2) => {
    if (err2) err("setServices error:", err2);
    else log("services set ✅");
  });
});

process.on("SIGINT", () => {
  log("SIGINT, exiting...");
  process.exit(0);
});
