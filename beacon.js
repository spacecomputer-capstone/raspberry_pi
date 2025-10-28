// beacon.js — Ed25519 version matching your Fastify backend
require("dotenv").config();
const bleno = require("@abandonware/bleno");
const nacl = require("tweetnacl");

// ---- Env ----
const SERVICE_UUID    = (process.env.VITE_SERVICE_UUID || "").toLowerCase();
const ID_CHAR_UUID    = (process.env.VITE_ID_CHAR_UUID || "").toLowerCase();
const NONCE_CHAR_UUID = (process.env.VITE_SIGN_NONCE_UUID || "").toLowerCase();
const RESP_CHAR_UUID  = (process.env.VITE_SIGN_RESP_UUID || "").toLowerCase();

const BEACON_ID_HEX = (process.env.BEACON_ID_HEX || "").toLowerCase();
if (!/^[0-9a-f]{16}$/.test(BEACON_ID_HEX)) throw new Error("BEACON_ID_HEX must be 16 hex chars (8 bytes)");
const BEACON_ID = Buffer.from(BEACON_ID_HEX, "hex");

// Ed25519 seed → keypair
const SEED_HEX = (process.env.ED25519_SEED_HEX || "").toLowerCase();
if (!/^[0-9a-f]{64}$/.test(SEED_HEX)) throw new Error("ED25519_SEED_HEX must be 32-byte hex");
const seed = Buffer.from(SEED_HEX, "hex");
const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(seed)); // {publicKey, secretKey}

// ---- GATT characteristics ----
class IdCharacteristic extends bleno.Characteristic {
  constructor() { super({ uuid: ID_CHAR_UUID, properties: ["read"], value: null }); }
  onReadRequest(offset, cb) {
    if (offset) return cb(this.RESULT_ATTR_NOT_LONG);
    cb(this.RESULT_SUCCESS, BEACON_ID);
  }
}

let lastNonce = null;
class NonceCharacteristic extends bleno.Characteristic {
  constructor() { super({ uuid: NONCE_CHAR_UUID, properties: ["writeWithoutResponse"], value: null }); }
  onWriteRequest(data, offset, _withoutResponse, cb) {
    if (offset) return cb(this.RESULT_ATTR_NOT_LONG);
    lastNonce = Buffer.from(data);    // expect 16 bytes (from /api/nonce)
    trySignAndNotify();
    cb(this.RESULT_SUCCESS);
  }
}

let notifyCb = null;
class ResponseCharacteristic extends bleno.Characteristic {
  constructor() { super({ uuid: RESP_CHAR_UUID, properties: ["notify"], value: null }); }
  onSubscribe(_m, updateValueCallback) { notifyCb = updateValueCallback; }
  onUnsubscribe() { notifyCb = null; }
}

const service = new bleno.PrimaryService({
  uuid: SERVICE_UUID,
  characteristics: [ new IdCharacteristic(), new NonceCharacteristic(), new ResponseCharacteristic() ],
});

// ---- Helpers ----
function be64(tsMs) {
  const b = Buffer.alloc(8);
  let n = BigInt(tsMs);
  for (let i = 7; i >= 0; i--) { b[i] = Number(n & 0xffn); n >>= 8n; } // big-endian
  return b;
}

function buildPayload(nonceBuf) {
  // message = nonce(16) || ts_be64(8)
  const tsBuf = be64(Date.now());
  const msg = Buffer.concat([nonceBuf, tsBuf]);      // 24 bytes
  const sig = Buffer.from(nacl.sign.detached(new Uint8Array(msg), kp.secretKey)); // 64 bytes
  // notify format: [ ts_be64 (8) || sig (64) ] = 72 bytes
  return Buffer.concat([tsBuf, sig]);
}

function trySignAndNotify() {
  if (!notifyCb || !lastNonce) return;
  try { notifyCb(buildPayload(lastNonce)); }
  catch (e) { console.error("notify failed:", e.message); }
  finally { lastNonce = null; }
}

// ---- BLE lifecycle ----
bleno.on("stateChange", (state) => {
  console.log("bleno state:", state);
  if (state === "poweredOn") bleno.startAdvertising("BeaconPresence", [SERVICE_UUID], (err)=>err&&console.error("adv error:",err));
  else bleno.stopAdvertising();
});
bleno.on("advertisingStart", (err) => {
  if (err) return console.error("advertisingStart error:", err);
  console.log("advertising started");
  bleno.setServices([service], (err2)=>err2&&console.error("setServices error:", err2));
});
process.on("SIGINT", ()=>process.exit(0));
