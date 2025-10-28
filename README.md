# Quick Setup: SpaceScrypt BLE Beacon (super simple)

Follow these steps on your Raspberry Pi to bring up a BLE beacon that signs with Ed25519.

---

## 1) Install Node.js + Bluetooth tools
```bash
sudo apt update
sudo apt install -y nodejs npm bluetooth bluez
```

## 2) Give Node Bluetooth perms

```bash
sudo setcap 'cap_net_raw,cap_net_admin+eip' "$(readlink -f "$(which node)")"
```

## 3) Create project

```bash
mkdir /ble-beacon
cd /ble-beacon

#Add ble packages
npm init -y
npm i @abandonware/bleno @abandonware/bluetooth-hci-socket dotenv tweetnacl
```

## 4) Add the .env and create the ed25519 pair

```bash
SEED=$(openssl rand -hex 32); echo "$SEED"
node -e "const n=require('tweetnacl');const s=Buffer.from(process.argv[1],'hex');const k=n.sign.keyPair.fromSeed(s);console.log(Buffer.from(k.publicKey).toString('hex'))" "$SEED"

cat > .env <<'EOF'
VITE_SERVICE_UUID=eb5c86a4-733c-4d9d-aab2-285c2dab09a1
VITE_ID_CHAR_UUID=eb5c86a4-733c-4d9d-aab2-285c2dab09a2
VITE_SIGN_NONCE_UUID=eb5c86a4-733c-4d9d-aab2-285c2dab09a3
VITE_SIGN_RESP_UUID=eb5c86a4-733c-4d9d-aab2-285c2dab09a4
BEACON_ID_HEX=0000000000000002(3/4/5)
ED25519_SEED_HEX=PUT_64_HEX_BYTES_HERE
EOF
```

## 5) Add beacon.js

file in the repo



