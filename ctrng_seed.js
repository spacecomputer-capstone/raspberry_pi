import { OrbitportSDK } from "@spacecomputer-io/orbitport-sdk-ts";
import nacl from "tweetnacl";

async function main() {
    try {
        const sdk = new OrbitportSDK({
            config: {
                clientId: process.env.OP_CLIENT_ID,
                clientSecret: process.env.OP_CLIENT_SECRET,
            },
        });

        // Request randomness from ctRNG
        // We need 32 bytes for the seed. The API returns hex.
        // Ensure we get enough by parsing the result.
        console.error("Requesting randomness from ctRNG...");
        const result = await sdk.ctrng.random();
        const hexData = result.data.data;

        // Check if we have enough data (32 bytes = 64 hex chars)
        if (hexData.length < 64) {
            throw new Error(`Insufficient randomness received: ${hexData.length} chars`);
        }

        // Take the first 32 bytes (64 hex characters) as the seed
        const seedHex = hexData.slice(0, 64);
        const seedBytes = new Uint8Array(Buffer.from(seedHex, "hex"));

        // Generate Keypair from seed
        const keyPair = nacl.sign.keyPair.fromSeed(seedBytes);
        const publicKeyHex = Buffer.from(keyPair.publicKey).toString("hex");

        console.error("Successfully generated keys.");
        console.log(`
cat > .env <<'EOF'
VITE_SERVICE_UUID=eb5c86a4-733c-4d9d-aab2-285c2dab09a1
VITE_ID_CHAR_UUID=eb5c86a4-733c-4d9d-aab2-285c2dab09a2
VITE_SIGN_NONCE_UUID=eb5c86a4-733c-4d9d-aab2-285c2dab09a3
VITE_SIGN_RESP_UUID=eb5c86a4-733c-4d9d-aab2-285c2dab09a4
BEACON_ID_HEX=${publicKeyHex}
ED25519_SEED_HEX=${seedHex}
EOF
`);

    } catch (err) {
        console.error("Error generating keys:", err);
        process.exit(1);
    }
}

main();
