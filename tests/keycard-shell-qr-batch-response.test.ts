import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createCipheriv,
  createECDH,
  createHmac,
  randomBytes,
} from "node:crypto";

import {
  createShellBatchRequest,
  decodeShellBatchRequest,
} from "../src/utils/keycard-shell-qr-batch.js";

import {
  decryptShellBatchResponse,
} from "../src/utils/keycard-shell-qr-batch-response.js";

import {
  deriveShellDeriveAesKey,
} from "../src/utils/keycard-shell-qr-derive-response.js";

const paths = [
  "m/28784'/1'/0'/0'/17'/0'",
  "m/28784'/1'/0'/1'/17'/0'",
];

function simulateShell(request: Uint8Array, root: Buffer) {
  const parsed = decodeShellBatchRequest(request);
  const shell = createECDH("secp256k1");
  shell.generateKeys();

  const publicKey = shell.getPublicKey(
    undefined, "uncompressed",
  );
  const shared = shell.computeSecret(parsed.hostPublicKey);
  const nonce = randomBytes(13);

  const key = deriveShellDeriveAesKey(
    shared, request, publicKey, nonce,
  );

  const credentials = parsed.paths.map((path) =>
    createHmac("sha256", root)
      .update("kohaku-key/v3-r3/privacy-pools-v1/deriveAt")
      .update("\0")
      .update(path)
      .digest()
  );

  const plaintext = Buffer.concat([
    Buffer.from([credentials.length]),
    ...credentials,
  ]);

  try {
    const cipher = createCipheriv(
      "aes-128-ccm", key, nonce, { authTagLength: 8 },
    );

    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);

    return {
      response: Buffer.concat([
        Buffer.from("KKR3\x03", "binary"),
        parsed.challenge,
        publicKey,
        nonce,
        ciphertext,
        cipher.getAuthTag(),
      ]),
      credentials,
    };
  } finally {
    shared.fill(0);
    key.fill(0);
    plaintext.fill(0);
  }
}

test("Two V3-R3 credentials survive encrypted QR exchange", () => {
  const root = Buffer.alloc(32, 0x42);
  const session = createShellBatchRequest(paths);
  const { response, credentials } =
    simulateShell(session.request, root);

  const recovered = decryptShellBatchResponse(
    session, response,
  );

  assert.equal(response.length, 172);
  assert.deepEqual(recovered, credentials);
  assert.notDeepEqual(recovered[0], recovered[1]);

  assert.throws(
    () => decryptShellBatchResponse(session, response),
    /already consumed/,
  );

  recovered.forEach((value) => value.fill(0));
  credentials.forEach((value) => value.fill(0));
  root.fill(0);
});

test("Tampered batch ciphertext is rejected", () => {
  const root = Buffer.alloc(32, 0x42);
  const session = createShellBatchRequest(paths);
  const { response, credentials } =
    simulateShell(session.request, root);

  const tampered = Buffer.from(response);
  tampered[105] ^= 1;

  assert.throws(
    () => decryptShellBatchResponse(session, tampered),
  );

  credentials.forEach((value) => value.fill(0));
  root.fill(0);
});

test("Different QR session cannot accept the response", () => {
  const root = Buffer.alloc(32, 0x42);
  const first = createShellBatchRequest(paths);
  const second = createShellBatchRequest(paths);
  const { response, credentials } =
    simulateShell(first.request, root);

  assert.throws(
    () => decryptShellBatchResponse(second, response),
    /challenge mismatch/,
  );

  credentials.forEach((value) => value.fill(0));
  root.fill(0);
});
