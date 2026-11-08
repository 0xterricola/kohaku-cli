import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createCipheriv,
  createECDH,
  createHmac,
  randomBytes,
} from "node:crypto";

import {
  createShellDeriveRequest,
  decodeShellDeriveRequest,
  validateShellDerivePath,
} from "../src/utils/keycard-shell-qr-derive.js";

import {
  decryptShellDeriveResponse,
  deriveShellDeriveAesKey,
} from "../src/utils/keycard-shell-qr-derive-response.js";

function simulateShell(
  request: Uint8Array,
  credential: Uint8Array,
): Buffer {
  const parsed = decodeShellDeriveRequest(request);

  const shell = createECDH("secp256k1");
  shell.generateKeys();

  const shellPublicKey = shell.getPublicKey(
    undefined,
    "uncompressed",
  );
  const sharedSecret = shell.computeSecret(parsed.hostPublicKey);
  const nonce = randomBytes(13);

  const key = deriveShellDeriveAesKey(
    sharedSecret,
    request,
    shellPublicKey,
    nonce,
  );

  try {
    const cipher = createCipheriv(
      "aes-128-ccm",
      key,
      nonce,
      { authTagLength: 8 },
    );

    const ciphertext = Buffer.concat([
      cipher.update(credential),
      cipher.final(),
    ]);

    return Buffer.concat([
      Buffer.from([0x4b, 0x4b, 0x52, 0x32, 0x02]),
      parsed.challenge,
      shellPublicKey,
      nonce,
      ciphertext,
      cipher.getAuthTag(),
    ]);
  } finally {
    sharedSecret.fill(0);
    key.fill(0);
  }
}

test("V3-R3 credential survives encrypted Shell QR exchange", () => {
  const path = "m/28784'/1'/0'/0'/17'/0'";
  const session = createShellDeriveRequest(path);

  const root = Buffer.alloc(32, 0x42);
  const expected = createHmac("sha256", root)
    .update("kohaku-key/v3-r3/privacy-pools-v1/deriveAt")
    .update("\0")
    .update(path)
    .digest();

  const response = simulateShell(session.request, expected);
  const recovered = decryptShellDeriveResponse(
    session,
    response,
  );

  assert.deepEqual(recovered, expected);
  assert.equal(response.length, 139);

  recovered.fill(0);
  expected.fill(0);
  root.fill(0);
});

test("Tampered encrypted credentials are rejected", () => {
  const session = createShellDeriveRequest(
    "m/28784'/1'/0'/0'/17'/0'",
  );

  const credential = Buffer.alloc(32, 0x7a);
  const response = simulateShell(session.request, credential);

  const tampered = Buffer.from(response);
  tampered[105] ^= 1;

  assert.throws(() =>
    decryptShellDeriveResponse(session, tampered),
  );

  const wrongChallenge = Buffer.from(response);
  wrongChallenge[5] ^= 1;

  assert.throws(() =>
    decryptShellDeriveResponse(session, wrongChallenge),
    /challenge mismatch/,
  );

  credential.fill(0);
});

test("Invalid derivation paths are rejected", () => {
  for (const path of [
    "m/44'/60'/0'",
    "m/28784'/1'/01'",
    "m/28784'/1'/0",
    "m/28784'/1'/",
    "m/28784'/1'/0'/../../",
  ]) {
    assert.throws(() => validateShellDerivePath(path));
  }
});
