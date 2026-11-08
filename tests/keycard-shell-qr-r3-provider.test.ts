import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createCipheriv,
  createECDH,
  createHmac,
  randomBytes,
} from "node:crypto";

import {
  createKeycardR3CredentialProvider,
  KEYCARD_R3_HMAC_DOMAIN,
} from "../src/utils/keycard-r3-credentials.js";

import {
  createShellQrR3Provider,
} from "../src/utils/keycard-shell-qr-r3-provider.js";

import {
  decodeShellBatchRequest,
} from "../src/utils/keycard-shell-qr-batch.js";

import {
  deriveShellDeriveAesKey,
} from "../src/utils/keycard-shell-qr-derive-response.js";

test("Shell QR reproduces V3 deposit, withdrawal and signer", async () => {
  const root = Buffer.alloc(32, 0x42);
  const original = createKeycardR3CredentialProvider(root);
  const requested: string[][] = [];

  const bridge = createShellQrR3Provider(async (request) => {
    const parsed = decodeShellBatchRequest(request);
    requested.push(parsed.paths);

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
        .update(KEYCARD_R3_HMAC_DOMAIN)
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
        "aes-128-ccm",
        key,
        nonce,
        { authTagLength: 8 },
      );

      const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
      ]);

      return Buffer.concat([
        Buffer.from([0x4b, 0x4b, 0x52, 0x33, 0x03]),
        parsed.challenge,
        publicKey,
        nonce,
        ciphertext,
        cipher.getAuthTag(),
      ]);
    } finally {
      shared.fill(0);
      key.fill(0);
      plaintext.fill(0);
      credentials.forEach((value) => value.fill(0));
    }
  });

  const coordinates = {
    chainId: 11155111n,
    entrypointAddress:
      0x1111111111111111111111111111111111111111n,
    depositIndex: 17,
  };

  try {
    const deposit = await bridge.secretManager
      .getDepositSecrets(coordinates);
    const expectedDeposit = await original.secretManager
      .getDepositSecrets(coordinates);

    assert.deepEqual(deposit, expectedDeposit);

    const withdrawalCoordinates = {
      ...coordinates,
      withdrawIndex: 1,
    };

    const withdrawal = await bridge.secretManager
      .getSecrets(withdrawalCoordinates);
    const expectedWithdrawal = await original.secretManager
      .getSecrets(withdrawalCoordinates);

    assert.deepEqual(withdrawal, expectedWithdrawal);

    const signer = await bridge.secretManager
      .deriveEphemeralSigner(withdrawalCoordinates);
    const expectedSigner = await original.secretManager
      .deriveEphemeralSigner(withdrawalCoordinates);

    assert.equal(signer, expectedSigner);

    assert.deepEqual(requested, [
      [
        "m/28784'/1'/0'/1'/17'/0'",
        "m/28784'/1'/0'/0'/17'/0'",
      ],
      [
        "m/28784'/1'/0'/1'/17'/1'",
        "m/28784'/1'/0'/0'/17'/1'",
      ],
      [
        "m/28784'/1'/0'/2'/17'/1'",
      ],
    ]);

    console.log("PASS: V3 deposit credentials");
    console.log("PASS: V3 withdrawal credentials");
    console.log("PASS: V3 ephemeral signer");
    console.log("PASS: Exact derivation paths");
  } finally {
    original.dispose();
    bridge.dispose();
    root.fill(0);
  }
});
