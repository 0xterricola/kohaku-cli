import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createCipheriv,
  createECDH,
  createHmac,
  randomBytes,
} from "node:crypto";
import {
  decodeFunctionData,
  getAddress,
  toHex,
} from "viem";
import { PrivacyPoolsV1_0xBow } from "@kohaku-eth/privacy-pools";

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
import {
  buildDepositPayload,
} from "../../kohaku-sdk-research/packages/privacy-pools/src/state/selectors/deposits.selector.ts";
import {
  entrypointDepositNativeAbi,
} from "../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/entrypoint.abi.ts";

test("V4 Shell QR deposit index 15 reproduces Sepolia calldata", async () => {
  // Public synthetic fixture; never a real wallet root.
  const root = Buffer.alloc(32, 0x42);
  const requested: string[][] = [];

  const exchange = async (request: Uint8Array) => {
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

    const credentials = parsed.paths.map(path =>
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
      credentials.forEach(value => value.fill(0));
    }
  };

  const bridge = createShellQrR3Provider(exchange, {
    accountIndex: 0,
  });
  const original = createKeycardR3CredentialProvider(
    root, { accountIndex: 0 },
  );

  try {
    const config = PrivacyPoolsV1_0xBow[11155111];
    assert.ok(config?.entrypoint?.entrypointAddress);

    const entrypointAddress = BigInt(
      config.entrypoint.entrypointAddress,
    );

    const coordinates = {
      chainId: 11155111n,
      entrypointAddress,
      depositIndex: 15,
    };

    const first = await bridge.secretManager
      .getDepositSecrets(coordinates);
    const second = await bridge.secretManager
      .getDepositSecrets(coordinates);
    const expected = await original.secretManager
      .getDepositSecrets(coordinates);

    assert.deepEqual(first, second);
    assert.deepEqual(first, expected);

    const withdrawalCoordinates = {
      ...coordinates,
      withdrawIndex: 0,
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
        "m/28784'/1'/0'/1'/15'/0'",
        "m/28784'/1'/0'/0'/15'/0'",
      ],
      [
        "m/28784'/1'/0'/1'/15'/0'",
        "m/28784'/1'/0'/0'/15'/0'",
      ],
      [
        "m/28784'/1'/0'/1'/15'/0'",
        "m/28784'/1'/0'/0'/15'/0'",
      ],
      [
        "m/28784'/1'/0'/2'/15'/0'",
      ],
    ]);

    const amount = 2000000000000000n;
    const asset = BigInt(
      "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
    );

    const payload = buildDepositPayload(
      first.precommitment,
      asset,
      amount,
      entrypointAddress,
    );

    assert.equal(payload.value, amount);
    assert.equal(
      getAddress(payload.to),
      getAddress(toHex(entrypointAddress, { size: 20 })),
    );

    const decoded = decodeFunctionData({
      abi: entrypointDepositNativeAbi,
      data: payload.data,
    });

    assert.equal(decoded.functionName, "deposit");
    assert.deepEqual(decoded.args, [first.precommitment]);

    console.log("PASS: Two independent encrypted QR exchanges");
    console.log("PASS: V3-compatible credential derivation");
    console.log("PASS: Exact account 0 / deposit 15 paths");
    console.log("PASS: Real Sepolia SDK deposit calldata");
    console.log("PASS: No signing or broadcasting");
  } finally {
    bridge.dispose();
    original.dispose();
    root.fill(0);
  }
});
