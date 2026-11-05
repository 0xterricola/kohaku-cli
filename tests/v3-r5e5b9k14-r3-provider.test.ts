import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { test } from "node:test";

import {
  decodeFunctionData,
  getAddress,
  isAddressEqual,
  keccak256,
  parseTransaction,
  recoverTransactionAddress,
  serializeTransaction,
  type Hex,
} from "viem";

import { privateKeyToAccount } from "viem/accounts";

import {
  createKeycardR3CredentialProvider,
  KEYCARD_R3_HMAC_DOMAIN,
} from "../src/utils/keycard-r3-credentials.js";

import { buildDepositPayload } from
  "../../kohaku-sdk-research/packages/privacy-pools/src/state/selectors/deposits.selector.js";

import { entrypointDepositNativeAbi } from
  "../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/entrypoint.abi.js";

// Deterministic public fixtures, never real hardware entropy.
const testRoot = (label: string) =>
  createHash("sha256")
    .update(`kohaku-key/r5-e5b9k14/${label}`)
    .digest();

const chainId = 987654321n;
const entrypoint =
  0x1111111111111111111111111111111111111111n;
const asset =
  0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeEn;

const coordinates = {
  chainId,
  entrypointAddress: entrypoint,
  depositIndex: 17,
};

test("R3 HMAC derivation preserves the frozen path contract", async () => {
  const callerRoot = testRoot("root");
  const provider = createKeycardR3CredentialProvider(
    callerRoot,
    { accountIndex: 0 },
  );

  const path = "m/28784'/1'/0'/1'/17'/0'";

  try {
    const expected = "0x" + createHmac(
      "sha256",
      callerRoot,
    )
      .update(KEYCARD_R3_HMAC_DOMAIN)
      .update("\0")
      .update(path)
      .digest("hex");

    assert.equal(await provider.deriveAt(path), expected);

    // The adapter owns an independent in-memory copy.
    callerRoot.fill(0);

    assert.equal(await provider.deriveAt(path), expected);

    await assert.rejects(
      provider.deriveAt("m/44'/60'/0'/0/0"),
      /outside R3 Privacy Pools namespace/,
    );

    await assert.rejects(
      provider.secretManager.deriveDelegatorSigner({
        path: "m/44'/60'/0'/0/0",
      }),
      /outside R3 Privacy Pools namespace/,
    );

    console.log("PASS: Frozen HMAC domain and path");
    console.log("PASS: Caller buffer isolation");
    console.log("PASS: Non-R3 paths rejected");
    console.log("PASS: Software-key fallback rejected");
  } finally {
    provider.dispose();
  }

  await assert.rejects(
    provider.deriveAt(path),
    /disposed/,
  );

  assert.throws(
    () => createKeycardR3CredentialProvider(
      new Uint8Array(31)
    ),
    /32-byte/,
  );

  assert.throws(
    () => createKeycardR3CredentialProvider(
      testRoot("invalid-account"),
      { accountIndex: -1 },
    ),
    /account index/,
  );

  console.log("PASS: Provider disposal");
  console.log("PASS: Invalid configuration rejected");
});

test("R3 provider produces SDK credentials and signed native deposit", async () => {
  const first = createKeycardR3CredentialProvider(
    testRoot("root")
  );

  const repeated = createKeycardR3CredentialProvider(
    testRoot("root")
  );

  const wrong = createKeycardR3CredentialProvider(
    testRoot("wrong-root")
  );

  try {
    const owned = await first.secretManager
      .getDepositSecrets(coordinates);

    const recovered = await repeated.secretManager
      .getDepositSecrets(coordinates);

    const incorrect = await wrong.secretManager
      .getDepositSecrets(coordinates);

    assert.equal(
      owned.precommitment,
      recovered.precommitment,
    );

    assert.notEqual(
      owned.precommitment,
      incorrect.precommitment,
    );

    const nextDeposit = await first.secretManager
      .getDepositSecrets({
        ...coordinates,
        depositIndex: 18,
      });

    const anotherChain = await first.secretManager
      .getDepositSecrets({
        ...coordinates,
        chainId: chainId + 1n,
      });

    const anotherEntrypoint = await first.secretManager
      .getDepositSecrets({
        ...coordinates,
        entrypointAddress: entrypoint + 1n,
      });

    const withdrawal = await first.secretManager
      .getSecrets({
        ...coordinates,
        withdrawIndex: 1,
      });

    assert.notEqual(
      owned.precommitment,
      nextDeposit.precommitment,
    );

    assert.notEqual(
      owned.precommitment,
      anotherChain.precommitment,
    );

    assert.notEqual(
      owned.precommitment,
      anotherEntrypoint.precommitment,
    );

    assert.notEqual(
      owned.precommitment,
      withdrawal.precommitment,
    );

    console.log("PASS: SDK deposit credential reconstruction");
    console.log("PASS: Wrong-root isolation");
    console.log("PASS: Deposit, chain and entrypoint separation");
    console.log("PASS: Withdrawal credential separation");

    const amount = 2000000000000000n;

    const payload = buildDepositPayload(
      owned.precommitment,
      asset,
      amount,
      entrypoint,
    );

    const again = buildDepositPayload(
      recovered.precommitment,
      asset,
      amount,
      entrypoint,
    );

    const wrongPayload = buildDepositPayload(
      incorrect.precommitment,
      asset,
      amount,
      entrypoint,
    );

    assert.ok(isAddressEqual(
      getAddress(payload.to),
      "0x1111111111111111111111111111111111111111",
    ));

    assert.equal(payload.value, amount);
    assert.equal(payload.data, again.data);
    assert.notEqual(payload.data, wrongPayload.data);

    const decoded = decodeFunctionData({
      abi: entrypointDepositNativeAbi,
      data: payload.data as Hex,
    });

    assert.equal(decoded.functionName, "deposit");
    assert.deepEqual(
      decoded.args,
      [owned.precommitment],
    );

    console.log("PASS: Hardware-compatible deposit calldata");
    console.log("PASS: 0.002 native ETH value");
    console.log("PASS: SDK ABI matches R3 precommitment");

    // Public test private key, not hardware or a real wallet.
    const signer = privateKeyToAccount(
      `0x${"0".repeat(63)}1` as Hex
    );

    const tx = {
      type: "eip1559" as const,
      chainId: Number(chainId),
      nonce: 0,
      to: getAddress(payload.to),
      data: payload.data as Hex,
      value: payload.value,
      gas: 350000n,
      maxFeePerGas: 2n,
      maxPriorityFeePerGas: 1n,
    };

    const digest = keccak256(
      serializeTransaction(tx)
    );

    const signed = await signer.signTransaction(tx);

    assert.match(signed, /^0x02[0-9a-f]+$/i);

    const parsed = parseTransaction(signed);

    assert.equal(parsed.type, "eip1559");
    assert.equal(parsed.chainId, tx.chainId);
    assert.equal(parsed.nonce, tx.nonce);
    assert.equal(parsed.data, tx.data);
    assert.equal(parsed.value, tx.value);

    const recoveredSigner =
      await recoverTransactionAddress({
        serializedTransaction:
          signed as `0x02${string}`,
      });

    assert.ok(isAddressEqual(
      recoveredSigner,
      signer.address,
    ));

    assert.notEqual(
      digest,
      keccak256(serializeTransaction({
        ...tx,
        data: wrongPayload.data as Hex,
      }))
    );

    console.log("PASS: Synthetic EIP-1559 signing");
    console.log("PASS: Signer recovery");
    console.log("PASS: Wrong credential changes signed digest");
  } finally {
    first.dispose();
    repeated.dispose();
    wrong.dispose();
  }

  console.log("Physical hardware used: NO");
  console.log("Real credentials used: NO");
  console.log("Network requests: NO");
  console.log("Broadcasting: DISABLED");
  console.log("PASS: R5-E5B9K14");
});
