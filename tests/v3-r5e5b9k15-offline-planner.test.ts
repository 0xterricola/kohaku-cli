import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  decodeFunctionData,
  keccak256,
  parseTransaction,
  serializeTransaction,
  type Hex,
} from "viem";

import {
  createKeycardR3CredentialProvider,
} from "../src/utils/keycard-r3-credentials.js";

import {
  prepareKeycardR3OfflineDeposit,
  R3_RESEARCH_CHAIN_ID,
  R3_RESEARCH_ENTRYPOINT,
  R3_RESEARCH_AMOUNT,
  R3_NATIVE_ETH_ASSET,
} from "../src/utils/keycard-r3-offline-deposit.js";

import { buildDepositPayload } from
  "../../kohaku-sdk-research/packages/privacy-pools/src/state/selectors/deposits.selector.js";

import { entrypointDepositNativeAbi } from
  "../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/entrypoint.abi.js";

const root = (label: string) =>
  createHash("sha256")
    .update(`kohaku-key/r5-e5b9k15/${label}`)
    .digest();

test("R3 offline deposit preparation is reproducible", async () => {
  const first = createKeycardR3CredentialProvider(
    root("owned"),
  );

  const repeated = createKeycardR3CredentialProvider(
    root("owned"),
  );

  const wrong = createKeycardR3CredentialProvider(
    root("wrong"),
  );

  const anotherAccount =
    createKeycardR3CredentialProvider(
      root("owned"),
      { accountIndex: 1 },
    );

  const makePlan = (
    provider: typeof first,
    depositIndex = 17,
  ) => prepareKeycardR3OfflineDeposit({
    provider,
    depositIndex,
    buildDepositPayload,
  });

  try {
    const a = await makePlan(first);
    const b = await makePlan(repeated);
    const invalidRoot = await makePlan(wrong);
    const nextDeposit = await makePlan(first, 18);
    const otherAccount = await makePlan(anotherAccount);

    assert.equal(
      a.unsignedTransaction,
      b.unsignedTransaction,
    );

    assert.equal(
      a.signingDigest,
      b.signingDigest,
    );

    assert.notEqual(
      a.signingDigest,
      invalidRoot.signingDigest,
    );

    assert.notEqual(
      a.signingDigest,
      nextDeposit.signingDigest,
    );

    assert.notEqual(
      a.signingDigest,
      otherAccount.signingDigest,
    );

    assert.equal(a.coordinates.chainId, R3_RESEARCH_CHAIN_ID);
    assert.equal(
      a.coordinates.entrypointAddress,
      R3_RESEARCH_ENTRYPOINT,
    );
    assert.equal(a.coordinates.depositIndex, 17);
    assert.equal(a.coordinates.accountIndex, 0);
    assert.equal(otherAccount.coordinates.accountIndex, 1);

    console.log("PASS: R3 deposit reproducibility");
    console.log("PASS: Wrong-root separation");
    console.log("PASS: Deposit-index separation");
    console.log("PASS: Account-index separation");

    const secret = await first.secretManager
      .getDepositSecrets({
        chainId: R3_RESEARCH_CHAIN_ID,
        entrypointAddress: R3_RESEARCH_ENTRYPOINT,
        depositIndex: 17,
      });

    const decoded = decodeFunctionData({
      abi: entrypointDepositNativeAbi,
      data: a.call.data,
    });

    assert.equal(decoded.functionName, "deposit");
    assert.deepEqual(
      decoded.args,
      [secret.precommitment],
    );

    assert.equal(a.call.value, R3_RESEARCH_AMOUNT);

    const tx = parseTransaction(a.unsignedTransaction);

    assert.equal(tx.type, "eip1559");
    assert.equal(tx.chainId, Number(R3_RESEARCH_CHAIN_ID));
    assert.equal(tx.nonce, 0);
    assert.equal(tx.value, R3_RESEARCH_AMOUNT);
    assert.equal(tx.data, a.call.data);

    assert.equal(
      a.signingDigest,
      keccak256(a.unsignedTransaction),
    );

    console.log("PASS: SDK-native deposit calldata");
    console.log("PASS: Hardware-compatible precommitment");
    console.log("PASS: EIP-1559 transaction unsigned");

    await assert.rejects(
      prepareKeycardR3OfflineDeposit({
        provider: first,
        depositIndex: -1,
        buildDepositPayload,
      }),
      /deposit index/,
    );

    await assert.rejects(
      prepareKeycardR3OfflineDeposit({
        provider: first,
        depositIndex: 17,
        buildDepositPayload: () => ({
          to: a.call.to,
          value: a.call.value,
          data: "0x",
        }),
      }),
      /Invalid SDK deposit calldata/,
    );

    await assert.rejects(
      prepareKeycardR3OfflineDeposit({
        provider: first,
        depositIndex: 17,
        buildDepositPayload: () => ({
          to: a.call.to,
          value: a.call.value + 1n,
          data: a.call.data,
        }),
      }),
      /value mismatch/,
    );

    await assert.rejects(
      prepareKeycardR3OfflineDeposit({
        provider: first,
        depositIndex: 17,
        buildDepositPayload: () => ({
          to: a.call.to,
          value: a.call.value,
          data: "0x12345678",
        }),
      }),
      /ABI mismatch/,
    );

    console.log("PASS: Invalid index rejected");
    console.log("PASS: Malformed calldata rejected");
    console.log("PASS: Altered transaction value rejected");
    console.log("PASS: Wrong ABI rejected");
  } finally {
    first.dispose();
    repeated.dispose();
    wrong.dispose();
    anotherAccount.dispose();
  }

  console.log("Physical hardware used: NO");
  console.log("Real credential roots used: NO");
  console.log("Network requests: NO");
  console.log("Signing performed: NO");
  console.log("Broadcasting: DISABLED");
  console.log("PASS: R5-E5B9K15");
});
