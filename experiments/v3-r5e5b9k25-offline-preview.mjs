
globalThis.fetch = () => {
  throw new Error("Network access prohibited in K25");
};
import assert from "node:assert/strict";
import { timingSafeEqual } from "node:crypto";
import { readSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import {
  decodeFunctionData,
  getAddress,
  isAddressEqual,
  toHex,
} from "viem";

const importFile = async path =>
  import(pathToFileURL(path).href);

function acquireHardwareRoots() {
  const payload = Buffer.alloc(64);

  try {
    let offset = 0;

    while (offset < payload.length) {
      const n = readSync(
        3,
        payload,
        offset,
        payload.length - offset,
        null,
      );

      if (n <= 0) {
        throw new Error(
          "Incomplete hardware credential IPC"
        );
      }

      offset += n;
    }

    return [
      Buffer.from(payload.subarray(0, 32)),
      Buffer.from(payload.subarray(32, 64)),
    ];
  } finally {
    payload.fill(0);
  }
}

async function main() {
  // Fail closed if an imported dependency attempts fetch.
  globalThis.fetch = () => {
    throw new Error("Network disabled for K18");
  };

  const [rootA, rootB] = acquireHardwareRoots();

  let providerA;
  let providerB;

  try {
    assert.ok(
      timingSafeEqual(rootA, rootB),
      "Independent hardware roots differ"
    );

    console.log(
      "PASS: Two physical hardware roots reproduced"
    );

    const cli = process.cwd();

    const credentials = await importFile(join(
      cli,
      "src/utils/keycard-r3-credentials.ts",
    ));

    const identifiers = await importFile(join(
      cli,
      "../kohaku-key/experiments/v3-r5e3-credential-ids.mjs",
    ));

    const sdk = await importFile(join(
      cli,
      "../kohaku-sdk-research/packages/privacy-pools/src/state/selectors/deposits.selector.ts",
    ));

    const { entrypointDepositNativeAbi } =
      await importFile(join(
        cli,
        "../kohaku-sdk-research/packages/privacy-pools/src/data/abis/entrypoint.abi.ts",
      ));

    const { PrivacyPoolsV1_0xBow } =
      await import("@kohaku-eth/privacy-pools");


    const k25 = await import(
      (await import("node:url")).pathToFileURL(
        (await import("node:path")).join(
          process.cwd(),
          "experiments/v3-r5e5b9k25-public-evidence.mjs"
        )
      ).href
    );

    const evidence = k25.verifyK25PublicEvidence();

    console.log(
      "PASS: Historical and refreshed public evidence verified"
    );

    const chainId = 11155111n;
    const accountIndex = 0;
    const depositIndex = 17;
    const amount = 2000000000000000n;

    // SDK native ETH sentinel, not a substitute token.
    const asset = BigInt(
      "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"
    );

    const config = PrivacyPoolsV1_0xBow[
      Number(chainId)
    ];

    assert.ok(
      config?.entrypoint?.entrypointAddress,
      "Sepolia Privacy Pools configuration missing"
    );

    const entrypointAddress = BigInt(
      config.entrypoint.entrypointAddress
    );

    assert.ok(
      entrypointAddress > 0n &&
      entrypointAddress < (1n << 160n),
      "Invalid configured Sepolia entrypoint"
    );

    assert.notEqual(
      entrypointAddress,
      0x1111111111111111111111111111111111111111n,
      "Synthetic entrypoint cannot be used on Sepolia"
    );

    const entrypoint = getAddress(
      toHex(entrypointAddress, { size: 20 })
    );

    console.log(
      "PASS: Real Sepolia chain configuration selected"
    );

    console.log(
      "PASS: Synthetic entrypoint excluded"
    );

    const credentialId = identifiers.formatCredentialId({
      chainId,
      entrypointAddress,
      accountIndex,
      depositIndex,
      role: "deposit",
      secretIndex: 0,
    });

    const coordinates = identifiers.sdkCoordinates(
      credentialId,
      {
        chainId,
        entrypointAddress,
        accountIndex,
      }
    );

    assert.equal(coordinates.depositIndex, 17);

    providerA =
      credentials.createKeycardR3CredentialProvider(
        rootA,
        { accountIndex },
      );

    providerB =
      credentials.createKeycardR3CredentialProvider(
        rootB,
        { accountIndex },
      );

    const first = await providerA.secretManager
      .getDepositSecrets(coordinates);

    const second = await providerB.secretManager
      .getDepositSecrets(coordinates);

    assert.equal(
      first.precommitment,
      second.precommitment
    );

    assert.equal(
      first.nullifier,
      second.nullifier
    );

    assert.equal(first.salt, second.salt);

    const otherChain = await providerA.secretManager
      .getDepositSecrets({
        ...coordinates,
        chainId: 987654321n,
      });

    const nextDeposit = await providerA.secretManager
      .getDepositSecrets({
        ...coordinates,
        depositIndex: 18,
      });

    assert.notEqual(
      first.precommitment,
      otherChain.precommitment
    );

    assert.notEqual(
      first.precommitment,
      nextDeposit.precommitment
    );

    console.log(
      "PASS: Sepolia R3 credentials reproduced across sessions"
    );

    console.log(
      "PASS: Chain and deposit-index separation"
    );

    const makePayload = secret =>
      sdk.buildDepositPayload(
        secret.precommitment,
        asset,
        amount,
        entrypointAddress
      );

    const payloadA = makePayload(first);
    const payloadB = makePayload(second);

    k25.assertUnused(
      first.precommitment,
      evidence.allPublicKeys
    );

    console.log(
      "PASS: Hardware index-17 precommitment unused through block " +
      evidence.checkedThrough
    );

    // Construct the real unsigned deposit intent
    // entirely in volatile memory. Fees and gas remain
    // deliberately unassigned until the live review.
    const unsignedIntent = {
      type: "eip1559",
      chainId: Number(chainId),
      from: evidence.sender,
      to: entrypoint,
      nonce: evidence.observedNonce,
      value: amount,
      data: payloadA.data,
    };

    assert.equal(unsignedIntent.chainId, 11155111);
    assert.equal(unsignedIntent.value, amount);
    assert.equal(unsignedIntent.to, entrypoint);
    assert.equal(unsignedIntent.data, payloadB.data);

    console.log(
      "PASS: Unsigned real-deposit intent constructed in memory"
    );



    assert.equal(
      payloadA.data,
      payloadB.data
    );

    assert.equal(
      payloadA.value,
      amount
    );

    assert.ok(
      isAddressEqual(
        getAddress(payloadA.to),
        entrypoint
      )
    );

    const decoded = decodeFunctionData({
      abi: entrypointDepositNativeAbi,
      data: payloadA.data,
    });

    assert.equal(
      decoded.functionName,
      "deposit"
    );

    assert.deepEqual(
      decoded.args,
      [first.precommitment]
    );

    console.log(
      "PASS: Real Sepolia SDK deposit calldata reproduced"
    );

    console.log(
      "PASS: Hardware precommitment matches decoded calldata"
    );

    console.log(
      "PASS: Correct entrypoint and native ETH value"
    );

    // Do not serialize a signable real-chain transaction.
    // Nonce, fee, gas, deposit-index availability and
    // on-chain entrypoint status remain unverified.
    console.log(JSON.stringify({
      checkpoint: "R5-E5B9K25",
      chainId: Number(chainId),
      entrypoint,
      depositIndex,
      amountWei: amount.toString(),
      hardwareCredentials: true,
      calldataVerified: true,
      onchainStateVerified: false,
      unsignedIntentConstructedInMemory: true,
      signed: false,
      broadcast: false,
    }, null, 2));

    console.log("PASS: R5-E5B9K25");
  } finally {
    providerA?.dispose();
    providerB?.dispose();
    rootA.fill(0);
    rootB.fill(0);
  }
}

try {
  await main();
} catch (error) {
  console.error(
    "FAIL:",
    error instanceof Error
      ? error.message
      : "Sepolia preview failed"
  );

  process.exitCode = 1;
}
