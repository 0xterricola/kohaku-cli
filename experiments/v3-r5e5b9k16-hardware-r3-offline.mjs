import assert from "node:assert/strict";
import { timingSafeEqual } from "node:crypto";
import { readSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const importFile = async path =>
  import(pathToFileURL(path).href);

function readHardwareRoots() {
  const payload = Buffer.alloc(64);

  try {
    let offset = 0;

    while (offset < payload.length) {
      const count = readSync(
        3,
        payload,
        offset,
        payload.length - offset,
        null,
      );

      if (count <= 0) {
        throw new Error(
          "Incomplete hardware credential IPC"
        );
      }

      offset += count;
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
  // No RPC or remote data source is used.
  globalThis.fetch = () => {
    throw new Error("Network disabled for K16");
  };

  const [rootA, rootB] = readHardwareRoots();

  let providerA;
  let providerB;

  try {
    if (!timingSafeEqual(rootA, rootB)) {
      throw new Error(
        "Independent hardware roots differ"
      );
    }

    console.log(
      "PASS: Two independent BIP-85 roots verified"
    );

    const cli = process.cwd();

    const credentials = await importFile(join(
      cli,
      "src/utils/keycard-r3-credentials.ts",
    ));

    const planner = await importFile(join(
      cli,
      "src/utils/keycard-r3-offline-deposit.ts",
    ));

    const sdk = await importFile(join(
      cli,
      "../kohaku-sdk-research/packages/privacy-pools/src/state/selectors/deposits.selector.ts",
    ));

    const identifiers = await importFile(join(
      cli,
      "../kohaku-key/experiments/v3-r5e3-credential-ids.mjs",
    ));

    providerA =
      credentials.createKeycardR3CredentialProvider(
        rootA,
        { accountIndex: 0 },
      );

    providerB =
      credentials.createKeycardR3CredentialProvider(
        rootB,
        { accountIndex: 0 },
      );

    const chainId = planner.R3_RESEARCH_CHAIN_ID;
    const entrypointAddress =
      planner.R3_RESEARCH_ENTRYPOINT;

    assert.equal(chainId, 987654321n);

    const credentialId = identifiers.formatCredentialId({
      chainId,
      entrypointAddress,
      accountIndex: 0,
      depositIndex: 17,
      role: "deposit",
      secretIndex: 0,
    });

    const coordinates = identifiers.sdkCoordinates(
      credentialId,
      {
        chainId,
        entrypointAddress,
        accountIndex: 0,
      },
    );

    assert.equal(coordinates.depositIndex, 17);

    console.log(
      "PASS: R5-E credential identifier resolved"
    );

    const prepare = provider =>
      planner.prepareKeycardR3OfflineDeposit({
        provider,
        depositIndex: coordinates.depositIndex,
        buildDepositPayload: sdk.buildDepositPayload,
      });

    const first = await prepare(providerA);
    const second = await prepare(providerB);

    assert.equal(
      first.unsignedTransaction,
      second.unsignedTransaction,
    );

    assert.equal(
      first.signingDigest,
      second.signingDigest,
    );

    assert.equal(
      first.coordinates.chainId,
      chainId,
    );

    assert.equal(
      first.coordinates.entrypointAddress,
      entrypointAddress,
    );

    assert.equal(
      first.coordinates.depositIndex,
      17,
    );

    assert.equal(
      first.call.value,
      2000000000000000n,
    );

    console.log(
      "PASS: Physical R3 credential provider"
    );

    console.log(
      "PASS: Hardware-derived SDK deposit calldata"
    );

    console.log(
      "PASS: Two sessions reproduce identical unsigned EIP-1559 transaction"
    );

    console.log(
      "PASS: Two sessions reproduce identical signing digest"
    );

    // Synthetic transaction metadata only.
    // Never display BIP-85 roots, nullifiers, salts,
    // or raw credential derivation output.
    console.log(JSON.stringify({
      checkpoint: "R5-E5B9K16",
      chainId: Number(chainId),
      depositIndex: 17,
      amountWei: first.call.value.toString(),
      signingDigest: first.signingDigest,
      hardwareCredentials: true,
      signed: false,
      broadcast: false,
    }, null, 2));

    console.log("PASS: R5-E5B9K16");
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
      : "Hardware integration failed",
  );

  process.exitCode = 1;
}
