import assert from "node:assert/strict";
import {
  createHash,
  timingSafeEqual,
} from "node:crypto";

import {
  readFileSync,
  readSync,
} from "node:fs";

import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import {
  getAddress,
  toHex,
} from "viem";

import {
  PrivacyPoolsV1_0xBow,
} from "@kohaku-eth/privacy-pools";

// No remote network access is required in K21R7.
globalThis.fetch = () => {
  throw new Error(
    "Network forbidden during local credential check"
  );
};

const cliRoot = process.cwd();

const importLocal = relative =>
  import(pathToFileURL(
    join(cliRoot, relative)
  ).href);

const work = join(
  homedir(),
  "Library/Application Support/KohakuKeyResearch/v3-r5e9i-parser-fix",
);

const archivePath = join(
  work,
  "r5-e5b9k21r6-pool-history.json",
);

function loadVerifiedArchive() {
  const snapshotBytes = readFileSync(
    "src/utils/ppv1-sepolia-state.json"
  );

  const snapshot = JSON.parse(
    snapshotBytes.toString("utf8")
  );

  const config =
    PrivacyPoolsV1_0xBow[11155111];

  assert.ok(
    config?.entrypoint?.entrypointAddress,
    "Sepolia entrypoint missing"
  );

  const entrypointAddress = BigInt(
    config.entrypoint.entrypointAddress
  );

  const entrypoint = getAddress(
    toHex(entrypointAddress, { size: 20 })
  );

  const state = snapshot[
    `privacy-pool-state-11155111-${entrypointAddress}`
  ];

  assert.ok(
    state,
    "Bundled Sepolia state missing"
  );

  const deposits =
    state.deposits?.depositsTuples;

  const pools =
    state.pools?.poolsTuples;

  assert.ok(
    Array.isArray(deposits) &&
    deposits.length > 0 &&
    Array.isArray(pools) &&
    pools.length > 0,
    "Bundled public history missing"
  );

  const source = {
    entrypoint,
    snapshotHead: BigInt(
      state.sync.lastSyncedBlock
    ),

    sha256: createHash("sha256")
      .update(snapshotBytes)
      .digest("hex"),

    snapshotKeys: deposits.map(tuple =>
      BigInt(tuple[0]).toString()
    ),

    snapshotPools: pools.map(tuple =>
      getAddress(
        toHex(BigInt(tuple[0]), { size: 20 })
      )
    ),
  };

  const archive = JSON.parse(
    readFileSync(archivePath, "utf8")
  );

  return { source, archive };
}

function readHardwareRoots() {
  const input = Buffer.alloc(64);

  try {
    let offset = 0;

    while (offset < input.length) {
      const count = readSync(
        3,
        input,
        offset,
        input.length - offset,
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
      Buffer.from(input.subarray(0, 32)),
      Buffer.from(input.subarray(32, 64)),
    ];
  } finally {
    input.fill(0);
  }
}

async function main() {
  console.log(
    "=== R5-E5B9K21R7: Offline credential reuse ==="
  );

  const { source, archive } =
    loadVerifiedArchive();

  const {
    verifyR3PoolHistory,
    assertR3CredentialUnused,
  } = await importLocal(
    "src/utils/keycard-r3-pool-reuse-guard.mjs"
  );

  const verified = verifyR3PoolHistory(
    archive,
    source,
  );

  console.log(
    "PASS: Public archive matches bundled snapshot"
  );

  console.log(
    "PASS: Contiguous public-history ranges verified"
  );

  // Archive-only mode validates everything before
  // any physical hardware session is requested.
  if (
    process.argv.includes("--archive-only")
  ) {
    console.log(JSON.stringify({
      ...verified,
      hardwareAccessed: false,
      networkAccess: false,
    }, null, 2));

    console.log(
      "PASS: R5-E5B9K21R7 archive preflight"
    );

    return;
  }

  const [rootA, rootB] =
    readHardwareRoots();

  let providerA;
  let providerB;

  try {
    assert.ok(
      timingSafeEqual(rootA, rootB),
      "Independent hardware BIP-85 roots differ"
    );

    console.log(
      "PASS: Independent hardware roots match"
    );

    const {
      createKeycardR3CredentialProvider,
    } = await importLocal(
      "src/utils/keycard-r3-credentials.ts"
    );

    const {
      formatCredentialId,
      sdkCoordinates,
    } = await importLocal(
      "../kohaku-key/experiments/v3-r5e3-credential-ids.mjs"
    );

    providerA =
      createKeycardR3CredentialProvider(
        rootA,
        { accountIndex: 0 }
      );

    providerB =
      createKeycardR3CredentialProvider(
        rootB,
        { accountIndex: 0 }
      );

    const credentialId = formatCredentialId({
      chainId: 11155111n,
      entrypointAddress:
        BigInt(source.entrypoint),
      accountIndex: 0,
      depositIndex: 17,
      role: "deposit",
      secretIndex: 0,
    });

    const coordinates = sdkCoordinates(
      credentialId,
      {
        chainId: 11155111n,
        entrypointAddress:
          BigInt(source.entrypoint),
        accountIndex: 0,
      }
    );

    assert.equal(
      coordinates.depositIndex,
      17
    );

    const first =
      await providerA.secretManager
        .getDepositSecrets(coordinates);

    const second =
      await providerB.secretManager
        .getDepositSecrets(coordinates);

    assert.equal(
      first.precommitment,
      second.precommitment,
      "Independent hardware credentials differ"
    );

    assert.equal(
      first.nullifier,
      second.nullifier,
      "Hardware nullifier reconstruction differs"
    );

    assert.equal(
      first.salt,
      second.salt,
      "Hardware salt reconstruction differs"
    );

    console.log(
      "PASS: Hardware credential recovered twice"
    );

    assertR3CredentialUnused(
      first.precommitment,
      archive
    );

    console.log(
      "PASS: Index-17 precommitment absent from cached deposit history"
    );

    console.log(JSON.stringify({
      checkpoint: "R5-E5B9K21R7",
      chainId: 11155111,
      depositIndex: 17,
      ...verified,
      credentialReuseDetected: false,
      historicalSnapshotIndependentlyAudited:
        false,
      freshHeadRecheckRequired: true,
      secretMaterialPrinted: false,
      networkRequests: 0,
      transactionSigned: false,
      broadcast: false,
    }, null, 2));

    console.log(
      "PASS: R5-E5B9K21R7"
    );
  } finally {
    providerA?.dispose();
    providerB?.dispose();
    rootA.fill(0);
    rootB.fill(0);
  }
}

try {
  await main();
} catch {
  // Fail closed without exposing credential
  // material or unexpected library errors.
  console.error(
    "FAIL: Archive or hardware credential verification failed"
  );

  process.exitCode = 1;
}
