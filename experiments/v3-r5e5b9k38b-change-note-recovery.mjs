
import assert from "node:assert/strict";
import { timingSafeEqual } from "node:crypto";
import { readSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  decodeEventLog,
  isAddressEqual,
  parseAbiItem,
  toEventSelector,
} from "viem";

import {
  createKeycardR3CredentialProvider,
} from "./src/utils/keycard-r3-credentials.ts";

import { commitment } from "../kohaku-sdk-research/packages/privacy-pools/src/utils.ts";

const work = join(
  homedir(),
  "Library/Application Support/KohakuKeyResearch/v3-r5e9i-parser-fix"
);

const output = join(
  work,
  "r5-e5b9k38b-change-recovery.json"
);

const chainId = 11155111n;

const pool =
  "0x644d5A2554d36e27509254F32ccfeBe8cd58861f";

const entrypoint =
  "0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB";

const signer =
  "0x155a8332A3504D5F532742Ae6531cd0e28035972";

const depositTx =
  "0x33c357c4b212ac67f2d93c5f4b97563ae50939dd21f6e3ede19b92520d62a22c";

const withdrawalTx =
  "0x3e2b488921a19e0bedddb7858d3cea7cb670cbc1239c50987ae9cdc583f82c1d";

const expectedChangeCommitment =
  0x29b2d484e4251b8040e4df8a9f3a71d35fea5008cbd4f970aff2a471e6148a2an;

const changeValue = 990000000000000n;

const providers = [
  "https://ethereum-sepolia-rpc.publicnode.com",
  "https://sepolia.gateway.tenderly.co",
];

const depositedEvent = parseAbiItem(
  "event Deposited(address indexed _depositor, " +
  "uint256 _commitment, uint256 _label, " +
  "uint256 _value, uint256 _precommitment)"
);

const withdrawnEvent = parseAbiItem(
  "event Withdrawn(address indexed _processooor, " +
  "uint256 _value, uint256 _spentNullifier, " +
  "uint256 _newCommitment)"
);

async function rpc(url, method, params = []) {
  assert.ok(providers.includes(url));

  assert.ok(
    ["eth_chainId", "eth_getTransactionReceipt"].includes(method),
    "Only public read-only RPC methods permitted"
  );

  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 38,
      method,
      params,
    }),
    signal: AbortSignal.timeout(30000),
  });

  assert.ok(response.ok, "RPC HTTP failure");

  const body = await response.json();

  assert.ok(
    !body.error && Object.hasOwn(body, "result"),
    "RPC result unavailable"
  );

  return body.result;
}

function findEvent(receipt, abiItem) {
  const topic = toEventSelector(abiItem).toLowerCase();

  const matching = receipt.logs.filter(log =>
    isAddressEqual(log.address, pool) &&
    log.topics?.[0]?.toLowerCase() === topic
  );

  assert.equal(
    matching.length, 1,
    "Expected exactly one matching pool event"
  );

  return decodeEventLog({
    abi: [abiItem],
    data: matching[0].data,
    topics: matching[0].topics,
    strict: true,
  });
}

async function readPublicAnchor() {
  let agreed = null;

  for (const url of providers) {
    const chain = await rpc(url, "eth_chainId");

    assert.equal(BigInt(chain), chainId);

    const [depositReceipt, withdrawalReceipt] =
      await Promise.all([
        rpc(url, "eth_getTransactionReceipt", [depositTx]),
        rpc(url, "eth_getTransactionReceipt", [withdrawalTx]),
      ]);

    assert.ok(depositReceipt);
    assert.ok(withdrawalReceipt);

    assert.equal(depositReceipt.status, "0x1");
    assert.equal(withdrawalReceipt.status, "0x1");

    assert.equal(
      BigInt(withdrawalReceipt.blockNumber),
      12072784n
    );

    assert.ok(isAddressEqual(
      withdrawalReceipt.from, signer
    ));

    assert.ok(isAddressEqual(
      withdrawalReceipt.to, pool
    ));

    const deposited = findEvent(
      depositReceipt, depositedEvent
    );

    const withdrawn = findEvent(
      withdrawalReceipt, withdrawnEvent
    );

    assert.ok(isAddressEqual(
      deposited.args._depositor, signer
    ));

    assert.ok(isAddressEqual(
      withdrawn.args._processooor, signer
    ));

    assert.equal(
      deposited.args._value,
      1980000000000000n
    );

    assert.equal(
      withdrawn.args._value,
      changeValue
    );

    assert.equal(
      deposited.args._value - withdrawn.args._value,
      changeValue
    );

    assert.equal(
      withdrawn.args._newCommitment,
      expectedChangeCommitment
    );

    const anchor = {
      depositLabel: deposited.args._label,
      originalPrecommitment:
        deposited.args._precommitment,
      newCommitment:
        withdrawn.args._newCommitment,
      spentNullifier:
        withdrawn.args._spentNullifier,
      blockHash: withdrawalReceipt.blockHash.toLowerCase(),
    };

    if (agreed !== null) {
      assert.deepEqual(
        anchor, agreed,
        "Two RPC providers disagree"
      );
    }

    agreed = anchor;

    console.log(
      "PASS: Mined deposit and withdrawal events:",
      new URL(url).hostname
    );
  }

  return agreed;
}

async function main() {
  const anchor = await readPublicAnchor();

  assert.equal(typeof commitment, "function");
  assert.equal(
    typeof createKeycardR3CredentialProvider,
    "function"
  );

  if (process.argv.includes("--public-preflight")) {
    // Dummy public values only. This checks that the
    // exact hash implementation initializes without
    // retrieving hardware credentials.
    const testHash = commitment({
      balance: 1n,
      label: 1n,
      precommitment: 1n,
    });

    assert.equal(typeof testHash, "bigint");

    console.log("PASS: Original commitment implementation");
    console.log("PASS: Mined change commitment anchored");
    console.log("Hardware accessed: NO");
    console.log("Signing: NO");
    console.log("Broadcasting: NO");
    return;
  }

  let providerA;
  let providerB;

  const payload = Buffer.alloc(64);

  try {
    let offset = 0;

    while (offset < 64) {
      const count = readSync(
        3, payload, offset, 64 - offset, null
      );

      assert.ok(
        count > 0,
        "Hardware credential pipe ended unexpectedly"
      );

      offset += count;
    }

    const rootA = payload.subarray(0, 32);
    const rootB = payload.subarray(32, 64);

    assert.ok(
      timingSafeEqual(rootA, rootB),
      "Authenticated hardware sessions differ"
    );

    providerA = createKeycardR3CredentialProvider(
      rootA, { accountIndex: 0 }
    );

    providerB = createKeycardR3CredentialProvider(
      rootB, { accountIndex: 0 }
    );

    const coordinates = {
      chainId,
      entrypointAddress: entrypoint,
      depositIndex: 17,
      withdrawIndex: 1,
    };

    const changeA =
      await providerA.secretManager.getSecrets(coordinates);

    const changeB =
      await providerB.secretManager.getSecrets(coordinates);

    for (const field of [
      "nullifier",
      "salt",
      "precommitment",
      "nullifierHash",
    ]) {
      assert.equal(
        changeA[field],
        changeB[field],
        "Independent change-note derivation mismatch"
      );
    }

    assert.notEqual(
      changeA.precommitment,
      anchor.originalPrecommitment,
      "Change credential reused original precommitment"
    );

    console.log(
      "PASS: Two independent hardware change derivations"
    );

    const recoveredCommitment = commitment({
      balance: changeValue,
      label: anchor.depositLabel,
      precommitment: changeA.precommitment,
    });

    assert.equal(
      recoveredCommitment,
      anchor.newCommitment,
      "Recovered change note does not match mined event"
    );

    console.log(
      "PASS: Recovered commitment matches on-chain withdrawal"
    );

    const evidence = {
      checkpoint: "R5-E5B9K38B-hardware-change-recovery",
      chainId: Number(chainId),
      sourceDepositTransactionHash: depositTx,
      withdrawalTransactionHash: withdrawalTx,
      withdrawalBlockNumber: "12072784",
      changeValueWei: changeValue.toString(),
      changeCommitment:
        "0x" + recoveredCommitment
          .toString(16).padStart(64, "0"),
      hardwareSessionsAgreed: true,
      independentChangeDerivationsAgreed: true,
      minedWithdrawalEventVerified: true,
      changeCommitmentRecovered: true,
      privateCredentialPersisted: false,
      privateWitnessPersisted: false,
      signingAttempted: false,
      broadcast: false,
    };

    // Public metadata only. Never store roots,
    // salts, nullifiers, or private credentials.
    writeFileSync(
      output,
      JSON.stringify(evidence, null, 2),
      { mode: 0o600, flag: "wx" }
    );

    console.log("PASS: Public-only recovery evidence saved");
    console.log("Private credentials persisted: NO");
    console.log("Signing: NO");
    console.log("Broadcasting: NO");
  } finally {
    providerA?.dispose();
    providerB?.dispose();
    payload.fill(0);
  }
}

await main();
