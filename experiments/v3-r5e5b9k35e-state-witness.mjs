import assert from "node:assert/strict";
import {
  existsSync, readFileSync, writeFileSync,
  renameSync, chmodSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  decodeEventLog,
  decodeFunctionResult,
  encodeFunctionData,
  getAddress,
  isAddressEqual,
  parseAbi,
  toEventSelector,
  toHex,
} from "viem";

import {
  POOL_EVENTS_SIGNATURES,
} from "../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/events.abi.ts";

import {
  buildMerkleTree,
  proofFromTree,
  merkleHash,
} from "../../kohaku-sdk-research/packages/privacy-pools/src/utils/proof.util.ts";

import {
  commitment,
} from "../../kohaku-sdk-research/packages/privacy-pools/src/utils.ts";

const work = join(
  homedir(),
  "Library/Application Support/KohakuKeyResearch/v3-r5e9i-parser-fix"
);

const cachePath = join(
  work, "r5-e5b9k35e-public-scan.json"
);

const outputPath = join(
  work, "r5-e5b9k35e-state-witness.json"
);

const rpcUrls = [
  "https://ethereum-sepolia-rpc.publicnode.com",
  "https://sepolia.gateway.tenderly.co",
];

const allowedMethods = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getLogs",
  "eth_getTransactionReceipt",
  "eth_call",
]);

const leafEvent = POOL_EVENTS_SIGNATURES.LeafInserted;
const depositEvent = POOL_EVENTS_SIGNATURES.PoolDeposited;

const stateRootAbi = parseAbi([
  "function currentRoot() view returns (uint256)",
]);

function load(name) {
  return JSON.parse(
    readFileSync(join(work, name), "utf8")
  );
}

function saveAtomic(path, value) {
  const temp = path + ".writing";

  writeFileSync(
    temp,
    JSON.stringify(value, null, 2),
    { mode: 0o600 }
  );

  chmodSync(temp, 0o600);
  renameSync(temp, path);
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function rpc(method, params = []) {
  assert.ok(
    allowedMethods.has(method),
    `Prohibited RPC method: ${method}`
  );

  let lastFailure = "unknown";

  for (let attempt = 0; attempt < 3; attempt++) {
    for (const url of rpcUrls) {
      const host = new URL(url).hostname;

      try {
        const response = await fetch(url, {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
          }),
          signal: AbortSignal.timeout(20000),
        });

        if (!response.ok) {
          throw new Error(
            `HTTP_${response.status}`
          );
        }

        const body = await response.json();

        if (body.error) {
          throw new Error(
            `RPC_${body.error.code ?? "error"}`
          );
        }

        if (body.result === undefined) {
          throw new Error("MISSING_RPC_RESULT");
        }

        return body.result;
      } catch (error) {
        // Do not print provider error messages:
        // arbitrary RPC responses may contain data.
        const reason = String(error.message);

        lastFailure =
          `${host}: ` +
          (
            /^(HTTP_|RPC_|MISSING_RPC_RESULT)/.test(reason)
              ? reason
              : "TRANSPORT_FAILURE"
          );
      }
    }

    await delay(800 * 2 ** attempt);
  }

  throw new Error(
    `RPC unavailable for ${method}; ` +
    `last failure: ${lastFailure}; ` +
    "completed scan checkpoints are preserved"
  );
}

export function verifyDepositAccounting(grossRaw, netRaw) {
  const gross = BigInt(grossRaw);
  const net = BigInt(netRaw);

  // This checkpoint is bound to the actual
  // K32 transaction, not an arbitrary deposit.
  assert.equal(
    gross,
    2000000000000000n,
    "Unexpected K32 transaction value"
  );

  assert.equal(
    net,
    1980000000000000n,
    "Unexpected K32 pool deposit value"
  );

  const fee = gross - net;

  assert.equal(
    fee,
    20000000000000n,
    "Unexpected deposit fee"
  );

  assert.equal(fee * 10000n, gross * 100n);

  return {
    grossDepositValueWei: gross.toString(),
    netDepositValueWei: net.toString(),
    vettingFeeWei: fee.toString(),
    vettingFeeBps: 100,
  };
}

export function leafPositionFromEventIndex(index) {
  const eventIndex = BigInt(index);

  assert.ok(
    eventIndex >= 1n,
    "LeafInserted index must be 1-based"
  );

  assert.ok(
    eventIndex <= BigInt(Number.MAX_SAFE_INTEGER),
    "LeafInserted index exceeds safe JS range"
  );

  return Number(eventIndex - 1n);
}

export function recomputeLeanProofRoot(proof) {
  // A LeanIMT proof's index is its compressed
  // direction-bit path, NOT its leaf position.
  // Only use the UNPADDED proof here.
  assert.ok(Array.isArray(proof.siblings));
  assert.ok(proof.siblings.length <= 32);

  const pathIndex = BigInt(proof.index);

  assert.ok(pathIndex >= 0n);
  assert.ok(
    pathIndex < (1n << BigInt(proof.siblings.length)),
    "Path index exceeds unpadded sibling depth"
  );

  let calculated = BigInt(proof.leaf);

  for (let depth = 0;
       depth < proof.siblings.length;
       depth++) {
    const sibling = BigInt(proof.siblings[depth]);
    const isRight =
      ((pathIndex >> BigInt(depth)) & 1n) === 1n;

    calculated = isRight
      ? merkleHash(sibling, calculated)
      : merkleHash(calculated, sibling);
  }

  return calculated;
}

export function assertContiguousEvents(events) {
  for (let i = 0; i < events.length; i++) {
    assert.equal(
      BigInt(events[i].index),
      BigInt(i) + 1n,
      `Missing or duplicate leaf index at ${i + 1}`
    );
  }

  return true;
}

export function assertTargetLeaf(events, index, leaf) {
  assertContiguousEvents(events);

  const event = events[leafPositionFromEventIndex(index)];

  assert.ok(event, "Deposited leaf index not present");
  assert.equal(BigInt(event.leaf), BigInt(leaf));

  return true;
}

async function contractRoot(pool, block) {
  const raw = await rpc("eth_call", [
    {
      to: pool,
      data: encodeFunctionData({
        abi: stateRootAbi,
        functionName: "currentRoot",
      }),
    },
    toHex(block),
  ]);

  return decodeFunctionResult({
    abi: stateRootAbi,
    functionName: "currentRoot",
    data: raw,
  });
}

export function auditedScanStartBlock(pool, head) {
  const expectedPool = getAddress(
    "0x644d5a2554d36e27509254f32ccfebe8cd58861f"
  );

  assert.ok(
    isAddressEqual(pool, expectedPool),
    "Unexpected pool for archived scan boundary"
  );

  // Conservative start from the earlier K22
  // public-chain audit. We do not assert this is
  // the pool's precise deployment block.
  const firstAuditedBlock = 8461453n;

  assert.ok(
    head >= firstAuditedBlock,
    "Snapshot predates audited scan boundary"
  );

  return firstAuditedBlock;
}

async function readBlock(number) {
  const block = await rpc(
    "eth_getBlockByNumber",
    [toHex(number), false]
  );

  assert.ok(block, "Block unavailable");
  assert.equal(BigInt(block.number), number);

  return block;
}

async function scanWindow(pool, start, end) {
  let logs;

  try {
    logs = await rpc("eth_getLogs", [{
      address: pool,
      fromBlock: toHex(start),
      toBlock: toHex(end),
      topics: [toEventSelector(leafEvent)],
    }]);
  } catch (error) {
    const length = end - start + 1n;

    if (length <= 625n) {
      throw new Error(
        `Unable to scan ${start}-${end}: ` +
        error.message
      );
    }

    // Some public RPCs reject large historical
    // log ranges. Split without skipping blocks.
    const midpoint = (start + end) / 2n;

    console.log(
      "SPLIT:",
      start.toString(),
      "through",
      end.toString()
    );

    const left = await scanWindow(
      pool, start, midpoint
    );

    await delay(200);

    const right = await scanWindow(
      pool, midpoint + 1n, end
    );

    return [...left, ...right];
  }

  assert.ok(Array.isArray(logs));

  return logs.map(log => {
    const decoded = decodeEventLog({
      abi: [leafEvent],
      topics: log.topics,
      data: log.data,
      strict: true,
    });

    return {
      index: decoded.args._index.toString(),
      leaf: decoded.args._leaf.toString(),
      root: decoded.args._root.toString(),
      blockNumber:
        BigInt(log.blockNumber).toString(),
      transactionHash: log.transactionHash,
      logIndex: BigInt(log.logIndex).toString(),
    };
  });
}

async function main() {
  const k32 = load(
    "r5-e5b9k32-publicnode-broadcast.json"
  );

  const k33 = load(
    "r5-e5b9k33-recovery.json"
  );

  assert.equal(k32.status, "confirmed");
  assert.equal(k32.receiptVerified, true);
  assert.equal(k32.depositEventVerified, true);
  assert.equal(k33.credentialReproduced, true);
  assert.equal(k33.onchainDepositEventMatched, true);
  assert.equal(
    k32.transactionHash.toLowerCase(),
    k33.transactionHash.toLowerCase()
  );

  const pool = getAddress(k32.depositEventPool);

  assert.ok(
    isAddressEqual(pool, k33.depositPool)
  );

  const chainId = BigInt(
    await rpc("eth_chainId")
  );

  assert.equal(chainId, 11155111n);

  const head = BigInt(
    await rpc("eth_blockNumber")
  );

  const snapshot = await readBlock(head);

  console.log("=== K35-E public state snapshot ===");
  console.log("Pool:", pool);
  console.log("Snapshot block:", head.toString());

  const receipt = await rpc(
    "eth_getTransactionReceipt",
    [k32.transactionHash]
  );

  assert.ok(receipt);
  assert.equal(receipt.status, "0x1");
  assert.equal(
    BigInt(receipt.blockNumber).toString(),
    k32.blockNumber
  );
  assert.equal(
    receipt.blockHash.toLowerCase(),
    k32.blockHash.toLowerCase()
  );

  const depositedLog = receipt.logs.find(log =>
    isAddressEqual(log.address, pool) &&
    BigInt(log.logIndex).toString() ===
      k32.depositEventLogIndex
  );

  assert.ok(depositedLog);

  const deposited = decodeEventLog({
    abi: [depositEvent],
    topics: depositedLog.topics,
    data: depositedLog.data,
    strict: true,
  });

  // The Entrypoint deducts the configured vetting
  // fee before the pool creates its commitment.
  // Check the exact accounting of this mined deposit.
  const accounting = verifyDepositAccounting(
    k32.depositValueWei,
    deposited.args._value
  );

  console.log("Gross deposit (wei):",
    accounting.grossDepositValueWei);
  console.log("Net pool note (wei):",
    accounting.netDepositValueWei);
  console.log("Vetting fee (wei):",
    accounting.vettingFeeWei);

  const targetCommitment = commitment({
    balance: deposited.args._value,
    label: deposited.args._label,
    precommitment: deposited.args._precommitment,
  });

  assert.equal(
    targetCommitment,
    deposited.args._commitment,
    "SDK and mined deposit commitments differ"
  );

  const receiptLeaves = receipt.logs
    .filter(log =>
      isAddressEqual(log.address, pool) &&
      log.topics[0]?.toLowerCase() ===
        toEventSelector(leafEvent).toLowerCase()
    )
    .map(log => decodeEventLog({
      abi: [leafEvent],
      topics: log.topics,
      data: log.data,
      strict: true,
    }));

  const inserted = receiptLeaves.filter(
    event =>
      event.args._leaf === targetCommitment
  );

  assert.equal(
    inserted.length, 1,
    "Mined deposit commitment must have one leaf insertion"
  );

  const targetIndex = inserted[0].args._index;
  const deployment = auditedScanStartBlock(pool, head);

  console.log(
    "Conservative public scan start:",
    deployment.toString()
  );
  console.log(
    "Mined leaf index:",
    targetIndex.toString()
  );

  let cache;

  if (existsSync(cachePath)) {
    cache = JSON.parse(
      readFileSync(cachePath, "utf8")
    );

    assert.equal(
      cache.checkpoint,
      "R5-E5B9K35E-public-scan"
    );
    assert.equal(
      cache.chainId,
      11155111
    );
    assert.ok(isAddressEqual(cache.pool, pool));
    assert.equal(
      BigInt(cache.firstCodeBlock),
      deployment
    );

    const checked = BigInt(cache.scannedThrough);

    assert.ok(
      checked < head,
      "Existing scan already reaches or exceeds snapshot"
    );

    const anchor = await readBlock(checked);

    assert.equal(
      anchor.hash.toLowerCase(),
      cache.scannedThroughHash.toLowerCase(),
      "Saved scan anchor changed"
    );

    assertContiguousEvents(cache.events);

    console.log(
      "Resuming public scan after block:",
      cache.scannedThrough
    );
  } else {
    cache = {
      checkpoint: "R5-E5B9K35E-public-scan",
      chainId: 11155111,
      pool,
      firstCodeBlock: deployment.toString(),
      scannedThrough: null,
      scannedThroughHash: null,
      events: [],
    };
  }

  // Sequential scans avoid bursts of concurrent
  // eth_getLogs calls on shared public RPCs.
  const batchSize = 5000n;
  const concurrency = 1;

  let next = cache.scannedThrough === null
    ? deployment
    : BigInt(cache.scannedThrough) + 1n;

  let round = 0;

  while (next <= head) {
    const ranges = [];

    for (
      let i = 0;
      i < concurrency && next <= head;
      i++
    ) {
      const end =
        next + batchSize - 1n > head
          ? head
          : next + batchSize - 1n;

      ranges.push([next, end]);
      next = end + 1n;
    }

    const batches = await Promise.all(
      ranges.map(([start, end]) =>
        scanWindow(pool, start, end)
      )
    );

    for (const events of batches) {
      cache.events.push(...events);
    }

    assertContiguousEvents(cache.events);

    const lastScanned = ranges.at(-1)[1];

    cache.scannedThrough = lastScanned.toString();

    const anchor = await readBlock(lastScanned);
    cache.scannedThroughHash = anchor.hash;

    round++;

    // Persist EVERY completed range. A subsequent
    // RPC failure cannot erase this progress.
    saveAtomic(cachePath, cache);

    if (round % 10 === 0 || lastScanned === head) {
      console.log(
        "SCAN:",
        cache.scannedThrough,
        "leaves:",
        cache.events.length
      );
    }

    await delay(200);
  }

  assert.ok(cache.events.length > 0);

  assertTargetLeaf(
    cache.events,
    targetIndex,
    targetCommitment
  );

  const leaves = cache.events.map(
    event => BigInt(event.leaf)
  );

  console.log("=== Build actual state Merkle tree ===");

  const tree = await buildMerkleTree(leaves);

  const leafPosition =
    leafPositionFromEventIndex(targetIndex);

  // The absolute position MUST match the mined
  // event. Never substitute the compressed index.
  assert.equal(
    tree.indexOf(targetCommitment),
    leafPosition,
    "Target commitment occupies wrong leaf position"
  );

  assert.equal(
    leaves[leafPosition],
    targetCommitment
  );

  // Raw LeanIMT proof: siblings omit levels
  // with no sibling, and index encodes the
  // compressed left/right path.
  const rawProof =
    tree.generateProof(leafPosition);

  assert.equal(rawProof.leaf, targetCommitment);
  assert.equal(rawProof.root, tree.root);

  assert.equal(
    recomputeLeanProofRoot(rawProof),
    tree.root,
    "Unpadded LeanIMT proof does not reconstruct root"
  );

  // SDK circuit format: 32 padded siblings.
  // Preserve the COMPRESSED proof index.
  const witness = proofFromTree(
    tree,
    targetCommitment
  );

  assert.equal(witness.index, rawProof.index);
  assert.equal(witness.root, tree.root);
  assert.equal(witness.siblings.length, 32);

  console.log("Absolute leaf position:", leafPosition);
  console.log("Compressed proof index:", witness.index);
  console.log(
    "Actual LeanIMT proof depth:",
    rawProof.siblings.length
  );

  const onchainRoot = await contractRoot(
    pool, head
  );

  assert.equal(
    tree.root,
    onchainRoot,
    "Rebuilt state root differs from Sepolia"
  );

  assert.equal(
    BigInt(cache.events.at(-1).root),
    onchainRoot,
    "Final LeafInserted event root mismatch"
  );

  const anchoredSnapshot = await readBlock(head);

  assert.equal(
    anchoredSnapshot.hash.toLowerCase(),
    snapshot.hash.toLowerCase(),
    "Snapshot reorganization detected"
  );

  const result = {
    checkpoint: "R5-E5B9K35E-state-witness",
    chainId: 11155111,
    transactionHash: k32.transactionHash,
    pool,
    depositedBlock: k32.blockNumber,
    ...accounting,
    snapshotBlock: head.toString(),
    snapshotHash: snapshot.hash,
    stateLeafCount: leaves.length,
    leafInsertedEventIndex: targetIndex.toString(),
    stateLeafPosition: leafPosition,
    stateIndex: witness.index,
    compressedPathVerified: true,
    stateRoot: witness.root.toString(),
    stateSiblings: witness.siblings.map(
      sibling => sibling.toString()
    ),
    commitmentMatchedMinedDeposit: true,
    leafIndexMatchedReceipt: true,
    contiguousLeafHistory: true,
    reconstructedRootMatchedOnchain: true,
    inclusionWitnessReady: true,
    containsPrivateCredentialMaterial: false,
    hardwareAccessed: false,
    zkProofGenerated: false,
    signed: false,
    broadcast: false,
  };

  saveAtomic(outputPath, result);

  console.log(JSON.stringify({
    ...result,
    stateSiblings: "[32 public sibling hashes]",
  }, null, 2));

  console.log(
    "PASS: K35-E deposited state witness verified"
  );
}

const isMain = process.argv[1]?.endsWith(
  "v3-r5e5b9k35e-state-witness.mjs"
);

if (isMain) {
  await main();
}
