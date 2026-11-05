import assert from "node:assert/strict";
import {
  readFileSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  decodeEventLog,
  decodeFunctionResult,
  encodeFunctionData,
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
} from "../../kohaku-sdk-research/packages/privacy-pools/src/utils/proof.util.ts";

const work = join(
  homedir(),
  "Library/Application Support/KohakuKeyResearch/v3-r5e9i-parser-fix"
);

const output = join(
  work,
  "r5-e5b9k39b-change-state-witness.json"
);

const load = name => JSON.parse(
  readFileSync(join(work, name), "utf8")
);

const pool =
  "0x644d5A2554d36e27509254F32ccfeBe8cd58861f";

const txHash =
  "0x3e2b488921a19e0bedddb7858d3cea7cb670cbc1239c50987ae9cdc583f82c1d";

const withdrawalBlock = 12072784n;

const expectedRoot =
  21456747409809235877618994284678988524351012416630627424000389143602581130000n;

const expectedCommitment =
  0x29b2d484e4251b8040e4df8a9f3a71d35fea5008cbd4f970aff2a471e6148a2an;

const providers = [
  "https://ethereum-sepolia-rpc.publicnode.com",
  "https://sepolia.gateway.tenderly.co",
];

const leafAbi = POOL_EVENTS_SIGNATURES.LeafInserted;
const leafTopic = toEventSelector(leafAbi).toLowerCase();

const rootAbi = parseAbi([
  "function currentRoot() view returns (uint256)",
]);

async function rpc(url, method, params = []) {
  assert.ok(providers.includes(url));

  assert.ok([
    "eth_chainId",
    "eth_getTransactionReceipt",
    "eth_call",
  ].includes(method));

  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 39,
      method,
      params,
    }),
    signal: AbortSignal.timeout(30000),
  });

  assert.ok(response.ok, "RPC HTTP failure");

  const body = await response.json();

  assert.ok(
    !body.error && Object.hasOwn(body, "result"),
    "Public RPC read failed"
  );

  return body.result;
}

async function currentRoot(url, blockTag) {
  const raw = await rpc(url, "eth_call", [{
    to: pool,
    data: encodeFunctionData({
      abi: rootAbi,
      functionName: "currentRoot",
    }),
  }, blockTag]);

  return decodeFunctionResult({
    abi: rootAbi,
    functionName: "currentRoot",
    data: raw,
  });
}

async function verifyPublicAnchor() {
  let agreed = null;

  for (const url of providers) {
    const [
      chainId,
      receipt,
      rootAtWithdrawal,
      latestRoot,
    ] = await Promise.all([
      rpc(url, "eth_chainId"),
      rpc(url, "eth_getTransactionReceipt", [txHash]),
      currentRoot(url, toHex(withdrawalBlock)),
      currentRoot(url, "latest"),
    ]);

    assert.equal(BigInt(chainId), 11155111n);
    assert.ok(receipt);
    assert.equal(receipt.status, "0x1");

    assert.equal(
      BigInt(receipt.blockNumber),
      withdrawalBlock
    );

    assert.equal(rootAtWithdrawal, expectedRoot);

    assert.equal(
      latestRoot,
      expectedRoot,
      "Pool root changed: rebuild against current leaf history"
    );

    const matches = receipt.logs.filter(log =>
      isAddressEqual(log.address, pool) &&
      log.topics?.[0]?.toLowerCase() === leafTopic
    );

    assert.equal(
      matches.length,
      1,
      "Expected exactly one change-note insertion"
    );

    const event = decodeEventLog({
      abi: [leafAbi],
      data: matches[0].data,
      topics: matches[0].topics,
      strict: true,
    });

    assert.equal(
      event.args._index,
      1481n
    );

    assert.equal(
      event.args._leaf,
      expectedCommitment
    );

    assert.equal(
      event.args._root,
      expectedRoot
    );

    const anchor = {
      index: event.args._index.toString(),
      leaf: event.args._leaf.toString(),
      root: event.args._root.toString(),
      blockHash: receipt.blockHash.toLowerCase(),
      blockNumber: BigInt(receipt.blockNumber).toString(),
    };

    if (agreed !== null) {
      assert.deepEqual(
        anchor,
        agreed,
        "RPC providers disagree on insertion"
      );
    }

    agreed = anchor;

    console.log(
      "PASS: Change insertion and state root:",
      new URL(url).hostname
    );
  }

  return agreed;
}

async function main() {
  const cache = load(
    "r5-e5b9k35e-public-scan.json"
  );

  const previous = load(
    "r5-e5b9k35e-state-witness.json"
  );

  const recovery = load(
    "r5-e5b9k38b-change-recovery.json"
  );

  const journal = load(
    "r5-e5b9k37d-submission-journal.json"
  );

  assert.equal(journal.status, "confirmed");
  assert.equal(journal.transactionHash, txHash);

  assert.equal(
    recovery.changeCommitmentRecovered,
    true
  );

  assert.equal(
    BigInt(recovery.changeCommitment),
    expectedCommitment
  );

  assert.equal(cache.events.length, 1480);
  assert.equal(previous.stateLeafCount, 1480);

  // Validate all cached insertion indices before
  // trusting their order or reconstructing the tree.
  for (let i = 0; i < cache.events.length; i++) {
    assert.equal(
      BigInt(cache.events[i].index),
      BigInt(i + 1),
      "Cached LeafInserted history is not contiguous"
    );
  }

  const cachedFinal = cache.events.at(-1);

  assert.equal(
    BigInt(cachedFinal.root),
    BigInt(previous.stateRoot)
  );

  console.log(
    "PASS: 1,480 historical leaves validated"
  );

  const anchor = await verifyPublicAnchor();

  assert.equal(
    BigInt(anchor.index),
    BigInt(cache.events.length + 1)
  );

  const oldLeaves = cache.events.map(event =>
    BigInt(event.leaf)
  );

  // First reconstruct K35-E independently.
  const oldTree = await buildMerkleTree(oldLeaves);

  assert.equal(
    oldTree.root,
    BigInt(previous.stateRoot),
    "Historical tree root reconstruction failed"
  );

  console.log(
    "PASS: K35-E historical tree reconstructed"
  );

  // Append the actual mined change commitment.
  const leaves = [
    ...oldLeaves,
    BigInt(anchor.leaf),
  ];

  assert.equal(leaves.length, 1481);

  const tree = await buildMerkleTree(leaves);

  assert.equal(
    tree.root,
    expectedRoot,
    "Reconstructed root differs from Sepolia"
  );

  console.log(
    "PASS: Updated 1,481-leaf tree matches Sepolia"
  );

  const absolutePosition = 1480;

  assert.equal(
    tree.indexOf(expectedCommitment),
    absolutePosition
  );

  const rawProof =
    tree.generateProof(absolutePosition);

  assert.equal(
    rawProof.leaf,
    expectedCommitment
  );

  assert.equal(
    rawProof.root,
    expectedRoot
  );

  // Independently walk the LeanIMT path using
  // the tree's verification implementation.
  assert.equal(
    tree.verifyProof(rawProof),
    true,
    "LeanIMT inclusion verification failed"
  );

  console.log(
    "PASS: Raw LeanIMT inclusion proof verified"
  );

  // The circuit expects 32 padded siblings.
  // Its index is the COMPRESSED path index,
  // not the absolute position of leaf 1480.
  const witness = proofFromTree(
    tree,
    expectedCommitment
  );

  assert.equal(
    BigInt(witness.index),
    BigInt(rawProof.index)
  );

  assert.equal(
    BigInt(witness.root),
    expectedRoot
  );

  assert.equal(
    witness.siblings.length,
    32
  );

  assert.ok(
    rawProof.siblings.length <= 32
  );

  console.log(
    "PASS: Circuit-compatible LeanIMT witness"
  );

  console.log(
    "Absolute leaf position:",
    absolutePosition
  );

  console.log(
    "Compressed proof index:",
    witness.index
  );

  console.log(
    "Unpadded siblings:",
    rawProof.siblings.length
  );

  const evidence = {
    checkpoint: "R5-E5B9K39B-change-state-witness",
    chainId: 11155111,
    sourceWithdrawalTransactionHash: txHash,
    pool,
    withdrawalBlockNumber: withdrawalBlock.toString(),
    withdrawalBlockHash: anchor.blockHash,
    stateLeafCount: leaves.length,
    leafInsertedEventIndex: anchor.index,
    stateLeafPosition: absolutePosition,
    stateIndex: Number(witness.index),
    stateRoot: expectedRoot.toString(),
    stateSiblings: witness.siblings.map(
      sibling => BigInt(sibling).toString()
    ),
    stateTreeDepth: 32,
    rawProofSiblingCount: rawProof.siblings.length,
    changeCommitment:
      "0x" + expectedCommitment
        .toString(16).padStart(64, "0"),
    historicalRootVerified: true,
    latestRootVerified: true,
    twoProvidersAgreed: true,
    inclusionProofVerified: true,
    compressedPathVerified: true,
    privateCredentialsPersisted: false,
    signingAttempted: false,
    broadcast: false,
  };

  assert.ok(
    Number.isSafeInteger(evidence.stateIndex)
  );

  // State siblings and roots are public data.
  // No nullifier, secret, witness input or
  // hardware-derived credential is persisted.
  writeFileSync(
    output,
    JSON.stringify(evidence, null, 2),
    { mode: 0o600, flag: "wx" }
  );

  console.log(
    "PASS: Public-only K39-B witness saved"
  );

  console.log("Hardware accessed: NO");
  console.log("Groth16 proof generated: NO");
  console.log("Signing: NO");
  console.log("Broadcasting: NO");
}

await main();
