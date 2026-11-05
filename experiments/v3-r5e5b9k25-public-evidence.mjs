import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { getAddress, toHex } from "viem";
import { PrivacyPoolsV1_0xBow } from
  "@kohaku-eth/privacy-pools";

const work = join(
  homedir(),
  "Library/Application Support/KohakuKeyResearch/v3-r5e9i-parser-fix"
);

const load = filename => JSON.parse(
  readFileSync(join(work, filename), "utf8")
);

const normalizeKeys = values =>
  values.map(value => BigInt(value).toString())
    .sort((a, b) =>
      BigInt(a) < BigInt(b) ? -1 :
      BigInt(a) > BigInt(b) ? 1 : 0
    );

const normalizeAddresses = values =>
  [...new Set(values.map(value =>
    getAddress(value).toLowerCase()
  ))].sort();

export function verifyRanges(
  ranges, start, finish, count, maximum
) {
  assert.ok(Array.isArray(ranges));

  let cursor = start;
  let found = 0;

  for (const range of ranges) {
    const from = BigInt(range.from);
    const to = BigInt(range.to);

    assert.ok(
      from === cursor &&
      to >= from &&
      to - from + 1n <= maximum,
      "Noncontiguous history"
    );

    assert.ok(
      Number.isSafeInteger(range.count) &&
      range.count >= 0,
      "Invalid event count"
    );

    cursor = to + 1n;
    found += range.count;
  }

  assert.equal(cursor - 1n, finish);
  assert.equal(found, count);

  return true;
}

export function assertUnused(
  candidate, publicKeys
) {
  assert.ok(
    typeof candidate === "bigint" &&
    candidate > 0n,
    "Invalid local credential"
  );

  const candidateKey = candidate.toString();

  if (publicKeys.some(value =>
    BigInt(value).toString() === candidateKey
  )) {
    throw new Error(
      "Credential reuse detected; deposit prohibited"
    );
  }

  return true;
}

export function verifyK25PublicEvidence() {
  const bytes = readFileSync(
    "src/utils/ppv1-sepolia-state.json"
  );

  const json = JSON.parse(bytes.toString("utf8"));

  const hash = createHash("sha256")
    .update(bytes).digest("hex");

  const config = PrivacyPoolsV1_0xBow[11155111];

  assert.ok(
    config?.entrypoint?.entrypointAddress &&
    config.entrypoint.deploymentBlock,
    "Deployment configuration missing"
  );

  const entrypointInt = BigInt(
    config.entrypoint.entrypointAddress
  );

  const entrypoint = getAddress(
    toHex(entrypointInt, { size: 20 })
  );

  const state = json[
    `privacy-pool-state-11155111-${entrypointInt}`
  ];

  assert.ok(state, "Bundled snapshot missing");

  const snapshotHead =
    BigInt(state.sync.lastSyncedBlock);

  const deploymentBlock =
    BigInt(config.entrypoint.deploymentBlock);

  const snapshotKeys =
    state.deposits.depositsTuples.map(row =>
      BigInt(row[0]).toString()
    );

  const snapshotPools =
    state.pools.poolsTuples.map(row =>
      getAddress(
        toHex(BigInt(row[0]), { size: 20 })
      )
    );

  const audit = load(
    "r5-e5b9k22-audit.json"
  );

  const cached = load(
    "r5-e5b9k21r6-pool-history.json"
  );

  const fresh = load(
    "r5-e5b9k24-public-head.json"
  );

  // K22: independently reconstructed historical logs.
  assert.equal(
    audit.schema,
    "kohaku-key/v3-k22/historical-audit-v1"
  );

  assert.equal(audit.snapshotSha, hash);
  assert.equal(
    audit.entrypoint.toLowerCase(),
    entrypoint.toLowerCase()
  );

  assert.equal(
    BigInt(audit.deploymentBlock),
    deploymentBlock
  );

  assert.equal(
    BigInt(audit.snapshotHead),
    snapshotHead
  );

  assert.equal(
    BigInt(audit.registrationThrough),
    snapshotHead
  );

  assert.equal(
    BigInt(audit.depositThrough),
    snapshotHead
  );

  verifyRanges(
    audit.registrationRanges,
    deploymentBlock,
    snapshotHead,
    audit.registrationEvents.length,
    8192n
  );

  verifyRanges(
    audit.depositRanges,
    deploymentBlock,
    snapshotHead,
    audit.depositKeys.length,
    8192n
  );

  assert.deepEqual(
    normalizeKeys(audit.depositKeys),
    normalizeKeys(snapshotKeys),
    "Historical snapshot does not match chain"
  );

  assert.deepEqual(
    normalizeAddresses(audit.registrationEvents),
    normalizeAddresses(snapshotPools),
    "Historical pool registry mismatch"
  );

  // K21R6: contiguous post-snapshot pool deposits.
  assert.equal(
    cached.schema,
    "kohaku-key/r5-e5b9k21r6/pools-v1"
  );

  assert.equal(cached.snapshotSha, hash);
  assert.equal(cached.chainId, 11155111);

  assert.equal(
    cached.entrypoint.toLowerCase(),
    entrypoint.toLowerCase()
  );

  assert.equal(
    BigInt(cached.snapshotHead),
    snapshotHead
  );

  assert.deepEqual(
    cached.snapshotKeys,
    snapshotKeys
  );

  assert.deepEqual(
    normalizeAddresses(cached.poolAddresses),
    normalizeAddresses(snapshotPools)
  );

  assert.equal(
    cached.targetHead,
    cached.checkedThrough
  );

  verifyRanges(
    cached.ranges,
    snapshotHead + 1n,
    BigInt(cached.checkedThrough),
    cached.recentKeys.length,
    500n
  );

  // K24: public-only extension beyond K21R6.
  assert.equal(
    fresh.checkpoint,
    "R5-E5B9K24-public"
  );

  assert.equal(fresh.chainId, 11155111);
  assert.equal(fresh.snapshotSha, hash);

  assert.equal(
    fresh.previousHead,
    cached.checkedThrough
  );

  assert.ok(
    BigInt(fresh.checkedThrough) >=
    BigInt(fresh.previousHead)
  );

  assert.deepEqual(
    normalizeAddresses(fresh.poolAddresses),
    normalizeAddresses(snapshotPools)
  );

  assert.equal(
    fresh.newPoolRegistrations,
    0
  );

  assert.ok(
    Array.isArray(fresh.publicPrecommitments)
  );

  assert.equal(
    fresh.newDeposits,
    fresh.publicPrecommitments.length
  );

  assert.equal(
    fresh.totalKnownDeposits,
    snapshotKeys.length +
      cached.recentKeys.length +
      fresh.publicPrecommitments.length
  );

  assert.equal(
    fresh.historicalSnapshotAudited,
    true
  );

  assert.equal(
    fresh.sender.toLowerCase(),
    "0x155a8332a3504d5f532742ae6531cd0e28035972"
  );

  assert.ok(
    Number.isSafeInteger(fresh.senderNonce) &&
    fresh.senderNonce >= 0
  );

  assert.ok(
    Number(fresh.senderBalanceETH) >= 0.002,
    "Sender cannot cover deposit value"
  );

  const allPublicKeys = [
    ...snapshotKeys,
    ...cached.recentKeys,
    ...fresh.publicPrecommitments,
  ];

  for (const value of allPublicKeys) {
    assert.ok(BigInt(value) > 0n);
  }

  return {
    checkedThrough: fresh.checkedThrough,
    depositCount: allPublicKeys.length,
    registeredPools: snapshotPools.length,
    sender: getAddress(fresh.sender),
    observedNonce: fresh.senderNonce,
    observedBalanceETH: fresh.senderBalanceETH,
    allPublicKeys,
  };
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) ===
    fileURLToPath(import.meta.url)
) {
  const evidence = verifyK25PublicEvidence();

  console.log(JSON.stringify({
    checkpoint: "K25-public-preflight",
    checkedThrough: evidence.checkedThrough,
    auditedDeposits: evidence.depositCount,
    registeredPools: evidence.registeredPools,
    sender: evidence.sender,
    nonceAtK24Head: evidence.observedNonce,
    balanceETHAtK24Head:
      evidence.observedBalanceETH,
    credentialsAccessed: false,
    RPCRequests: 0,
  }, null, 2));

  console.log(
    "PASS: K25 public evidence verified before PIN"
  );
}
