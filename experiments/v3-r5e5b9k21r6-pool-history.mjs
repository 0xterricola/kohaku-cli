import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  existsSync, readFileSync, writeFileSync,
  renameSync, chmodSync, mkdirSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  decodeEventLog,
  getAddress,
  toEventSelector,
  toHex,
} from "viem";

import { PrivacyPoolsV1_0xBow } from
  "@kohaku-eth/privacy-pools";

import {
  ENTRYPOINT_EVENTS_SIGNATURES,
  POOL_EVENTS_SIGNATURES,
} from "../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/events.abi.ts";

const ENTRY = getAddress(
  PrivacyPoolsV1_0xBow[11155111]
    .entrypoint.entrypointAddress
);

const REGISTER =
  ENTRYPOINT_EVENTS_SIGNATURES.PoolRegistered;

const DEPOSIT =
  POOL_EVENTS_SIGNATURES.PoolDeposited;

const REG_TOPIC = toEventSelector(REGISTER);
const DEP_TOPIC = toEventSelector(DEPOSIT);

const SCHEMA = "kohaku-key/r5-e5b9k21r6/pools-v1";

const WORK = join(
  homedir(),
  "Library/Application Support/KohakuKeyResearch/v3-r5e9i-parser-fix"
);

const PARTIAL = join(
  WORK, "r5-e5b9k21r6-pool-history.partial.json"
);

const FINAL = join(
  WORK, "r5-e5b9k21r6-pool-history.json"
);

const sleep = ms =>
  new Promise(resolve => setTimeout(resolve, ms));

function parseInteger(s) {
  if (
    typeof s !== "string" ||
    !/^(0x[0-9a-f]+|[0-9]+)$/i.test(s)
  ) {
    throw new Error("Invalid history integer");
  }
  return BigInt(s);
}

export function decodeAuthorizedDeposit(
  log, poolAddresses, from, to,
) {
  const authorized = new Set(
    poolAddresses.map(a => getAddress(a))
  );

  const address = getAddress(log.address);

  if (!authorized.has(address)) {
    throw new Error("Deposit from unregistered pool");
  }

  const block = parseInteger(log.blockNumber);

  if (
    block < from ||
    block > to ||
    log.removed === true ||
    log.topics?.[0]?.toLowerCase() !==
      DEP_TOPIC.toLowerCase()
  ) {
    throw new Error("Invalid pool deposit log");
  }

  const decoded = decodeEventLog({
    abi: [DEPOSIT],
    topics: log.topics,
    data: log.data,
    strict: true,
  });

  const value = decoded.args._precommitment;

  if (
    typeof value !== "bigint" ||
    value <= 0n
  ) {
    throw new Error("Invalid pool precommitment");
  }

  return value.toString();
}

const poolInputs = REGISTER.inputs.filter(
  input =>
    input.type === "address" &&
    /pool/i.test(input.name)
);

if (poolInputs.length !== 1) {
  throw new Error(
    "PoolRegistered ABI has ambiguous pool address"
  );
}

const poolField = poolInputs[0].name;

export function registeredPoolAddress(log) {
  const decoded = decodeEventLog({
    abi: [REGISTER],
    topics: log.topics,
    data: log.data,
    strict: true,
  });

  const value = decoded.args[poolField];

  if (typeof value !== "string") {
    throw new Error(
      "Pool registration address missing"
    );
  }

  return getAddress(value);
}

function snapshotState() {
  const bytes = readFileSync(
    "src/utils/ppv1-sepolia-state.json"
  );

  const json = JSON.parse(
    bytes.toString("utf8")
  );

  const entryInt = BigInt(ENTRY);

  const state = json[
    `privacy-pool-state-11155111-${entryInt}`
  ];

  assert.ok(state, "Bundled snapshot missing");

  const deposits = state.deposits?.depositsTuples;
  const pools = state.pools?.poolsTuples;

  assert.ok(
    Array.isArray(deposits) &&
    deposits.length > 0,
    "Snapshot deposits missing"
  );

  assert.ok(
    Array.isArray(pools) &&
    pools.length > 0,
    "Snapshot pools missing"
  );

  const poolAddresses = pools.map(tuple => {
    assert.ok(Array.isArray(tuple));

    const n = BigInt(tuple[0]);

    assert.ok(
      n > 0n && n < (1n << 160n),
      "Invalid bundled pool address"
    );

    return getAddress(toHex(n, { size: 20 }));
  });

  return {
    sha: createHash("sha256")
      .update(bytes).digest("hex"),
    head: BigInt(state.sync.lastSyncedBlock),
    keys: deposits.map(tuple =>
      BigInt(tuple[0]).toString()
    ),
    pools: [...new Set(poolAddresses)].sort(),
  };
}

const METHODS = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getLogs",
]);

async function rpc(url, method, params = []) {
  if (!METHODS.has(method)) {
    throw new Error("Prohibited RPC method");
  }

  const endpoint = new URL(url);

  if (endpoint.protocol !== "https:") {
    throw new Error("HTTPS RPC required");
  }

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

  const json = await response.json();

  if (!response.ok || json.error) {
    throw new Error(
      `HTTP ${response.status}, RPC ` +
      `${json.error?.code ?? "none"}: ` +
      String(json.error?.message ?? "Rejected")
        .slice(0, 100)
    );
  }

  if (json.result === undefined) {
    throw new Error("RPC result absent");
  }

  return json.result;
}

async function providers() {
  const candidates = [
    process.env.SEPOLIA_RPC_URL,
    "https://sepolia.gateway.tenderly.co",
  ].filter(Boolean);

  const result = [];

  for (const [i, url] of
    [...new Set(candidates)].entries()) {
    try {
      const chain = Number(
        BigInt(await rpc(url, "eth_chainId"))
      );

      if (chain !== 11155111) {
        throw new Error("Wrong chain");
      }

      const head = BigInt(
        await rpc(url, "eth_blockNumber")
      );

      result.push({
        name: `RPC-${i + 1}`,
        url,
        head,
      });

      console.log(
        `PASS: RPC-${i + 1}, block ${head}`
      );
    } catch {
      console.log(
        `UNAVAILABLE: RPC-${i + 1}`
      );
    }
  }

  if (!result.length) {
    throw new Error("No Sepolia RPC");
  }

  return result;
}

async function logsForRange(
  clients, from, to, topic, address,
) {
  const filter = {
    fromBlock: toHex(from),
    toBlock: toHex(to),
    topics: [topic],
    ...(address ? { address } : {}),
  };

  const failures = [];

  for (const client of clients) {
    if (client.head < to) continue;

    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt) {
        await sleep(400 * attempt);
      }

      try {
        const logs = await rpc(
          client.url,
          "eth_getLogs",
          [filter],
        );

        if (!Array.isArray(logs)) {
          throw new Error("Non-array log response");
        }

        return logs;
      } catch (error) {
        failures.push(
          `${client.name}: ${String(error.message)
            .replaceAll(client.url, "[RPC]")
            .slice(0, 90)}`
        );
      }
    }
  }

  if (from === to) {
    throw new Error(
      `Incomplete public history at ${from}; ` +
      failures.slice(-2).join("; ")
    );
  }

  const mid = (from + to) / 2n;

  return [
    ...await logsForRange(
      clients, from, mid, topic, address
    ),
    ...await logsForRange(
      clients, mid + 1n, to, topic, address
    ),
  ];
}

async function rangeScan(
  clients, first, last, size,
  topic, address, receive,
) {
  for (
    let from = first;
    from <= last;
    from += size
  ) {
    const to = from + size - 1n < last
      ? from + size - 1n
      : last;

    const logs = await logsForRange(
      clients, from, to, topic, address,
    );

    receive(logs, from, to);

    if (to < last) {
      await sleep(150);
    }
  }
}

function validateArchive(a, source, poolSet) {
  assert.equal(a.schema, SCHEMA);
  assert.equal(a.chainId, 11155111);
  assert.equal(a.entrypoint, ENTRY);
  assert.equal(a.snapshotSha, source.sha);
  assert.equal(a.snapshotHead, source.head.toString());
  assert.deepEqual(a.snapshotKeys, source.keys);
  assert.deepEqual(a.poolAddresses, poolSet);

  let cursor = source.head + 1n;
  let total = 0;

  for (const r of a.ranges) {
    assert.equal(BigInt(r.from), cursor);
    assert.ok(BigInt(r.to) >= cursor);
    cursor = BigInt(r.to) + 1n;
    total += r.count;
  }

  assert.equal(
    BigInt(a.checkedThrough),
    cursor - 1n,
  );

  assert.equal(total, a.recentKeys.length);

  assert.ok(
    BigInt(a.checkedThrough) <=
    BigInt(a.targetHead),
  );
}

function save(path, object) {
  const temp = `${path}.writing`;

  writeFileSync(temp, JSON.stringify(object), {
    mode: 0o600,
  });

  chmodSync(temp, 0o600);
  renameSync(temp, path);
}

async function main() {
  console.log(
    "=== R5-E5B9K21R6: Pool-scoped Sepolia history ==="
  );

  const source = snapshotState();
  const clients = await providers();

  const target = clients.reduce(
    (min, c) => c.head < min ? c.head : min,
    clients[0].head,
  );

  assert.ok(target >= source.head);

  const newPools = new Set();

  console.log(
    "=== Discover post-snapshot pool registrations ==="
  );

  await rangeScan(
    clients,
    source.head + 1n,
    target,
    1000n,
    REG_TOPIC,
    ENTRY,
    (logs, from, to) => {
      for (const log of logs) {
        const block = parseInteger(log.blockNumber);

        assert.ok(block >= from && block <= to);
        assert.equal(
          getAddress(log.address),
          ENTRY,
        );

        newPools.add(registeredPoolAddress(log));
      }
    },
  );

  const poolSet = [
    ...new Set([
      ...source.pools,
      ...newPools,
    ]),
  ].sort();

  assert.ok(poolSet.length > 0);

  console.log(JSON.stringify({
    snapshotPools: source.pools.length,
    newRegisteredPools: newPools.size,
    totalAuthorizedPools: poolSet.length,
    registeredEventAbi: REGISTER.name,
  }, null, 2));

  mkdirSync(WORK, { recursive: true });

  let archive;

  if (existsSync(PARTIAL)) {
    archive = JSON.parse(
      readFileSync(PARTIAL, "utf8")
    );

    validateArchive(archive, source, poolSet);

    assert.ok(
      BigInt(archive.checkedThrough) <= target
    );

    console.log(
      `PASS: Resuming pool-scoped scan at ${archive.checkedThrough}`
    );
  } else {
    archive = {
      schema: SCHEMA,
      chainId: 11155111,
      entrypoint: ENTRY,
      snapshotSha: source.sha,
      snapshotHead: source.head.toString(),
      snapshotKeys: source.keys,
      poolAddresses: poolSet,
      targetHead: target.toString(),
      checkedThrough: source.head.toString(),
      recentKeys: [],
      ranges: [],
    };
  }

  archive.targetHead = target.toString();

  console.log(
    "=== Scan only authorized Privacy Pools ==="
  );

  let chunks = 0;

  while (BigInt(archive.checkedThrough) < target) {
    const from =
      BigInt(archive.checkedThrough) + 1n;

    const to = from + 499n < target
      ? from + 499n
      : target;

    const logs = await logsForRange(
      clients,
      from,
      to,
      DEP_TOPIC,
      poolSet,
    );

    const keys = logs.map(log =>
      decodeAuthorizedDeposit(
        log, poolSet, from, to
      )
    );

    archive.recentKeys.push(...keys);

    archive.ranges.push({
      from: from.toString(),
      to: to.toString(),
      count: keys.length,
    });

    archive.checkedThrough = to.toString();

    validateArchive(archive, source, poolSet);
    save(PARTIAL, archive);

    chunks++;

    if (chunks % 20 === 0 || to === target) {
      console.log(
        `SCAN: ${to}/${target}, ` +
        `${archive.recentKeys.length} pool deposits`
      );
    }

    if (to < target) {
      await sleep(150);
    }
  }

  validateArchive(archive, source, poolSet);

  assert.equal(
    archive.checkedThrough,
    archive.targetHead,
  );

  save(FINAL, archive);

  console.log(JSON.stringify({
    checkpoint: "R5-E5B9K21R6",
    snapshotHead: archive.snapshotHead,
    snapshotDeposits: archive.snapshotKeys.length,
    authorizedPools: poolSet.length,
    newRegisteredPools: newPools.size,
    postSnapshotDeposits: archive.recentKeys.length,
    checkedThrough: archive.checkedThrough,
    contiguousCoverage: true,
    olderSnapshotIndependentlyAudited: false,
    hardwareCredentialCompared: false,
    signed: false,
    broadcast: false,
  }, null, 2));

  console.log(
    "PASS: R5-E5B9K21R6 pool-scoped history"
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) ===
    fileURLToPath(import.meta.url)
) {
  try {
    await main();
  } catch (error) {
    const configured = process.env.SEPOLIA_RPC_URL;

    const msg = String(
      error instanceof Error
        ? error.message
        : "History scan failed"
    );

    console.error(
      "FAIL:",
      (configured
        ? msg.replaceAll(configured, "[RPC]")
        : msg
      ).slice(0, 320)
    );

    process.exitCode = 1;
  }
}
