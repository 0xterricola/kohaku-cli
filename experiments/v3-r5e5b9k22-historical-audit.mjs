import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  readFileSync,
  writeFileSync,
  renameSync,
  chmodSync,
  existsSync,
  unlinkSync,
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

const schema =
  "kohaku-key/v3-k22/historical-audit-v1";

const work = join(
  homedir(),
  "Library/Application Support/KohakuKeyResearch/v3-r5e9i-parser-fix"
);

const partial = join(
  work, "r5-e5b9k22-audit.partial.json"
);

const finished = join(
  work, "r5-e5b9k22-audit.json"
);

const windowSize = 8192n;

const registration =
  ENTRYPOINT_EVENTS_SIGNATURES.PoolRegistered;

const deposit =
  POOL_EVENTS_SIGNATURES.PoolDeposited;

const regTopic = toEventSelector(registration);
const depTopic = toEventSelector(deposit);

const poolFields = registration.inputs.filter(
  field =>
    field.type === "address" &&
    /pool/i.test(field.name)
);

assert.equal(poolFields.length, 1);

const sleep = ms =>
  new Promise(r => setTimeout(r, ms));

const addressOf = value =>
  getAddress(toHex(BigInt(value), { size: 20 }));

export function assertSamePrecommitments(
  expected, actual
) {
  if (!Array.isArray(expected) ||
      !Array.isArray(actual)) {
    throw new Error("Missing history");
  }

  const normalize = values =>
    values.map(x => BigInt(x).toString())
      .sort((a, b) =>
        BigInt(a) < BigInt(b) ? -1 :
        BigInt(a) > BigInt(b) ? 1 : 0
      );

  if (
    expected.length !== actual.length ||
    JSON.stringify(normalize(expected)) !==
    JSON.stringify(normalize(actual))
  ) {
    throw new Error(
      "On-chain history differs from bundled snapshot"
    );
  }

  return true;
}

export function validateAuditRanges(
  ranges, start, through, expectedCount
) {
  assert.ok(Array.isArray(ranges));

  let cursor = start;
  let total = 0;

  for (const r of ranges) {
    const from = BigInt(r.from);
    const to = BigInt(r.to);

    if (
      from !== cursor ||
      to < from ||
      to - from + 1n > windowSize ||
      !Number.isSafeInteger(r.count) ||
      r.count < 0
    ) {
      throw new Error(
        "Historical audit coverage gap"
      );
    }

    cursor = to + 1n;
    total += r.count;
  }

  if (
    cursor !== through + 1n ||
    total !== expectedCount
  ) {
    throw new Error(
      "Historical audit checkpoint mismatch"
    );
  }

  return true;
}

function snapshot() {
  const bytes = readFileSync(
    "src/utils/ppv1-sepolia-state.json"
  );

  const data = JSON.parse(bytes.toString("utf8"));
  const config = PrivacyPoolsV1_0xBow[11155111];

  assert.ok(config?.entrypoint);

  const entrypoint = addressOf(
    config.entrypoint.entrypointAddress
  );

  const deploymentBlock = BigInt(
    config.entrypoint.deploymentBlock
  );

  const state = data[
    `privacy-pool-state-11155111-${BigInt(entrypoint)}`
  ];

  assert.ok(state);

  const head = BigInt(state.sync.lastSyncedBlock);
  const deposits = state.deposits?.depositsTuples;
  const pools = state.pools?.poolsTuples;

  assert.ok(
    deploymentBlock > 0n &&
    deploymentBlock <= head &&
    Array.isArray(deposits) &&
    deposits.length === 1153 &&
    Array.isArray(pools) &&
    pools.length > 0,
    "Unexpected bundled state"
  );

  return {
    sha: createHash("sha256")
      .update(bytes).digest("hex"),
    entrypoint,
    deploymentBlock,
    head,
    keys: deposits.map(
      row => BigInt(row[0]).toString()
    ),
    pools: [...new Set(
      pools.map(row => addressOf(row[0]))
    )].sort(),
  };
}

function validateArchive(a, source) {
  assert.equal(a.schema, schema);
  assert.equal(a.snapshotSha, source.sha);
  assert.equal(a.entrypoint, source.entrypoint);

  assert.equal(
    a.deploymentBlock,
    source.deploymentBlock.toString()
  );

  assert.equal(
    a.snapshotHead,
    source.head.toString()
  );

  assert.ok(
    Array.isArray(a.registrationEvents) &&
    Array.isArray(a.depositKeys)
  );

  validateAuditRanges(
    a.registrationRanges,
    source.deploymentBlock,
    BigInt(a.registrationThrough),
    a.registrationEvents.length
  );

  validateAuditRanges(
    a.depositRanges,
    source.deploymentBlock,
    BigInt(a.depositThrough),
    a.depositKeys.length
  );

  assert.ok(
    BigInt(a.registrationThrough) <= source.head &&
    BigInt(a.depositThrough) <= source.head
  );
}

function save(value) {
  const writing = partial + ".writing";

  writeFileSync(
    writing,
    JSON.stringify(value),
    { mode: 0o600 }
  );

  chmodSync(writing, 0o600);
  renameSync(writing, partial);
}

// Only read-only JSON-RPC operations.
const allowed = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getLogs",
]);

async function rpc(url, method, params = []) {
  if (!allowed.has(method)) {
    throw new Error("RPC method prohibited");
  }

  if (new URL(url).protocol !== "https:") {
    throw new Error("Remote RPC must use HTTPS");
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

  if (!response.ok) {
    throw new Error(
      `RPC HTTP ${response.status}`
    );
  }

  const body = await response.json();

  if (body.error) {
    throw new Error(
      `RPC error ${body.error.code ?? "unknown"}`
    );
  }

  if (body.result === undefined) {
    throw new Error("Missing RPC result");
  }

  return body.result;
}

async function connect() {
  const urls = [
    process.env.SEPOLIA_RPC_URL,
    "https://sepolia.gateway.tenderly.co",
  ].filter(Boolean);

  const result = [];

  for (const [index, url] of
    [...new Set(urls)].entries()) {
    try {
      const id = Number(
        BigInt(await rpc(url, "eth_chainId"))
      );

      assert.equal(id, 11155111);

      const head = BigInt(
        await rpc(url, "eth_blockNumber")
      );

      result.push({ url, head });

      console.log(
        `PASS: RPC-${index + 1} head ${head}`
      );
    } catch {
      console.log(
        `UNAVAILABLE: RPC-${index + 1}`
      );
    }
  }

  if (!result.length) {
    throw new Error("No Sepolia RPC available");
  }

  return result;
}

async function getLogs(
  clients, from, to, topic, addresses
) {
  const allowedAddresses = new Set(
    (Array.isArray(addresses)
      ? addresses
      : [addresses]
    ).map(a => getAddress(a).toLowerCase())
  );

  const filter = {
    fromBlock: toHex(from),
    toBlock: toHex(to),
    topics: [topic],
    address: addresses,
  };

  for (const client of clients) {
    if (client.head < to) continue;

    for (const delay of [0, 500, 1500]) {
      if (delay) await sleep(delay);

      try {
        const logs = await rpc(
          client.url,
          "eth_getLogs",
          [filter]
        );

        if (!Array.isArray(logs)) {
          throw new Error("Malformed logs");
        }

        for (const log of logs) {
          if (
            log.removed === true ||
            BigInt(log.blockNumber) < from ||
            BigInt(log.blockNumber) > to ||
            !allowedAddresses.has(
              getAddress(log.address).toLowerCase()
            ) ||
            log.topics?.[0]?.toLowerCase() !==
              topic.toLowerCase()
          ) {
            throw new Error("Unexpected event");
          }
        }

        return logs;
      } catch {
        // Try the next attempt or provider.
      }
    }
  }

  // A failed range is NEVER treated as empty.
  if (from === to) {
    throw new Error(
      `Historical RPC coverage unavailable at block ${from}`
    );
  }

  const mid = (from + to) / 2n;

  return [
    ...await getLogs(
      clients, from, mid, topic, addresses
    ),
    ...await getLogs(
      clients, mid + 1n, to, topic, addresses
    ),
  ];
}

function decodePool(log) {
  const result = decodeEventLog({
    abi: [registration],
    topics: log.topics,
    data: log.data,
    strict: true,
  });

  return getAddress(
    result.args[poolFields[0].name]
  );
}

function decodeDeposit(log) {
  const result = decodeEventLog({
    abi: [deposit],
    topics: log.topics,
    data: log.data,
    strict: true,
  });

  const value = result.args._precommitment;

  if (
    typeof value !== "bigint" ||
    value <= 0n
  ) {
    throw new Error("Invalid deposit event");
  }

  return value.toString();
}

async function scanPhase(
  a, source, clients, fields
) {
  let chunks = 0;

  while (BigInt(a[fields.through]) < source.head) {
    const from = BigInt(a[fields.through]) + 1n;

    const to =
      from + windowSize - 1n < source.head
        ? from + windowSize - 1n
        : source.head;

    const logs = await getLogs(
      clients,
      from,
      to,
      fields.topic,
      fields.addresses
    );

    const values = logs.map(fields.decode);

    a[fields.events].push(...values);
    a[fields.ranges].push({
      from: from.toString(),
      to: to.toString(),
      count: values.length,
    });

    a[fields.through] = to.toString();

    validateArchive(a, source);
    save(a);

    chunks++;

    if (
      chunks % 10 === 0 ||
      to === source.head
    ) {
      console.log(
        `${fields.name}: ${to}/${source.head} — ` +
        `${a[fields.events].length} events`
      );
    }

    if (to < source.head) await sleep(100);
  }
}

async function main() {
  console.log(
    "=== K22: Resumable historical audit ==="
  );

  const source = snapshot();
  const clients = await connect();

  assert.ok(
    clients.some(c => c.head >= source.head),
    "RPC behind bundled snapshot"
  );

  let a;

  if (existsSync(partial)) {
    a = JSON.parse(
      readFileSync(partial, "utf8")
    );

    validateArchive(a, source);

    console.log(
      `PASS: Registry resume at ${a.registrationThrough}`
    );

    console.log(
      `PASS: Deposit resume at ${a.depositThrough}`
    );
  } else {
    a = {
      schema,
      snapshotSha: source.sha,
      entrypoint: source.entrypoint,
      deploymentBlock:
        source.deploymentBlock.toString(),
      snapshotHead: source.head.toString(),
      registrationThrough:
        (source.deploymentBlock - 1n).toString(),
      depositThrough:
        (source.deploymentBlock - 1n).toString(),
      registrationRanges: [],
      depositRanges: [],
      registrationEvents: [],
      depositKeys: [],
    };
  }

  console.log("=== Pool registrations ===");

  await scanPhase(a, source, clients, {
    name: "REGISTRY",
    through: "registrationThrough",
    ranges: "registrationRanges",
    events: "registrationEvents",
    topic: regTopic,
    addresses: source.entrypoint,
    decode: decodePool,
  });

  const pools = [
    ...new Set(a.registrationEvents)
  ].sort();

  const registered = new Set(
    pools.map(p => p.toLowerCase())
  );

  for (const pool of source.pools) {
    assert.ok(
      registered.has(pool.toLowerCase()),
      "Bundled pool not registered on chain"
    );
  }

  console.log(
    `PASS: ${pools.length} on-chain registered pools`
  );

  console.log("=== Historical deposits ===");

  await scanPhase(a, source, clients, {
    name: "DEPOSITS",
    through: "depositThrough",
    ranges: "depositRanges",
    events: "depositKeys",
    topic: depTopic,
    addresses: pools,
    decode: decodeDeposit,
  });

  validateArchive(a, source);

  assert.equal(
    a.registrationThrough,
    source.head.toString()
  );

  assert.equal(
    a.depositThrough,
    source.head.toString()
  );

  assertSamePrecommitments(
    source.keys,
    a.depositKeys
  );

  writeFileSync(
    finished,
    JSON.stringify(a),
    { mode: 0o600 }
  );

  chmodSync(finished, 0o600);
  unlinkSync(partial);

  console.log(JSON.stringify({
    checkpoint: "R5-E5B9K22",
    deploymentBlock:
      source.deploymentBlock.toString(),
    snapshotHead: source.head.toString(),
    verifiedPools: pools.length,
    bundledDeposits: source.keys.length,
    independentlyFetchedDeposits:
      a.depositKeys.length,
    snapshotMatchesChain: true,
    hardwareAccess: false,
    signing: false,
    broadcasting: false,
  }, null, 2));

  console.log(
    "PASS: K22 independent historical audit"
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) ===
    fileURLToPath(import.meta.url)
) {
  main().catch(error => {
    console.error(
      "FAIL:",
      String(error.message).slice(0, 200)
    );
    process.exitCode = 1;
  });
}
