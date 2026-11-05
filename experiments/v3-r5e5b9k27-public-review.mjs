import assert from "node:assert/strict";
import {
  readFileSync,
  writeFileSync,
  chmodSync,
  renameSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  decodeEventLog,
  encodeFunctionData,
  getAddress,
  keccak256,
  parseAbi,
  toEventSelector,
  toHex,
} from "viem";

import {
  ENTRYPOINT_EVENTS_SIGNATURES,
  POOL_EVENTS_SIGNATURES,
} from "../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/events.abi.ts";

import {
  verifyK25PublicEvidence,
  verifyRanges,
  assertUnused,
} from "./v3-r5e5b9k25-public-evidence.mjs";

import {
  calculateFeeBudget,
  validateLogs,
} from "./v3-r5e5b9k26-live-readiness.mjs";

export { assertUnused };

const work = join(
  homedir(),
  "Library/Application Support/KohakuKeyResearch/v3-r5e9i-parser-fix"
);

const filename = join(
  work, "r5-e5b9k27-public-review.json"
);

const entrypoint = getAddress(
  "0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB"
);

const sender = getAddress(
  "0x155a8332A3504D5F532742Ae6531cd0e28035972"
);

const amount = 2000000000000000n;

const regAbi =
  ENTRYPOINT_EVENTS_SIGNATURES.PoolRegistered;

const depAbi =
  POOL_EVENTS_SIGNATURES.PoolDeposited;

const regTopic = toEventSelector(regAbi);
const depTopic = toEventSelector(depAbi);

const poolFields = regAbi.inputs.filter(
  x => x.type === "address" && /pool/i.test(x.name)
);

assert.equal(poolFields.length, 1);

const load = name => JSON.parse(
  readFileSync(join(work, name), "utf8")
);

const sleep = ms =>
  new Promise(resolve => setTimeout(resolve, ms));

const allowed = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getLogs",
  "eth_getBlockByNumber",
  "eth_getCode",
  "eth_getBalance",
  "eth_getTransactionCount",
  "eth_estimateGas",
  "eth_maxPriorityFeePerGas",
]);

export function validateExtension(previous, current) {
  assert.equal(current.checkpoint, "R5-E5B9K27-public");
  assert.equal(current.chainId, 11155111);
  assert.equal(
    current.previousHead,
    previous.checkedThrough
  );

  const start = BigInt(current.previousHead) + 1n;
  const finish = BigInt(current.checkedThrough);

  assert.ok(finish >= start - 1n);

  assert.equal(current.newRegistrations, 0);
  assert.ok(Array.isArray(current.newPrecommitments));

  assert.equal(
    current.newDeposits,
    current.newPrecommitments.length
  );

  verifyRanges(
    current.registrationRanges,
    start,
    finish,
    0,
    1000n
  );

  verifyRanges(
    current.depositRanges,
    start,
    finish,
    current.newDeposits,
    1000n
  );

  assert.equal(
    current.totalPublicDeposits,
    previous.totalPublicDeposits +
      current.newDeposits
  );

  assert.equal(
    current.entrypoint.toLowerCase(),
    previous.entrypoint.toLowerCase()
  );

  assert.equal(
    current.entrypointCodeHash,
    previous.entrypointCodeHash
  );

  assert.equal(
    current.sender.toLowerCase(),
    previous.sender.toLowerCase()
  );

  assert.equal(
    current.pendingNonce,
    previous.pendingNonce
  );

  assert.equal(
    current.depositValueWei,
    previous.depositValueWei
  );

  assert.ok(
    /^0x[0-9a-f]{64}$/i.test(current.blockHash)
  );

  for (const value of current.newPrecommitments) {
    assert.ok(BigInt(value) > 0n);
  }

  const balance = BigInt(current.balanceWei);
  const gas = BigInt(current.suggestedGasLimit);
  const maxFee = BigInt(
    current.suggestedMaxFeePerGas
  );

  const priority = BigInt(
    current.suggestedPriorityFeePerGas
  );

  assert.ok(gas > 0n);
  assert.ok(maxFee >= priority);

  assert.ok(
    balance >= amount + gas * maxFee,
    "Insufficient funds for review budget"
  );

  assert.equal(current.realCalldataSent, false);
  assert.equal(current.signed, false);
  assert.equal(current.broadcast, false);

  return true;
}

/**
 * Local-only evidence loader. Never accepts a
 * hardware precommitment as an RPC argument.
 */
export function verifyK27PublicEvidence() {
  const base = verifyK25PublicEvidence();

  const k26 = load(
    "r5-e5b9k26-live-readiness.json"
  );

  const k27 = load(
    "r5-e5b9k27-public-review.json"
  );

  assert.equal(k26.checkpoint, "R5-E5B9K26");

  assert.equal(
    k26.previousHead,
    base.checkedThrough
  );

  assert.equal(
    k26.totalPublicDeposits,
    base.depositCount + k26.newDeposits
  );

  assert.equal(k26.newRegistrations, 0);

  assert.ok(Array.isArray(k26.newPrecommitments));
  assert.equal(
    k26.newPrecommitments.length,
    k26.newDeposits
  );

  verifyRanges(
    k26.registrationRanges,
    BigInt(k26.previousHead) + 1n,
    BigInt(k26.checkedThrough),
    0,
    1000n
  );

  verifyRanges(
    k26.depositRanges,
    BigInt(k26.previousHead) + 1n,
    BigInt(k26.checkedThrough),
    k26.newDeposits,
    1000n
  );

  validateExtension(k26, k27);

  assert.equal(k27.sender.toLowerCase(), sender.toLowerCase());
  assert.equal(
    k27.entrypoint.toLowerCase(),
    entrypoint.toLowerCase()
  );

  assert.equal(
    k27.knownPools,
    base.registeredPools
  );

  return {
    checkedThrough: k27.checkedThrough,
    depositCount: k27.totalPublicDeposits,
    sender,
    observedNonce: Number(BigInt(k27.pendingNonce)),
    observedBalanceETH:
      Number(BigInt(k27.balanceWei)) / 1e18,
    suggestedGasLimit: k27.suggestedGasLimit,
    suggestedMaxFeePerGas:
      k27.suggestedMaxFeePerGas,
    suggestedPriorityFeePerGas:
      k27.suggestedPriorityFeePerGas,
    allPublicKeys: [
      ...base.allPublicKeys,
      ...k26.newPrecommitments,
      ...k27.newPrecommitments,
    ],
  };
}

async function rpc(url, method, params = []) {
  assert.ok(allowed.has(method));

  const endpoint = new URL(url);
  assert.equal(endpoint.protocol, "https:");

  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    }),
    signal: AbortSignal.timeout(20000),
  });

  if (!response.ok) {
    throw new Error(`RPC HTTP ${response.status}`);
  }

  const body = await response.json();

  if (body.error || body.result === undefined) {
    throw new Error("Public RPC request failed");
  }

  return body.result;
}

async function connect() {
  const candidates = [...new Set([
    process.env.SEPOLIA_RPC_URL,
    "https://sepolia.gateway.tenderly.co",
  ].filter(Boolean))];

  const providers = [];

  for (const url of candidates) {
    try {
      const chain = BigInt(
        await rpc(url, "eth_chainId")
      );

      assert.equal(chain, 11155111n);

      const head = BigInt(
        await rpc(url, "eth_blockNumber")
      );

      providers.push({ url, head });
    } catch {
      console.log(
        "RPC unavailable; trying another provider"
      );
    }
  }

  assert.ok(providers.length > 0);
  return providers;
}

async function logsFor(
  providers, from, to, topic, addresses
) {
  const filter = {
    fromBlock: toHex(from),
    toBlock: toHex(to),
    topics: [topic],
    address: addresses,
  };

  for (const provider of providers) {
    if (provider.head < to) continue;

    for (const delay of [0, 400, 1200]) {
      if (delay) await sleep(delay);

      try {
        const logs = await rpc(
          provider.url, "eth_getLogs", [filter]
        );

        return validateLogs(
          logs, from, to, topic, addresses
        );
      } catch {
        // Retry, then use another provider.
      }
    }
  }

  if (from === to) {
    throw new Error(
      `Public history unavailable at block ${from}`
    );
  }

  const middle = (from + to) / 2n;

  return [
    ...await logsFor(
      providers, from, middle, topic, addresses
    ),
    ...await logsFor(
      providers, middle + 1n, to, topic, addresses
    ),
  ];
}

async function scan(
  providers, first, last, topic, addresses
) {
  const events = [];
  const ranges = [];

  for (
    let from = first;
    from <= last;
    from += 1000n
  ) {
    const to = from + 999n < last
      ? from + 999n : last;

    const logs = await logsFor(
      providers, from, to, topic, addresses
    );

    events.push(...logs);

    ranges.push({
      from: from.toString(),
      to: to.toString(),
      count: logs.length,
    });
  }

  return { events, ranges };
}

async function main() {
  console.log(
    "=== K27: Fresh public-chain review ==="
  );

  const base = verifyK25PublicEvidence();

  const previous = load(
    "r5-e5b9k26-live-readiness.json"
  );

  assert.equal(previous.checkpoint, "R5-E5B9K26");
  assert.equal(previous.previousHead, base.checkedThrough);
  assert.equal(previous.newRegistrations, 0);

  const providers = await connect();

  const head = providers.reduce(
    (min, p) => p.head < min ? p.head : min,
    providers[0].head
  );

  const start = BigInt(previous.checkedThrough) + 1n;

  assert.ok(head >= start - 1n);

  const archive = load(
    "r5-e5b9k21r6-pool-history.json"
  );

  const pools = archive.poolAddresses.map(
    address => getAddress(address)
  );

  console.log(
    `SCAN: ${start} through ${head}`
  );

  const registrations = await scan(
    providers, start, head, regTopic, entrypoint
  );

  const known = new Set(
    pools.map(p => p.toLowerCase())
  );

  for (const log of registrations.events) {
    const decoded = decodeEventLog({
      abi: [regAbi],
      data: log.data,
      topics: log.topics,
      strict: true,
    });

    const pool = getAddress(
      decoded.args[poolFields[0].name]
    );

    if (!known.has(pool.toLowerCase())) {
      throw new Error(
        "New pool registered; full history refresh required"
      );
    }
  }

  const deposits = await scan(
    providers, start, head, depTopic, pools
  );

  const newPrecommitments = deposits.events.map(
    log => {
      const decoded = decodeEventLog({
        abi: [depAbi],
        data: log.data,
        topics: log.topics,
        strict: true,
      });

      const value = decoded.args._precommitment;

      assert.ok(
        typeof value === "bigint" && value > 0n
      );

      return value.toString();
    }
  );

  const provider = providers.find(
    p => p.head >= head
  );

  assert.ok(provider);

  const url = provider.url;
  const tag = toHex(head);

  const [
    block, code, balanceRaw,
    nonceRaw, priorityRaw,
  ] = await Promise.all([
    rpc(url, "eth_getBlockByNumber", [tag, false]),
    rpc(url, "eth_getCode", [entrypoint, tag]),
    rpc(url, "eth_getBalance", [sender, tag]),
    rpc(url, "eth_getTransactionCount",
      [sender, "pending"]),
    rpc(url, "eth_maxPriorityFeePerGas"),
  ]);

  assert.equal(BigInt(block.number), head);
  assert.ok(
    /^0x[0-9a-f]{64}$/i.test(block.hash)
  );

  assert.ok(code && code !== "0x");

  const codeHash = keccak256(code);

  assert.equal(
    codeHash,
    previous.entrypointCodeHash,
    "Entrypoint bytecode changed"
  );

  const balance = BigInt(balanceRaw);
  const nonce = BigInt(nonceRaw);

  assert.equal(
    nonce,
    BigInt(previous.pendingNonce),
    "Sender nonce changed"
  );

  const baseFee = BigInt(block.baseFeePerGas);
  const priority = BigInt(priorityRaw);

  // Public synthetic fixture, never the real
  // hardware-derived precommitment.
  const data = encodeFunctionData({
    abi: parseAbi([
      "function deposit(uint256 precommitment) payable",
    ]),
    functionName: "deposit",
    args: [12345678901234567890n],
  });

  const estimate = BigInt(
    await rpc(url, "eth_estimateGas", [{
      from: sender,
      to: entrypoint,
      value: toHex(amount),
      data,
    }])
  );

  const budget = calculateFeeBudget(
    estimate,
    baseFee,
    priority,
    balance
  );

  assert.ok(
    budget.gasLimit <= BigInt(block.gasLimit)
  );

  const result = {
    checkpoint: "R5-E5B9K27-public",
    chainId: 11155111,
    previousHead: previous.checkedThrough,
    checkedThrough: head.toString(),
    blockHash: block.hash,
    entrypoint,
    entrypointCodeHash: codeHash,
    sender,
    balanceWei: balance.toString(),
    pendingNonce: nonce.toString(),
    depositValueWei: amount.toString(),
    syntheticGasEstimate: estimate.toString(),
    suggestedGasLimit: budget.gasLimit.toString(),
    suggestedMaxFeePerGas:
      budget.maxFeePerGas.toString(),
    suggestedPriorityFeePerGas:
      priority.toString(),
    knownPools: pools.length,
    newRegistrations: registrations.events.length,
    newDeposits: newPrecommitments.length,
    totalPublicDeposits:
      previous.totalPublicDeposits +
      newPrecommitments.length,
    registrationRanges: registrations.ranges,
    depositRanges: deposits.ranges,
    newPrecommitments,
    realCalldataSent: false,
    signed: false,
    broadcast: false,
  };

  validateExtension(previous, result);

  const temporary = filename + ".writing";

  writeFileSync(
    temporary,
    JSON.stringify(result),
    { mode: 0o600 }
  );

  chmodSync(temporary, 0o600);
  renameSync(temporary, filename);

  const verified = verifyK27PublicEvidence();

  console.log(JSON.stringify({
    checkpoint: "R5-E5B9K27-public",
    checkedThrough: result.checkedThrough,
    publicDeposits: verified.depositCount,
    newDeposits: result.newDeposits,
    pendingNonce: result.pendingNonce,
    suggestedGasLimit: result.suggestedGasLimit,
    suggestedMaxFeePerGas:
      result.suggestedMaxFeePerGas,
    suggestedPriorityFeePerGas:
      result.suggestedPriorityFeePerGas,
    syntheticGasOnly: true,
    credentialAccessed: false,
    signed: false,
    broadcast: false,
  }, null, 2));

  console.log(
    "PASS: K27 public preflight"
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) ===
    fileURLToPath(import.meta.url)
) {
  main().catch(error => {
    const url = process.env.SEPOLIA_RPC_URL;
    const message = String(error.message);

    console.error(
      "FAIL:",
      (url ? message.replaceAll(url, "[RPC]") : message)
        .slice(0, 200)
    );

    process.exitCode = 1;
  });
}
