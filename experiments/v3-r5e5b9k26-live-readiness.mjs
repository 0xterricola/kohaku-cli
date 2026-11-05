import assert from "node:assert/strict";
import {
  existsSync, readFileSync, writeFileSync,
  renameSync, chmodSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  decodeEventLog, encodeFunctionData,
  getAddress, keccak256, toEventSelector, toHex,
  formatEther, parseAbi,
} from "viem";

import {
  ENTRYPOINT_EVENTS_SIGNATURES,
  POOL_EVENTS_SIGNATURES,
} from "../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/events.abi.ts";

import {
  verifyK25PublicEvidence,
} from "./v3-r5e5b9k25-public-evidence.mjs";

const registry =
  ENTRYPOINT_EVENTS_SIGNATURES.PoolRegistered;
const deposit =
  POOL_EVENTS_SIGNATURES.PoolDeposited;

const registryTopic = toEventSelector(registry);
const depositTopic = toEventSelector(deposit);

const poolField = registry.inputs.filter(
  x => x.type === "address" && /pool/i.test(x.name)
);
assert.equal(poolField.length, 1);

const entrypoint = getAddress(
  "0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB"
);
const sender = getAddress(
  "0x155a8332A3504D5F532742Ae6531cd0e28035972"
);
const amount = 2000000000000000n;

const work = join(
  homedir(),
  "Library/Application Support/KohakuKeyResearch/v3-r5e9i-parser-fix"
);

const output = join(
  work, "r5-e5b9k26-live-readiness.json"
);

const allowed = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getLogs",
  "eth_getBlockByNumber",
  "eth_getCode",
  "eth_getBalance",
  "eth_getTransactionCount",
  "eth_estimateGas",
  "eth_feeHistory",
  "eth_maxPriorityFeePerGas",
]);

const sleep = ms =>
  new Promise(r => setTimeout(r, ms));

export function calculateFeeBudget(
  estimate, baseFee, priorityFee, balance
) {
  for (const value of [
    estimate, baseFee, priorityFee, balance,
  ]) {
    if (typeof value !== "bigint" || value < 0n) {
      throw new Error("Invalid fee parameter");
    }
  }

  assert.ok(estimate > 0n && baseFee > 0n);

  const gasLimit = (estimate * 125n + 99n) / 100n;
  const maxFeePerGas = baseFee * 2n + priorityFee;
  const total = amount + gasLimit * maxFeePerGas;

  if (total > balance) {
    throw new Error(
      "Insufficient funds for conservative fee budget"
    );
  }

  return { gasLimit, maxFeePerGas, total };
}

export function validateLogs(logs, from, to, topic, addresses) {
  assert.ok(Array.isArray(logs));

  const authorized = new Set(
    (Array.isArray(addresses)
      ? addresses : [addresses]
    ).map(x => getAddress(x).toLowerCase())
  );

  const seen = new Set();

  for (const log of logs) {
    assert.equal(log.removed === true, false);

    const block = BigInt(log.blockNumber);

    assert.ok(block >= from && block <= to);
    assert.ok(
      authorized.has(getAddress(log.address).toLowerCase())
    );
    assert.equal(
      log.topics?.[0]?.toLowerCase(),
      topic.toLowerCase()
    );

    const identity =
      `${log.transactionHash}:${log.logIndex}`;

    assert.ok(!seen.has(identity), "Duplicate event");
    seen.add(identity);
  }

  return logs;
}

async function rpc(url, method, params = []) {
  if (!allowed.has(method)) {
    throw new Error("Prohibited RPC method");
  }

  const parsed = new URL(url);
  assert.equal(parsed.protocol, "https:");

  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 1, method, params,
    }),
    signal: AbortSignal.timeout(20000),
  });

  if (!response.ok) {
    throw new Error(`RPC HTTP ${response.status}`);
  }

  const result = await response.json();

  if (result.error || result.result === undefined) {
    throw new Error("Read-only RPC failure");
  }

  return result.result;
}

async function connect() {
  const urls = [...new Set([
    process.env.SEPOLIA_RPC_URL,
    "https://sepolia.gateway.tenderly.co",
  ].filter(Boolean))];

  const providers = [];

  for (const url of urls) {
    try {
      const chain = BigInt(
        await rpc(url, "eth_chainId")
      );

      assert.equal(chain, 11155111n);

      providers.push({
        url,
        head: BigInt(
          await rpc(url, "eth_blockNumber")
        ),
      });
    } catch {
      console.log(
        "Provider unavailable; checking next endpoint"
      );
    }
  }

  assert.ok(
    providers.length > 0,
    "No reachable Sepolia provider"
  );

  return providers;
}

async function resilientLogs(
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
        // Retry, then fail over.
      }
    }
  }

  if (from === to) {
    throw new Error(
      `Incomplete public log history at ${from}`
    );
  }

  const middle = (from + to) / 2n;

  return [
    ...await resilientLogs(
      providers, from, middle, topic, addresses
    ),
    ...await resilientLogs(
      providers, middle + 1n, to, topic, addresses
    ),
  ];
}

async function scan(providers, first, last, topic, addresses) {
  const events = [];
  const ranges = [];

  for (
    let from = first;
    from <= last;
    from += 1000n
  ) {
    const to = from + 999n < last
      ? from + 999n : last;

    const logs = await resilientLogs(
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
    "=== K26: Verify historical evidence ==="
  );

  const evidence = verifyK25PublicEvidence();

  const previous = BigInt(evidence.checkedThrough);
  const providers = await connect();

  const head = providers.reduce(
    (minimum, p) =>
      p.head < minimum ? p.head : minimum,
    providers[0].head
  );

  assert.ok(head >= previous);
  assert.equal(evidence.sender, sender);

  const archive = JSON.parse(
    readFileSync(
      join(work, "r5-e5b9k21r6-pool-history.json"),
      "utf8"
    )
  );

  const pools = archive.poolAddresses.map(getAddress);

  console.log(
    `PASS: ${evidence.depositCount} prior deposits audited`
  );
  console.log(
    `SCAN: ${previous + 1n} through ${head}`
  );

  const registrations = await scan(
    providers,
    previous + 1n,
    head,
    registryTopic,
    entrypoint
  );

  const known = new Set(
    pools.map(p => p.toLowerCase())
  );

  for (const log of registrations.events) {
    const decoded = decodeEventLog({
      abi: [registry],
      topics: log.topics,
      data: log.data,
      strict: true,
    });

    const pool = getAddress(
      decoded.args[poolField[0].name]
    );

    if (!known.has(pool.toLowerCase())) {
      throw new Error(
        "New pool registered: refresh full pool history"
      );
    }
  }

  const deposits = await scan(
    providers,
    previous + 1n,
    head,
    depositTopic,
    pools
  );

  const newPrecommitments = deposits.events.map(log => {
    const decoded = decodeEventLog({
      abi: [deposit],
      topics: log.topics,
      data: log.data,
      strict: true,
    });

    const value = decoded.args._precommitment;

    assert.ok(
      typeof value === "bigint" && value > 0n
    );

    return value.toString();
  });

  console.log(
    "PASS: Public deposit history refreshed"
  );

  // No credential, witness or hardware-derived
  // calldata is used for these RPC operations.
  const provider = providers.find(p => p.head >= head);
  assert.ok(provider);

  const url = provider.url;
  const tag = toHex(head);

  const [
    block, code, balanceRaw,
    pendingNonceRaw, feeHistory, priorityRaw,
  ] = await Promise.all([
    rpc(url, "eth_getBlockByNumber", [tag, false]),
    rpc(url, "eth_getCode", [entrypoint, tag]),
    rpc(url, "eth_getBalance", [sender, tag]),
    rpc(url, "eth_getTransactionCount",
      [sender, "pending"]),
    rpc(url, "eth_feeHistory",
      ["0x2", "latest", []]),
    rpc(url, "eth_maxPriorityFeePerGas"),
  ]);

  assert.equal(BigInt(block.number), head);
  assert.ok(/^0x[0-9a-f]{64}$/i.test(block.hash));
  assert.ok(
    typeof code === "string" && code !== "0x"
  );

  const balance = BigInt(balanceRaw);
  const nonce = BigInt(pendingNonceRaw);

  if (nonce !== BigInt(evidence.observedNonce)) {
    throw new Error(
      "Sender nonce changed since K24"
    );
  }

  const baseFee = BigInt(
    feeHistory.baseFeePerGas.at(-1)
  );

  const priorityFee = BigInt(priorityRaw);

  // Synthetic, public-only deposit calldata.
  // NOT derived from the user's Keycard.
  const syntheticData = encodeFunctionData({
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
      data: syntheticData,
    }])
  );

  const budget = calculateFeeBudget(
    estimate, baseFee, priorityFee, balance
  );

  assert.ok(
    budget.gasLimit <= BigInt(block.gasLimit),
    "Gas budget exceeds block gas limit"
  );

  const result = {
    checkpoint: "R5-E5B9K26",
    chainId: 11155111,
    previousHead: previous.toString(),
    checkedThrough: head.toString(),
    blockHash: block.hash,
    entrypoint,
    entrypointCodeHash: keccak256(code),
    sender,
    balanceWei: balance.toString(),
    balanceETH: formatEther(balance),
    pendingNonce: nonce.toString(),
    depositValueWei: amount.toString(),
    syntheticGasEstimate: estimate.toString(),
    suggestedGasLimit: budget.gasLimit.toString(),
    suggestedMaxFeePerGas:
      budget.maxFeePerGas.toString(),
    suggestedPriorityFeePerGas:
      priorityFee.toString(),
    maximumBudgetWei: budget.total.toString(),
    authorizedPoolCount: pools.length,
    newRegistrations: registrations.events.length,
    newDeposits: newPrecommitments.length,
    totalPublicDeposits:
      evidence.depositCount + newPrecommitments.length,
    simulationUsesRealCredential: false,
    hardwareAccessed: false,
    signed: false,
    broadcast: false,
  };

  // Public blockchain values only.
  const stored = {
    ...result,
    newPrecommitments,
    registrationRanges: registrations.ranges,
    depositRanges: deposits.ranges,
  };

  const temporary = output + ".writing";

  writeFileSync(
    temporary,
    JSON.stringify(stored),
    { mode: 0o600 }
  );

  chmodSync(temporary, 0o600);
  renameSync(temporary, output);

  console.log(JSON.stringify(result, null, 2));
  console.log("PASS: K26 public readiness");
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) ===
    fileURLToPath(import.meta.url)
) {
  try {
    await main();
  } catch (error) {
    // Do not print RPC URLs or provider credentials.
    console.error(
      "FAIL:",
      String(error.message)
        .replaceAll(
          process.env.SEPOLIA_RPC_URL || "\0",
          "[RPC]"
        )
        .slice(0, 200)
    );
    process.exitCode = 1;
  }
}
