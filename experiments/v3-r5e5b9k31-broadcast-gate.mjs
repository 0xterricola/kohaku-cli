import assert from "node:assert/strict";
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { keccak256, toEventSelector, toHex } from "viem";

import {
  ENTRYPOINT_EVENTS_SIGNATURES,
  POOL_EVENTS_SIGNATURES,
} from "../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/events.abi.ts";

import {
  verifyK28PublicEvidence,
} from "./v3-r5e5b9k28-public-review.mjs";

const work = join(
  homedir(),
  "Library/Application Support/KohakuKeyResearch/v3-r5e9i-parser-fix"
);

const load = name => JSON.parse(
  readFileSync(join(work, name), "utf8")
);

const entrypoint =
  "0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB";

const sender =
  "0x155a8332A3504D5F532742Ae6531cd0e28035972";

const amount = 2000000000000000n;

const methods = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getLogs",
  "eth_getCode",
  "eth_getBalance",
  "eth_getTransactionCount",
  "eth_maxPriorityFeePerGas",
]);

export function assertReadOnly(method) {
  assert.ok(methods.has(method), "Prohibited RPC method");
  return true;
}

export function verifySigningEvidence(k29, k30) {
  assert.equal(k29.checkpoint, "R5-E5B9K29-simulation");
  assert.equal(k30.checkpoint, "R5-E5B9K30-signed-offline");

  assert.equal(k29.chainId, 11155111);
  assert.equal(k30.chainId, 11155111);

  assert.equal(k29.ethCallPassed, true);
  assert.equal(k29.ethEstimateGasPassed, true);
  assert.equal(k29.realCalldataSent, true);

  assert.equal(k30.hardwareSigned, true);
  assert.equal(k30.signerRecovered, true);
  assert.equal(k30.signedBytesPersisted, false);
  assert.equal(k30.broadcast, false);

  // K30 is an earlier, independently verified offline
  // signature. K29 is refreshed by subsequent attempts.
  // They need not share a simulation block or fee quote.
  assert.ok(
    BigInt(k29.simulatedAtBlock) >=
      BigInt(k30.simulatedAtBlock),
    "Latest simulation predates signed checkpoint"
  );
  assert.equal(k29.nonce, String(k30.nonce));
  assert.equal(k30.depositIndex, 17);
  assert.equal(k30.depositValueWei, amount.toString());

  assert.equal(k29.sender.toLowerCase(), sender.toLowerCase());
  assert.equal(k30.sender.toLowerCase(), sender.toLowerCase());
  assert.equal(k30.entrypoint.toLowerCase(), entrypoint.toLowerCase());

  // Validate each checkpoint's parameters separately.
  // Current fees must always be refreshed before signing.
  assert.ok(BigInt(k30.gasLimit) > 0n);
  assert.ok(
    BigInt(k30.maxFeePerGas) >=
      BigInt(k30.maxPriorityFeePerGas)
  );
  assert.ok(
    BigInt(k29.suggestedGasLimit) >
      BigInt(k29.realGasEstimate)
  );
  assert.ok(
    BigInt(k29.suggestedMaxFeePerGas) >=
      BigInt(k29.suggestedPriorityFeePerGas)
  );

  assert.match(k30.transactionHash, /^0x[0-9a-f]{64}$/i);

  return true;
}

export function budget(gas, baseFee, priority, balance) {
  for (const n of [gas, baseFee, priority, balance]) {
    assert.ok(typeof n === "bigint" && n >= 0n);
  }

  assert.ok(gas > 0n && baseFee > 0n);

  const maxFeePerGas = 2n * baseFee + priority;
  const maximumCostWei = amount + gas * maxFeePerGas;

  assert.ok(
    maximumCostWei <= balance,
    "Insufficient sender balance"
  );

  // Separate conservative cost ceiling for this PoC.
  assert.ok(
    maximumCostWei <= 10000000000000000n,
    "Review exceeds 0.01 ETH total budget ceiling"
  );

  return { maxFeePerGas, maximumCostWei };
}

async function main() {
  const evidence = verifyK28PublicEvidence();
  const k28 = load("r5-e5b9k28-public-review.json");
  const k29 = load("r5-e5b9k29-simulation.json");
  const k30 = load("r5-e5b9k30-signing.json");
  const history = load("r5-e5b9k21r6-pool-history.json");

  verifySigningEvidence(k29, k30);
  assert.equal(k28.checkedThrough, evidence.checkedThrough);
  assert.equal(k28.totalPublicDeposits, evidence.depositCount);

  const url = process.env.SEPOLIA_RPC_URL ||
    "https://sepolia.gateway.tenderly.co";

  const parsed = new URL(url);

  assert.equal(parsed.protocol, "https:");
  assert.ok(!parsed.username && !parsed.password);

  async function rpc(method, params = []) {
    assertReadOnly(method);

    let response;
    try {
      response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0", id: 1, method, params,
        }),
        signal: AbortSignal.timeout(20000),
      });
    } catch {
      throw new Error(`RPC transport failed: ${method}`);
    }

    if (!response.ok) {
      throw new Error(`RPC HTTP failure: ${method}`);
    }

    const result = await response.json();

    if (result.error || result.result === undefined) {
      throw new Error(`RPC rejected: ${method}`);
    }

    return result.result;
  }

  assert.equal(BigInt(await rpc("eth_chainId")), 11155111n);

  const start = BigInt(evidence.checkedThrough);
  const head = BigInt(await rpc("eth_blockNumber"));

  assert.ok(head >= start && head - start <= 64n,
    "Public history stale: rerun K28");

  const anchor = await rpc(
    "eth_getBlockByNumber", [toHex(start), false]
  );

  assert.equal(
    anchor?.hash?.toLowerCase(),
    k28.blockHash.toLowerCase(),
    "Audited head changed"
  );

  const block = await rpc(
    "eth_getBlockByNumber", [toHex(head), false]
  );

  assert.equal(BigInt(block.number), head);

  if (head > start) {
    const fromBlock = toHex(start + 1n);
    const toBlock = toHex(head);

    const registrations = await rpc("eth_getLogs", [{
      address: entrypoint,
      fromBlock,
      toBlock,
      topics: [
        toEventSelector(
          ENTRYPOINT_EVENTS_SIGNATURES.PoolRegistered
        ),
      ],
    }]);

    const deposits = await rpc("eth_getLogs", [{
      address: history.poolAddresses,
      fromBlock,
      toBlock,
      topics: [
        toEventSelector(
          POOL_EVENTS_SIGNATURES.PoolDeposited
        ),
      ],
    }]);

    assert.ok(
      Array.isArray(registrations) &&
      registrations.length === 0,
      "Registry changed: refresh history"
    );

    assert.ok(
      Array.isArray(deposits) &&
      deposits.length === 0,
      "Deposit history changed: refresh history"
    );
  }

  const tag = toHex(head);

  const [code, balanceRaw, nonceRaw, priorityRaw] =
    await Promise.all([
      rpc("eth_getCode", [entrypoint, tag]),
      rpc("eth_getBalance", [sender, tag]),
      rpc("eth_getTransactionCount", [sender, "pending"]),
      rpc("eth_maxPriorityFeePerGas"),
    ]);

  assert.ok(typeof code === "string" && code !== "0x");
  assert.equal(
    keccak256(code).toLowerCase(),
    k28.entrypointCodeHash.toLowerCase()
  );

  const nonce = BigInt(nonceRaw);
  assert.equal(nonce, BigInt(k30.nonce),
    "Sender nonce changed");

  const gasLimit = BigInt(k29.suggestedGasLimit);

  assert.ok(gasLimit < BigInt(block.gasLimit));

  const fees = budget(
    gasLimit,
    BigInt(block.baseFeePerGas),
    BigInt(priorityRaw),
    BigInt(balanceRaw)
  );

  const result = {
    checkpoint: "R5-E5B9K31-public-gate",
    chainId: 11155111,
    checkedThrough: head.toString(),
    auditedDepositCount: evidence.depositCount,
    registeredPools: history.poolAddresses.length,
    sender,
    entrypoint,
    nonce: nonce.toString(),
    depositValueWei: amount.toString(),
    gasLimitForReview: gasLimit.toString(),
    freshMaxFeePerGas: fees.maxFeePerGas.toString(),
    freshPriorityFeePerGas: BigInt(priorityRaw).toString(),
    maximumCostWei: fees.maximumCostWei.toString(),
    k30OfflineSignatureVerified: true,
    k30OfflineTransactionHash: k30.transactionHash,
    k30HashIsOnchain: false,
    requiresFreshSimulationAndSigning: true,
    broadcastingAuthorized: false,
    hardwareAccessed: false,
    signedNow: false,
    broadcastNow: false,
  };

  const filename = join(work, "r5-e5b9k31-public-gate.json");
  const temp = filename + ".writing";

  writeFileSync(temp, JSON.stringify(result), { mode: 0o600 });
  renameSync(temp, filename);

  console.log(JSON.stringify(result, null, 2));
  console.log("PASS: K31 public broadcast-readiness gate");
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch(() => {
    console.error(
      "FAIL: K31 public gate; no transaction was submitted"
    );
    process.exitCode = 1;
  });
}
