import assert from "node:assert/strict";
import {
  readFileSync,
  writeFileSync,
  renameSync,
  chmodSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  decodeFunctionData,
  encodeFunctionData,
  getAddress,
  keccak256,
  parseAbi,
  toEventSelector,
  toHex,
  formatEther,
} from "viem";

import {
  ENTRYPOINT_EVENTS_SIGNATURES,
  POOL_EVENTS_SIGNATURES,
} from "../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/events.abi.ts";

import {
  assertUnused,
} from "./v3-r5e5b9k25-public-evidence.mjs";

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

const depositAbi = parseAbi([
  "function deposit(uint256 _precommitment) payable returns (uint256 _commitment)",
]);

const allowedMethods = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getLogs",
  "eth_getCode",
  "eth_getBalance",
  "eth_getTransactionCount",
  "eth_maxPriorityFeePerGas",
  "eth_call",
  "eth_estimateGas",
]);

export function assertReadOnlyMethod(method) {
  if (!allowedMethods.has(method)) {
    throw new Error("Prohibited RPC method");
  }
  return true;
}

export function validateLocalIntent(
  intent, candidate, evidence
) {
  if (
    intent.type !== "eip1559" ||
    intent.chainId !== 11155111 ||
    getAddress(intent.from) !== sender ||
    getAddress(intent.to) !== entrypoint ||
    intent.value !== amount ||
    !Number.isSafeInteger(intent.nonce) ||
    intent.nonce < 0 ||
    intent.nonce !== evidence.observedNonce
  ) {
    throw new Error("Unexpected hardware deposit intent");
  }

  let decoded;

  try {
    decoded = decodeFunctionData({
      abi: depositAbi,
      data: intent.data,
    });
  } catch {
    throw new Error("Invalid deposit calldata");
  }

  if (
    decoded.functionName !== "deposit" ||
    decoded.args.length !== 1 ||
    decoded.args[0] !== candidate
  ) {
    throw new Error(
      "Hardware precommitment/calldata mismatch"
    );
  }

  assertUnused(candidate, evidence.allPublicKeys);

  return true;
}

export async function simulateRealDeposit(
  intent,
  candidate,
  evidence,
  networkFetch
) {
  validateLocalIntent(intent, candidate, evidence);

  if (typeof networkFetch !== "function") {
    throw new Error("Approved transport missing");
  }

  const rpcUrl = process.env.SEPOLIA_RPC_URL ||
    "https://sepolia.gateway.tenderly.co";

  const endpoint = new URL(rpcUrl);

  if (
    endpoint.protocol !== "https:" ||
    endpoint.username ||
    endpoint.password ||
    endpoint.hash
  ) {
    throw new Error("HTTPS RPC endpoint required");
  }

  async function rpc(method, params = []) {
    assertReadOnlyMethod(method);

    let response;

    try {
      response = await networkFetch(rpcUrl, {
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
    } catch {
      throw new Error(
        `Read-only RPC transport failed: ${method}`
      );
    }

    if (!response.ok) {
      throw new Error(
        `Read-only RPC HTTP ${response.status}: ${method}`
      );
    }

    let body;

    try {
      body = await response.json();
    } catch {
      throw new Error("Invalid RPC response");
    }

    // Never print a provider error object: it may
    // echo the submitted real calldata.
    if (body.error || body.result === undefined) {
      throw new Error(
        `Read-only RPC rejected ${method}`
      );
    }

    return body.result;
  }

  console.log(
    "=== K29: Authorized RPC simulation ==="
  );
  console.log(
    "Provider host:", endpoint.hostname
  );

  const chainId = BigInt(
    await rpc("eth_chainId")
  );

  if (chainId !== 11155111n) {
    throw new Error("Wrong RPC chain");
  }

  const previous = JSON.parse(
    readFileSync(
      join(work, "r5-e5b9k28-public-review.json"),
      "utf8"
    )
  );

  const archive = JSON.parse(
    readFileSync(
      join(work, "r5-e5b9k21r6-pool-history.json"),
      "utf8"
    )
  );

  const fromHead = BigInt(
    evidence.checkedThrough
  );

  if (
    previous.checkedThrough !==
    evidence.checkedThrough
  ) {
    throw new Error("Public snapshot mismatch");
  }

  const head = BigInt(
    await rpc("eth_blockNumber")
  );

  if (
    head < fromHead ||
    head - fromHead > 128n
  ) {
    throw new Error(
      "Public snapshot too old; rerun K28"
    );
  }

  const anchoredBlock = await rpc(
    "eth_getBlockByNumber",
    [toHex(fromHead), false]
  );

  if (
    anchoredBlock?.hash?.toLowerCase() !==
    previous.blockHash.toLowerCase()
  ) {
    throw new Error(
      "Public snapshot block changed"
    );
  }

  const currentBlock = await rpc(
    "eth_getBlockByNumber",
    [toHex(head), false]
  );

  if (
    !currentBlock ||
    BigInt(currentBlock.number) !== head
  ) {
    throw new Error("Current block unavailable");
  }

  console.log(
    "PASS: Sepolia chain and snapshot anchor verified"
  );

  // Close the small gap that may have appeared
  // while the two physical PIN sessions ran.
  if (head > fromHead) {
    const first = toHex(fromHead + 1n);
    const last = toHex(head);

    const regTopic = toEventSelector(
      ENTRYPOINT_EVENTS_SIGNATURES.PoolRegistered
    );

    const depTopic = toEventSelector(
      POOL_EVENTS_SIGNATURES.PoolDeposited
    );

    const registrationLogs = await rpc(
      "eth_getLogs",
      [{
        address: entrypoint,
        fromBlock: first,
        toBlock: last,
        topics: [regTopic],
      }]
    );

    if (
      !Array.isArray(registrationLogs) ||
      registrationLogs.length !== 0
    ) {
      throw new Error(
        "Pool registry changed; refresh required"
      );
    }

    const poolAddresses =
      archive.poolAddresses.map(getAddress);

    const depositLogs = await rpc(
      "eth_getLogs",
      [{
        address: poolAddresses,
        fromBlock: first,
        toBlock: last,
        topics: [depTopic],
      }]
    );

    if (
      !Array.isArray(depositLogs) ||
      depositLogs.length !== 0
    ) {
      throw new Error(
        "Deposit history changed; refresh required"
      );
    }
  }

  console.log(
    "PASS: No new pool registrations or deposits"
  );

  const tag = toHex(head);

  const [
    bytecode,
    balanceRaw,
    nonceRaw,
    priorityRaw,
  ] = await Promise.all([
    rpc("eth_getCode", [entrypoint, tag]),
    rpc("eth_getBalance", [sender, tag]),
    rpc("eth_getTransactionCount",
      [sender, "pending"]),
    rpc("eth_maxPriorityFeePerGas"),
  ]);

  if (
    !bytecode ||
    bytecode === "0x" ||
    keccak256(bytecode).toLowerCase() !==
      previous.entrypointCodeHash.toLowerCase()
  ) {
    throw new Error("Entrypoint bytecode changed");
  }

  const balance = BigInt(balanceRaw);
  const nonce = BigInt(nonceRaw);

  if (nonce !== BigInt(intent.nonce)) {
    throw new Error("Sender nonce changed");
  }

  const baseFee = BigInt(
    currentBlock.baseFeePerGas
  );

  const priorityFee = BigInt(priorityRaw);

  if (baseFee <= 0n || priorityFee < 0n) {
    throw new Error("Invalid live fee quote");
  }

  if (balance < amount) {
    throw new Error("Insufficient deposit balance");
  }

  console.log(
    "PASS: Entrypoint, sender and fee state verified"
  );

  // This is the authorized disclosure boundary.
  // Only the precommitment is embedded in calldata.
  // The BIP-85 root, nullifier and salt are NOT.
  const transactionCall = {
    from: sender,
    to: entrypoint,
    value: toHex(amount),
    data: intent.data,
  };

  console.log(
    "AUTHORIZED: Sending real deposit calldata for eth_call"
  );

  const callResult = await rpc(
    "eth_call",
    [transactionCall, tag]
  );

  if (
    typeof callResult !== "string" ||
    !/^0x[0-9a-f]{64}$/i.test(callResult)
  ) {
    throw new Error(
      "Unexpected real-deposit simulation result"
    );
  }

  console.log("PASS: Real deposit eth_call");

  console.log(
    "AUTHORIZED: Sending real deposit calldata for eth_estimateGas"
  );

  const estimatedGas = BigInt(
    await rpc(
      "eth_estimateGas",
      [transactionCall]
    )
  );

  if (estimatedGas <= 0n) {
    throw new Error("Invalid real gas estimate");
  }

  const gasLimit =
    (estimatedGas * 125n + 99n) / 100n;

  if (
    gasLimit > BigInt(currentBlock.gasLimit)
  ) {
    throw new Error(
      "Real gas limit exceeds block limit"
    );
  }

  const maxFeePerGas =
    baseFee * 2n + priorityFee;

  const maximumCost =
    amount + gasLimit * maxFeePerGas;

  if (balance < maximumCost) {
    throw new Error(
      "Insufficient sender balance for fee budget"
    );
  }

  const result = {
    checkpoint: "R5-E5B9K29-simulation",
    chainId: 11155111,
    simulatedAtBlock: head.toString(),
    providerHost: endpoint.hostname,
    sender,
    entrypoint,
    nonce: nonce.toString(),
    senderBalanceETH: formatEther(balance),
    depositValueWei: amount.toString(),
    realCalldataSent: true,
    ethCallPassed: true,
    ethEstimateGasPassed: true,
    realGasEstimate: estimatedGas.toString(),
    suggestedGasLimit: gasLimit.toString(),
    suggestedMaxFeePerGas:
      maxFeePerGas.toString(),
    suggestedPriorityFeePerGas:
      priorityFee.toString(),
    maximumCostWei: maximumCost.toString(),
    requiresFreshChecksBeforeSigning: true,
    hardwareSigningPerformed: false,
    signed: false,
    broadcast: false,
  };

  // Persist public execution metadata only.
  // Never persist calldata or credentials.
  const output = join(
    work, "r5-e5b9k29-simulation.json"
  );

  const temporary = output + ".writing";

  writeFileSync(
    temporary,
    JSON.stringify(result),
    { mode: 0o600 }
  );

  chmodSync(temporary, 0o600);
  renameSync(temporary, output);

  console.log(JSON.stringify(result, null, 2));

  console.log(
    "PASS: K29 real-calldata simulation"
  );

  return result;
}
