import assert from "node:assert/strict";
import {
  openSync, closeSync, readSync, writeSync,
  readFileSync, writeFileSync, renameSync, chmodSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  decodeEventLog, decodeFunctionData,
  getAddress, isAddressEqual, keccak256,
  parseAbi, parseTransaction,
  recoverTransactionAddress, toEventSelector,
  toHex, formatEther,
} from "viem";

import {
  POOL_EVENTS_SIGNATURES,
  ENTRYPOINT_EVENTS_SIGNATURES,
} from "../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/events.abi.ts";

import {
  assertUnused,
} from "./v3-r5e5b9k25-public-evidence.mjs";

const sender = getAddress(
  "0x155a8332A3504D5F532742Ae6531cd0e28035972"
);

const entrypoint = getAddress(
  "0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB"
);

const amount = 2000000000000000n;

const work = join(
  homedir(),
  "Library/Application Support/KohakuKeyResearch/v3-r5e9i-parser-fix"
);

const output = join(work, "r5-e5b9k32-publicnode-broadcast.json");

const depositAbi = parseAbi([
  "function deposit(uint256 _precommitment) payable",
]);

const depositEvent = POOL_EVENTS_SIGNATURES.PoolDeposited;
const registrationEvent =
  ENTRYPOINT_EVENTS_SIGNATURES.PoolRegistered;

const depositTopic = toEventSelector(depositEvent);
const registrationTopic = toEventSelector(registrationEvent);

const readMethods = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getCode",
  "eth_getLogs",
  "eth_getBalance",
  "eth_getTransactionCount",
  "eth_getTransactionReceipt",
  "eth_getTransactionByHash",
]);

export function assertRpcMethod(method, approved = false) {
  if (method === "eth_sendRawTransaction") {
    if (approved !== true) {
      throw new Error("Broadcast approval required");
    }
    return true;
  }

  if (!readMethods.has(method)) {
    throw new Error("Prohibited RPC method");
  }

  return true;
}

export function requireBroadcastWord(value) {
  if (value !== "BROADCAST") {
    throw new Error("Broadcast authorization declined");
  }
  return true;
}

function readTerminalApproval() {
  let fd;

  try {
    fd = openSync("/dev/tty", "r+");
  } catch {
    throw new Error(
      "Interactive terminal required for broadcast"
    );
  }

  try {
    writeSync(
      fd,
      Buffer.from(
        "\n=== K32 FINAL BROADCAST APPROVAL ===\n" +
        "This submits a REAL transaction on Sepolia.\n" +
        "It will deposit 0.002 Sepolia ETH.\n" +
        "The signed transaction has been verified.\n" +
        "Type BROADCAST to submit, or anything else to cancel: "
      )
    );

    const byte = Buffer.alloc(1);
    let response = "";

    while (response.length < 32) {
      const n = readSync(fd, byte, 0, 1, null);

      if (n !== 1) {
        throw new Error("Approval input unavailable");
      }

      const c = String.fromCharCode(byte[0]);

      if (c === "\n") break;
      if (c !== "\r") response += c;
    }

    requireBroadcastWord(response);
    writeSync(fd, Buffer.from("\n"));
  } finally {
    closeSync(fd);
  }
}

function load(name) {
  return JSON.parse(
    readFileSync(join(work, name), "utf8")
  );
}

function savePublicEvidence(record) {
  const temporary = output + ".writing";

  writeFileSync(
    temporary,
    JSON.stringify(record, null, 2),
    { mode: 0o600 }
  );

  chmodSync(temporary, 0o600);
  renameSync(temporary, output);
}

function sleep(ms) {
  return new Promise(resolve =>
    setTimeout(resolve, ms)
  );
}

export async function broadcastVerifiedDeposit({
  transaction,
  serializedTransaction,
  transactionHash,
  simulation,
  evidence,
  candidate,
  networkFetch,
}) {
  if (typeof networkFetch !== "function") {
    throw new Error("Approved RPC transport unavailable");
  }

  assert.equal(
    simulation.checkpoint,
    "R5-E5B9K29-simulation"
  );

  assert.equal(simulation.ethCallPassed, true);
  assert.equal(simulation.ethEstimateGasPassed, true);

  const parsed = parseTransaction(serializedTransaction);

  assert.equal(parsed.type, "eip1559");
  assert.equal(parsed.chainId, 11155111);
  assert.equal(parsed.nonce, transaction.nonce);
  assert.equal(parsed.value, amount);
  assert.equal(parsed.gas, transaction.gas);
  assert.equal(parsed.data, transaction.data);
  assert.equal(
    parsed.maxFeePerGas,
    transaction.maxFeePerGas
  );
  assert.equal(
    parsed.maxPriorityFeePerGas,
    transaction.maxPriorityFeePerGas
  );

  assert.ok(isAddressEqual(parsed.to, entrypoint));

  assert.equal(
    keccak256(serializedTransaction).toLowerCase(),
    transactionHash.toLowerCase()
  );

  const recovered = await recoverTransactionAddress({
    serializedTransaction,
  });

  assert.ok(
    isAddressEqual(recovered, sender),
    "Serialized transaction signer mismatch"
  );

  const decoded = decodeFunctionData({
    abi: depositAbi,
    data: parsed.data,
  });

  assert.equal(decoded.functionName, "deposit");
  assert.equal(decoded.args[0], candidate);

  assertUnused(candidate, evidence.allPublicKeys);

  const rpcUrl = process.env.SEPOLIA_RPC_URL ||
    "https://sepolia.gateway.tenderly.co";

  const endpoint = new URL(rpcUrl);

  if (
    endpoint.protocol !== "https:" ||
    endpoint.username ||
    endpoint.password ||
    endpoint.hash
  ) {
    throw new Error("Invalid HTTPS RPC endpoint");
  }

  let submissionApproved = false;

  async function rpc(method, params = []) {
    assertRpcMethod(method, submissionApproved);

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
        `RPC transport failure: ${method}`
      );
    }

    if (!response.ok) {
      throw new Error(
        `RPC HTTP failure: ${method}`
      );
    }

    const body = await response.json();

    // Provider errors may echo raw calldata or the
    // signed transaction. Never print their payloads.
    if (body.error || body.result === undefined) {
      throw new Error(
        `RPC rejected request: ${method}`
      );
    }

    return body.result;
  }

  const chainId = BigInt(
    await rpc("eth_chainId")
  );

  assert.equal(chainId, 11155111n);

  const k28 = load(
    "r5-e5b9k28-public-review.json"
  );

  const history = load(
    "r5-e5b9k21r6-pool-history.json"
  );

  const pools = history.poolAddresses.map(getAddress);
  const allowedPools = new Set(
    pools.map(p => p.toLowerCase())
  );

  assert.equal(pools.length, 3);

  const expectedNonce = BigInt(transaction.nonce);
  const simulatedHead = BigInt(
    simulation.simulatedAtBlock
  );

  const totalBudget =
    amount +
    transaction.gas * transaction.maxFeePerGas;

  if (
    totalBudget > 10000000000000000n
  ) {
    throw new Error(
      "Deposit exceeds 0.01 ETH total budget ceiling"
    );
  }

  console.log("");
  console.log("=== K32: VERIFIED SIGNED TRANSACTION ===");

  console.log(JSON.stringify({
    chainId: 11155111,
    sender,
    entrypoint,
    depositIndex: 17,
    amountETH: "0.002",
    nonce: transaction.nonce,
    gasLimit: transaction.gas.toString(),
    maxFeePerGasWei:
      transaction.maxFeePerGas.toString(),
    priorityFeePerGasWei:
      transaction.maxPriorityFeePerGas.toString(),
    maximumCostETH: formatEther(totalBudget),
    locallyComputedTransactionHash:
      transactionHash,
    rpcProvider: endpoint.hostname,
    hardwareSignerVerified: true,
    signedTransactionPersisted: false,
  }, null, 2));

  // This confirmation is separate from the
  // native Keycard SIGN approval.
  readTerminalApproval();

  submissionApproved = true;

  // Final live recheck AFTER the user authorizes
  // broadcasting, not before.
  const currentHead = BigInt(
    await rpc("eth_blockNumber")
  );

  if (
    currentHead < simulatedHead ||
    currentHead - simulatedHead > 128n
  ) {
    throw new Error(
      "Simulation is stale; no broadcast performed"
    );
  }

  const k28Anchor = BigInt(k28.checkedThrough);

  const anchoredBlock = await rpc(
    "eth_getBlockByNumber",
    [toHex(k28Anchor), false]
  );

  assert.equal(
    anchoredBlock?.hash?.toLowerCase(),
    k28.blockHash.toLowerCase(),
    "Audited history anchor changed"
  );

  const currentBlock = await rpc(
    "eth_getBlockByNumber",
    [toHex(currentHead), false]
  );

  assert.equal(
    BigInt(currentBlock.number),
    currentHead
  );

  if (currentHead > simulatedHead) {
    const fromBlock = toHex(simulatedHead + 1n);
    const toBlock = toHex(currentHead);

    const registrations = await rpc(
      "eth_getLogs",
      [{
        address: entrypoint,
        fromBlock,
        toBlock,
        topics: [registrationTopic],
      }]
    );

    const deposits = await rpc(
      "eth_getLogs",
      [{
        address: pools,
        fromBlock,
        toBlock,
        topics: [depositTopic],
      }]
    );

    if (
      !Array.isArray(registrations) ||
      registrations.length !== 0 ||
      !Array.isArray(deposits) ||
      deposits.length !== 0
    ) {
      throw new Error(
        "Pool history changed; no broadcast performed"
      );
    }
  }

  const tag = toHex(currentHead);

  const [code, balanceRaw, nonceRaw] =
    await Promise.all([
      rpc("eth_getCode", [entrypoint, tag]),
      rpc("eth_getBalance", [sender, tag]),
      rpc("eth_getTransactionCount",
        [sender, "pending"]),
    ]);

  if (
    !code ||
    code === "0x" ||
    keccak256(code).toLowerCase() !==
      k28.entrypointCodeHash.toLowerCase()
  ) {
    throw new Error(
      "Entrypoint bytecode changed"
    );
  }

  if (BigInt(nonceRaw) !== expectedNonce) {
    throw new Error(
      "Sender nonce changed; no broadcast performed"
    );
  }

  if (BigInt(balanceRaw) < totalBudget) {
    throw new Error(
      "Insufficient balance; no broadcast performed"
    );
  }

  const baseFee = BigInt(
    currentBlock.baseFeePerGas
  );

  // Require enough headroom for the next block's
  // maximum 12.5% EIP-1559 base-fee increase.
  const nextBaseFee =
    (baseFee * 9n + 7n) / 8n;

  if (
    transaction.maxFeePerGas <
    nextBaseFee +
      transaction.maxPriorityFeePerGas
  ) {
    throw new Error(
      "Signed fee cap is stale; no broadcast performed"
    );
  }

  assert.ok(
    transaction.gas <= BigInt(currentBlock.gasLimit)
  );

  console.log(
    "PASS: Final nonce, balance, fees, bytecode and history"
  );

  console.log(
    "Local transaction hash:", transactionHash
  );
  console.log(
    `Explorer: https://sepolia.etherscan.io/tx/${transactionHash}`
  );

  const publicBase = {
    checkpoint: "R5-E5B9K32-broadcast",
    chainId: 11155111,
    transactionHash,
    explorerUrl:
      `https://sepolia.etherscan.io/tx/${transactionHash}`,
    sender,
    entrypoint,
    depositIndex: 17,
    depositValueWei: amount.toString(),
    nonce: transaction.nonce,
    gasLimit: transaction.gas.toString(),
    maxFeePerGas:
      transaction.maxFeePerGas.toString(),
    maxPriorityFeePerGas:
      transaction.maxPriorityFeePerGas.toString(),
    simulationBlock: simulation.simulatedAtBlock,
    prebroadcastHead: currentHead.toString(),
    hardwareSigned: true,
    signerRecovered: true,
    signedTransactionPersisted: false,
  };

  // Persist only a public hash and status so that
  // an ambiguous RPC failure can be investigated
  // without signing or submitting a second time.
  savePublicEvidence({
    ...publicBase,
    status: "submission_attempted",
    receiptVerified: false,
    depositEventVerified: false,
  });

  let returnedHash;

  try {
    returnedHash = await rpc(
      "eth_sendRawTransaction",
      [serializedTransaction]
    );
  } catch {
    throw new Error(
      "Submission result uncertain. Check the transaction " +
      "hash above before attempting anything else."
    );
  }

  assert.equal(
    returnedHash.toLowerCase(),
    transactionHash.toLowerCase(),
    "RPC returned an unexpected transaction hash"
  );

  savePublicEvidence({
    ...publicBase,
    status: "submitted",
    receiptVerified: false,
    depositEventVerified: false,
  });

  console.log(
    "PASS: Signed transaction accepted by Sepolia RPC"
  );

  let receipt = null;

  for (let attempt = 0; attempt < 36; attempt++) {
    receipt = await rpc(
      "eth_getTransactionReceipt",
      [transactionHash]
    );

    if (receipt !== null) break;

    await sleep(5000);
  }

  if (!receipt) {
    throw new Error(
      "Transaction submitted but receipt is pending. " +
      "Do not resubmit; inspect the saved public hash."
    );
  }

  assert.equal(
    receipt.transactionHash.toLowerCase(),
    transactionHash.toLowerCase()
  );

  assert.ok(isAddressEqual(receipt.from, sender));
  assert.ok(isAddressEqual(receipt.to, entrypoint));

  if (receipt.status !== "0x1") {
    savePublicEvidence({
      ...publicBase,
      status: "reverted",
      receiptVerified: false,
      depositEventVerified: false,
      blockNumber:
        BigInt(receipt.blockNumber).toString(),
    });

    throw new Error(
      "Transaction was mined but reverted"
    );
  }

  const onchainTx = await rpc(
    "eth_getTransactionByHash",
    [transactionHash]
  );

  assert.ok(onchainTx);

  assert.ok(isAddressEqual(onchainTx.from, sender));
  assert.ok(isAddressEqual(onchainTx.to, entrypoint));
  assert.equal(BigInt(onchainTx.nonce), expectedNonce);
  assert.equal(BigInt(onchainTx.value), amount);
  assert.equal(
    onchainTx.input.toLowerCase(),
    transaction.data.toLowerCase()
  );

  const minedBlock = await rpc(
    "eth_getBlockByNumber",
    [receipt.blockNumber, false]
  );

  assert.equal(
    minedBlock.hash.toLowerCase(),
    receipt.blockHash.toLowerCase(),
    "Mined receipt block mismatch"
  );

  const matchingEvents = [];

  for (const log of receipt.logs) {
    if (
      log.topics?.[0]?.toLowerCase() !==
      depositTopic.toLowerCase()
    ) continue;

    if (
      !allowedPools.has(
        getAddress(log.address).toLowerCase()
      )
    ) continue;

    const event = decodeEventLog({
      abi: [depositEvent],
      topics: log.topics,
      data: log.data,
      strict: true,
    });

    if (event.args._precommitment === candidate) {
      matchingEvents.push(log);
    }
  }

  assert.equal(
    matchingEvents.length,
    1,
    "Expected exactly one matching Privacy Pools deposit event"
  );

  const depositLog = matchingEvents[0];

  const result = {
    ...publicBase,
    status: "confirmed",
    blockNumber:
      BigInt(receipt.blockNumber).toString(),
    blockHash: receipt.blockHash,
    gasUsed: BigInt(receipt.gasUsed).toString(),
    depositEventPool: depositLog.address,
    depositEventLogIndex:
      BigInt(depositLog.logIndex).toString(),
    receiptVerified: true,
    depositEventVerified: true,
    broadcast: true,
  };

  savePublicEvidence(result);

  console.log("");
  console.log(JSON.stringify(result, null, 2));

  console.log(
    "PASS: K32 on-chain Privacy Pools deposit confirmed"
  );

  return result;
}
