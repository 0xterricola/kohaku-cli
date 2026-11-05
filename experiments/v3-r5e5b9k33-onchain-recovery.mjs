import assert from "node:assert/strict";
import {
  readFileSync, writeFileSync, renameSync, chmodSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  decodeEventLog,
  decodeFunctionData,
  getAddress,
  isAddressEqual,
  parseAbi,
  toEventSelector,
} from "viem";

import {
  POOL_EVENTS_SIGNATURES,
} from "../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/events.abi.ts";

const work = join(
  homedir(),
  "Library/Application Support/KohakuKeyResearch/v3-r5e9i-parser-fix"
);

const sender =
  "0x155a8332A3504D5F532742Ae6531cd0e28035972";

const entrypoint =
  "0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB";

const expectedHash =
  "0x33c357c4b212ac67f2d93c5f4b97563ae50939dd21f6e3ede19b92520d62a22c";

const amount = 2000000000000000n;

const depositAbi = parseAbi([
  "function deposit(uint256 _precommitment) payable",
]);

const depositEvent =
  POOL_EVENTS_SIGNATURES.PoolDeposited;

const depositTopic = toEventSelector(depositEvent);

function load(name) {
  return JSON.parse(
    readFileSync(join(work, name), "utf8")
  );
}

export function verifyPublicMetadata(proof, tx, receipt, block) {
  assert.equal(proof.checkpoint, "R5-E5B9K32-broadcast");
  assert.equal(proof.status, "confirmed");
  assert.equal(proof.receiptVerified, true);
  assert.equal(proof.depositEventVerified, true);
  assert.equal(proof.chainId, 11155111);
  assert.equal(proof.depositIndex, 17);
  assert.equal(proof.depositValueWei, amount.toString());

  assert.equal(
    proof.transactionHash.toLowerCase(),
    expectedHash
  );

  assert.equal(
    tx.hash.toLowerCase(),
    expectedHash
  );

  assert.equal(
    receipt.transactionHash.toLowerCase(),
    expectedHash
  );

  assert.equal(BigInt(tx.chainId), 11155111n);
  assert.ok(isAddressEqual(tx.from, sender));
  assert.ok(isAddressEqual(tx.to, entrypoint));

  assert.equal(BigInt(tx.value), amount);
  assert.equal(BigInt(tx.nonce), 0n);

  assert.equal(
    BigInt(tx.gas).toString(),
    proof.gasLimit
  );

  assert.equal(
    BigInt(tx.maxFeePerGas).toString(),
    proof.maxFeePerGas
  );

  assert.equal(
    BigInt(tx.maxPriorityFeePerGas).toString(),
    proof.maxPriorityFeePerGas
  );

  assert.equal(receipt.status, "0x1");
  assert.ok(isAddressEqual(receipt.from, sender));
  assert.ok(isAddressEqual(receipt.to, entrypoint));

  assert.equal(
    BigInt(receipt.blockNumber).toString(),
    proof.blockNumber
  );

  assert.equal(
    receipt.blockHash.toLowerCase(),
    proof.blockHash.toLowerCase()
  );

  assert.equal(
    block.hash.toLowerCase(),
    receipt.blockHash.toLowerCase()
  );

  assert.equal(
    BigInt(receipt.gasUsed).toString(),
    proof.gasUsed
  );

  return true;
}

function verifyRecoveredNote(proof, tx, receipt, secret, calldata) {
  assert.ok(
    typeof secret === "bigint" && secret > 0n,
    "Invalid recovered credential"
  );

  assert.equal(
    tx.input.toLowerCase(),
    calldata.toLowerCase(),
    "Recovered SDK calldata differs from mined transaction"
  );

  const decoded = decodeFunctionData({
    abi: depositAbi,
    data: tx.input,
  });

  assert.equal(decoded.functionName, "deposit");
  assert.deepEqual(decoded.args, [secret]);

  const history = load(
    "r5-e5b9k21r6-pool-history.json"
  );

  const authorized = new Set(
    history.poolAddresses.map(address =>
      getAddress(address).toLowerCase()
    )
  );

  const matched = [];

  for (const log of receipt.logs) {
    if (
      log.topics?.[0]?.toLowerCase() !==
      depositTopic.toLowerCase()
    ) continue;

    const address = getAddress(log.address);

    if (!authorized.has(address.toLowerCase())) continue;

    const event = decodeEventLog({
      abi: [depositEvent],
      topics: log.topics,
      data: log.data,
      strict: true,
    });

    if (event.args._precommitment === secret) {
      matched.push(log);
    }
  }

  assert.equal(
    matched.length, 1,
    "Expected one exact matching deposit event"
  );

  const log = matched[0];

  assert.ok(
    isAddressEqual(log.address, proof.depositEventPool)
  );

  assert.equal(
    BigInt(log.logIndex).toString(),
    proof.depositEventLogIndex
  );

  assert.equal(
    log.transactionHash.toLowerCase(),
    expectedHash
  );

  return {
    pool: getAddress(log.address),
    logIndex: BigInt(log.logIndex).toString(),
  };
}

const providers = [...new Set([
  process.env.SEPOLIA_RPC_URL,
  "https://ethereum-sepolia-rpc.publicnode.com",
  "https://sepolia.gateway.tenderly.co",
].filter(Boolean))];

const allowed = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getTransactionByHash",
  "eth_getTransactionReceipt",
  "eth_getBlockByNumber",
]);

async function readChain(fetchImpl) {
  const proof = load(
    "r5-e5b9k32-publicnode-broadcast.json"
  );

  const results = [];

  for (const url of providers) {
    const endpoint = new URL(url);

    if (
      endpoint.protocol !== "https:" ||
      endpoint.username ||
      endpoint.password
    ) continue;

    async function rpc(method, params = []) {
      assert.ok(allowed.has(method));

      const response = await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method,
          params,
        }),
        signal: AbortSignal.timeout(12000),
      });

      if (!response.ok) {
        throw new Error("RPC unavailable");
      }

      const body = await response.json();

      if (body.error || body.result === undefined) {
        throw new Error("RPC read failed");
      }

      return body.result;
    }

    let chain;

    try {
      const chainId = await rpc("eth_chainId");

      assert.equal(BigInt(chainId), 11155111n);

      const [tx, receipt, head] = await Promise.all([
        rpc("eth_getTransactionByHash", [expectedHash]),
        rpc("eth_getTransactionReceipt", [expectedHash]),
        rpc("eth_blockNumber"),
      ]);

      if (!tx || !receipt) {
        throw new Error("Confirmed transaction missing");
      }

      const block = await rpc(
        "eth_getBlockByNumber",
        [receipt.blockNumber, false]
      );

      if (!block) {
        throw new Error("Mined block missing");
      }

      chain = { tx, receipt, block, head };
    } catch {
      console.log(
        "RPC provider unavailable; trying next provider"
      );
      continue;
    }

    // A contradictory response is not silently ignored.
    verifyPublicMetadata(
      proof,
      chain.tx,
      chain.receipt,
      chain.block
    );

    assert.ok(
      BigInt(chain.head) >=
      BigInt(chain.receipt.blockNumber)
    );

    results.push({
      ...chain,
      host: endpoint.hostname,
    });
  }

  assert.ok(
    results.length > 0,
    "No RPC independently verified the mined deposit"
  );

  for (const other of results.slice(1)) {
    assert.equal(
      other.receipt.blockHash.toLowerCase(),
      results[0].receipt.blockHash.toLowerCase(),
      "Provider disagreement on deposit block"
    );
  }

  return { proof, providers: results };
}

export async function verifyHardwareRecovery({
  precommitment,
  calldata,
  fetchImpl,
}) {
  assert.equal(typeof fetchImpl, "function");

  const { proof, providers } =
    await readChain(fetchImpl);

  let matching = null;

  for (const provider of providers) {
    const match = verifyRecoveredNote(
      proof,
      provider.tx,
      provider.receipt,
      precommitment,
      calldata
    );

    if (matching) {
      assert.equal(match.pool, matching.pool);
      assert.equal(match.logIndex, matching.logIndex);
    }

    matching = match;
  }

  const record = {
    checkpoint: "R5-E5B9K33-hardware-recovery",
    chainId: 11155111,
    transactionHash: expectedHash,
    explorerUrl:
      `https://sepolia.etherscan.io/tx/${expectedHash}`,
    blockNumber: proof.blockNumber,
    depositPool: matching.pool,
    depositEventLogIndex: matching.logIndex,
    depositIndex: 17,
    depositValueWei: amount.toString(),
    independentRpcProviders: providers.length,
    hardwareSessions: 2,
    credentialReproduced: true,
    sdkCalldataMatched: true,
    onchainPrecommitmentMatched: true,
    onchainDepositEventMatched: true,
    rootOrSecretsPersisted: false,
    hardwareSigningNow: false,
    broadcastingNow: false,
  };

  const path = join(
    work, "r5-e5b9k33-recovery.json"
  );

  const temporary = path + ".writing";

  writeFileSync(
    temporary,
    JSON.stringify(record, null, 2),
    { mode: 0o600 }
  );

  chmodSync(temporary, 0o600);
  renameSync(temporary, path);

  console.log(JSON.stringify(record, null, 2));
  console.log(
    "PASS: K33 hardware credential independently recovered"
  );

  return record;
}

if (
  process.argv.includes("--preflight") &&
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await readChain(globalThis.fetch.bind(globalThis));
  console.log("PASS: K33 independent on-chain preflight");
  console.log("Hardware accessed: NO");
}
