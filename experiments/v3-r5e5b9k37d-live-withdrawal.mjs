import assert from "node:assert/strict";
import { timingSafeEqual, createHash } from "node:crypto";
import {
  readFileSync, writeFileSync, readSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  decodeEventLog,
  decodeFunctionData,
  decodeFunctionResult,
  encodeFunctionData,
  getAddress,
  isAddressEqual,
  parseAbi,
} from "viem";

import { Prover } from
  "@fatsolutions/privacy-pools-core-circuits";
import * as snarkjs from "snarkjs";
import {
  serializeTransaction,
  parseTransaction,
  keccak256,
} from "viem";
import { buildBn128, Scalar, utils as ffUtils } from "ffjavascript";
import { WithdrawSignalMapper } from
  "./node_modules/@fatsolutions/privacy-pools-core-circuits/dist/types.js";

import {
  createKeycardR3CredentialProvider,
} from "./src/utils/keycard-r3-credentials.ts";

import {
  POOL_EVENTS_SIGNATURES,
} from "../kohaku-sdk-research/packages/privacy-pools/src/data/abis/events.abi.ts";

import {
  OxBowAspService,
} from "../kohaku-sdk-research/packages/privacy-pools/src/data/0xbowAsp.service.ts";

import {
  computeMerkleTreeRoot,
  generateMerkleProof,
  calculateContext,
} from "../kohaku-sdk-research/packages/privacy-pools/src/utils/proof.util.ts";

import {
  commitment,
} from "../kohaku-sdk-research/packages/privacy-pools/src/utils.ts";

// The physical Go bridge executes this source
// through Node stdin. import.meta.url therefore
// identifies [eval1], not the experiments file.
const repo = process.cwd();

// Capture the native fetch before the proving
// phase restricts globalThis.fetch to local artifacts.
// Only the explicit eth_call simulator may use it.
const publicReadOnlyFetch =
  globalThis.fetch.bind(globalThis);

import {
  encodePoolWithdraw,
} from "../kohaku-sdk-research/packages/privacy-pools/src/paymaster/adapter-data.ts";

import {
  poolAbi,
} from "../kohaku-sdk-research/packages/privacy-pools/src/data/abis/pool.abi.ts";

const work = join(
  homedir(),
  "Library/Application Support/KohakuKeyResearch/v3-r5e9i-parser-fix"
);

const outputPath = join(
  work, "r5-e5b9k37d-withdrawal-confirmed.json"
);

const artifactRoot = join(
  repo,
  "node_modules/kohaku-artifacts/artifacts/privacy-pools"
);

const expectedHashes = {
  "build/withdraw/withdraw_js/withdraw.wasm":
    "36cda22791def3d520a55c0fc808369cd5849532a75fab65686e666ed3d55c10",
  "trusted-setup/final-keys/withdraw.zkey":
    "2a893b42174c813566e5c40c715a8b90cd49fc4ecf384e3a6024158c3d6de677",
  "trusted-setup/final-keys/withdraw.vkey":
    "666bd0983b20c1611543b04f7712e067fbe8cad69f07ada8a310837ff398d21e",
};

const providers = [
  "https://ethereum-sepolia-rpc.publicnode.com",
  "https://sepolia.gateway.tenderly.co",
];

const load = name => JSON.parse(
  readFileSync(join(work, name), "utf8")
);

async function rpc(url, method, params = []) {
  assert.ok(new Set([
    "eth_chainId",
    "eth_getTransactionReceipt",
    "eth_call",
  ]).has(method));

  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    }),
    signal: AbortSignal.timeout(15000),
  });

  assert.ok(response.ok, "Public RPC unavailable");

  const body = await response.json();

  assert.ok(!body.error && body.result !== undefined,
    "Public RPC returned an error");

  return body.result;
}

async function readContract(url, address, abi, name) {
  const result = await rpc(url, "eth_call", [{
    to: address,
    data: encodeFunctionData({
      abi,
      functionName: name,
    }),
  }, "latest"]);

  return decodeFunctionResult({
    abi,
    functionName: name,
    data: result,
  });
}

function acquireRoots() {
  const payload = Buffer.alloc(64);

  try {
    let offset = 0;

    while (offset < payload.length) {
      const n = readSync(
        3, payload, offset,
        payload.length - offset, null
      );

      assert.ok(n > 0, "Incomplete hardware IPC");
      offset += n;
    }

    return [
      Buffer.from(payload.subarray(0, 32)),
      Buffer.from(payload.subarray(32, 64)),
    ];
  } finally {
    payload.fill(0);
  }
}

function verifyPinnedArtifacts() {
  for (const [name, expected] of
    Object.entries(expectedHashes)) {
    const actual = createHash("sha256")
      .update(readFileSync(join(artifactRoot, name)))
      .digest("hex");

    assert.equal(
      actual, expected,
      "Pinned proof artifact mismatch"
    );
  }
}

async function preparePublicInputs() {
  const k32 = load(
    "r5-e5b9k32-publicnode-broadcast.json"
  );

  const k33 = load(
    "r5-e5b9k33-recovery.json"
  );

  const k35e = load(
    "r5-e5b9k35e-state-witness.json"
  );

  assert.equal(k32.status, "confirmed");
  assert.equal(k32.receiptVerified, true);
  assert.equal(k33.credentialReproduced, true);
  assert.equal(k35e.inclusionWitnessReady, true);
  assert.equal(k35e.compressedPathVerified, true);
  assert.equal(
    k35e.reconstructedRootMatchedOnchain,
    true
  );

  assert.equal(
    k32.transactionHash.toLowerCase(),
    k35e.transactionHash.toLowerCase()
  );

  const pool = getAddress(k32.depositEventPool);
  const entrypoint = getAddress(k32.entrypoint);

  assert.ok(isAddressEqual(pool, k35e.pool));
  assert.equal(k35e.stateLeafPosition, 1479);
  assert.equal(k35e.leafInsertedEventIndex, "1480");
  assert.equal(k35e.stateSiblings.length, 32);
  assert.equal(
    k35e.netDepositValueWei,
    "1980000000000000"
  );

  const poolAbi = parseAbi([
    "function SCOPE() view returns (uint256)",
    "function currentRoot() view returns (uint256)",
  ]);

  const entrypointAbi = parseAbi([
    "function latestRoot() view returns (uint256)",
  ]);

  const observations = [];

  for (const url of providers) {
    const [chain, receipt, scope, stateRoot, aspRoot] =
      await Promise.all([
        rpc(url, "eth_chainId"),
        rpc(url, "eth_getTransactionReceipt",
          [k32.transactionHash]),
        readContract(url, pool, poolAbi, "SCOPE"),
        readContract(url, pool, poolAbi, "currentRoot"),
        readContract(
          url, entrypoint, entrypointAbi, "latestRoot"
        ),
      ]);

    assert.equal(BigInt(chain), 11155111n);
    assert.ok(receipt);
    assert.equal(receipt.status, "0x1");
    assert.equal(
      receipt.blockHash.toLowerCase(),
      k32.blockHash.toLowerCase()
    );

    const log = receipt.logs.find(item =>
      isAddressEqual(item.address, pool) &&
      BigInt(item.logIndex).toString() ===
        k32.depositEventLogIndex
    );

    assert.ok(log, "Mined deposit event missing");

    const event = decodeEventLog({
      abi: [POOL_EVENTS_SIGNATURES.PoolDeposited],
      topics: log.topics,
      data: log.data,
      strict: true,
    });

    assert.equal(
      event.args._value,
      1980000000000000n
    );

    assert.equal(
      stateRoot,
      BigInt(k35e.stateRoot),
      "State root advanced; refresh K35-E"
    );

    assert.ok(aspRoot > 0n);

    observations.push({
      scope, stateRoot, aspRoot, event,
    });
  }

  const first = observations[0];

  for (const other of observations.slice(1)) {
    assert.equal(other.scope, first.scope);
    assert.equal(other.stateRoot, first.stateRoot);
    assert.equal(other.aspRoot, first.aspRoot);
    assert.equal(
      other.event.args._precommitment,
      first.event.args._precommitment
    );
    assert.equal(
      other.event.args._label,
      first.event.args._label
    );
  }

  const aspService = new OxBowAspService({
    network: {
      fetch: globalThis.fetch.bind(globalThis),
    },
    aspUrl: "https://dw.0xbow.io",
  });

  const tree = await aspService.getAspTreeOxBow({
    chainId: 11155111n,
    scope: first.scope,
  });

  const leaves = tree[0];

  assert.ok(Array.isArray(leaves) && leaves.length > 0);

  const rebuiltAspRoot =
    await computeMerkleTreeRoot(leaves);

  assert.equal(
    rebuiltAspRoot, first.aspRoot,
    "ASP leaves differ from on-chain root"
  );

  const aspWitness = await generateMerkleProof(
    leaves,
    first.event.args._label
  );

  assert.equal(aspWitness.root, first.aspRoot);
  assert.equal(aspWitness.siblings.length, 32);

  console.log("PASS: Two RPC providers agree");
  console.log("PASS: State root matches K35-E");
  console.log("PASS: Deposit belongs to current ASP");
  console.log("PASS: Both public witnesses ready");

  return {
    k32,
    k35e,
    pool,
    entrypoint,
    scope: first.scope,
    event: first.event,
    aspRoot: first.aspRoot,
    aspWitness,
  };
}

function configureLocalArtifactsOnly() {
  const baseUrl =
    "https://artifacts.0000000000.org/privacy-pools/";

  const circuitPaths = {
    withdraw: {
      wasm: "build/withdraw/withdraw_js/withdraw.wasm",
      vkey: "trusted-setup/final-keys/withdraw.vkey",
      zkey: "trusted-setup/final-keys/withdraw.zkey",
    },
    commitment: {
      wasm:
        "build/commitment/commitment_js/commitment.wasm",
      vkey: "trusted-setup/final-keys/commitment.vkey",
      zkey: "trusted-setup/final-keys/commitment.zkey",
    },
  };

  const allowed = new Set(
    Object.values(circuitPaths).flatMap(
      paths => Object.values(paths)
    )
  );

  globalThis.fetch = async input => {
    const url = new URL(String(input));

    assert.ok(
      url.href.startsWith(baseUrl),
      "Network access prohibited during proving"
    );

    const relative = url.href.slice(baseUrl.length);

    assert.ok(
      allowed.has(relative),
      "Unexpected proving artifact request"
    );

    return new Response(
      readFileSync(join(artifactRoot, relative)),
      { status: 200 }
    );
  };

  return {
    baseUrl,
    ...circuitPaths,
  };
}


// Explicit single-thread implementation of the
// Groth16 verification equation used by snarkjs.
// No worker threads, global curve cache or RPC.
async function verifyGroth16SingleThread(
  verificationKey,
  signals,
  groth16Proof
) {
  const vk = ffUtils.unstringifyBigInts(verificationKey);
  const inputs = ffUtils.unstringifyBigInts(signals);
  const proof = ffUtils.unstringifyBigInts(groth16Proof);

  assert.equal(vk.protocol, "groth16");
  assert.ok(
    ["bn128", "bn254", "altbn128"].includes(
      String(vk.curve).toLowerCase()
    )
  );

  assert.equal(inputs.length, 8);
  assert.equal(vk.IC.length, inputs.length + 1);

  const curve = await buildBn128(true);

  try {
    for (const input of inputs) {
      if (
        !Scalar.geq(input, 0n) ||
        !Scalar.lt(input, curve.r)
      ) {
        return false;
      }
    }

    const g1Bytes = curve.G1.F.n8 * 2;
    const scalarBytes = curve.Fr.n8;

    const points = new Uint8Array(
      g1Bytes * inputs.length
    );

    const scalars = new Uint8Array(
      scalarBytes * inputs.length
    );

    for (let i = 0; i < inputs.length; i++) {
      points.set(
        curve.G1.fromObject(vk.IC[i + 1]),
        i * g1Bytes
      );

      Scalar.toRprLE(
        scalars,
        i * scalarBytes,
        inputs[i],
        scalarBytes
      );
    }

    let publicCommitment =
      await curve.G1.multiExpAffine(
        points, scalars
      );

    publicCommitment = curve.G1.add(
      publicCommitment,
      curve.G1.fromObject(vk.IC[0])
    );

    const a = curve.G1.fromObject(proof.pi_a);
    const b = curve.G2.fromObject(proof.pi_b);
    const c = curve.G1.fromObject(proof.pi_c);

    if (
      !curve.G1.isValid(a) ||
      !curve.G2.isValid(b) ||
      !curve.G1.isValid(c)
    ) {
      return false;
    }

    return await curve.pairingEq(
      curve.G1.neg(a),
      b,
      publicCommitment,
      curve.G2.fromObject(vk.vk_gamma_2),
      c,
      curve.G2.fromObject(vk.vk_delta_2),
      curve.G1.fromObject(vk.vk_alpha_1),
      curve.G2.fromObject(vk.vk_beta_2)
    );
  } finally {
    await curve.terminate();
  }
}

// Explicit allowlisted JSON-RPC read; never signs,
// sends, or writes a transaction.
async function simulateDirectWithdrawal(
  providerUrl, poolAddress, sender, calldata
) {
  assert.ok(providers.includes(providerUrl));

  const response = await publicReadOnlyFetch(
    providerUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 36,
        method: "eth_call",
        params: [{
          from: sender,
          to: poolAddress,
          data: calldata,
          value: "0x0",
          gas: "0x989680",
        }, "latest"],
      }),
      signal: AbortSignal.timeout(45000),
    }
  );

  const payload = await response.json();

  if (!response.ok || payload.error ||
      typeof payload.result !== "string") {
    // Never print raw RPC error.data or calldata.
    const code = payload.error?.code ??
      response.status;
    throw new Error(
      `Direct withdraw eth_call rejected by ` +
      `${new URL(providerUrl).hostname} ` +
      `(code ${code})`
    );
  }

  // pool.withdraw() has no return values.
  assert.equal(
    payload.result,
    "0x",
    "Unexpected withdrawal simulation return"
  );

  return new URL(providerUrl).hostname;
}

// Restricted public RPC access for transaction
// preparation. Never submits a transaction.
const txReadMethods = new Set([
  "eth_chainId",
  "eth_getBalance",
  "eth_getTransactionCount",
  "eth_getBlockByNumber",
  "eth_gasPrice",
  "eth_estimateGas",
]);

async function txReadRpc(url, method, params = []) {
  assert.ok(providers.includes(url));
  assert.ok(
    txReadMethods.has(method),
    "Transaction RPC method prohibited"
  );

  const response = await publicReadOnlyFetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 37,
      method,
      params,
    }),
    signal: AbortSignal.timeout(45000),
  });

  assert.ok(response.ok, "Read-only RPC unavailable");

  const body = await response.json();

  assert.ok(
    !body.error && body.result !== undefined,
    "Read-only RPC rejected request"
  );

  return body.result;
}

async function prepareUnsignedWithdrawal({
  pool, sender, calldata,
}) {
  const observations = [];

  for (const url of providers) {
    const [
      chain,
      pendingNonce,
      latestNonce,
      balance,
      estimatedGas,
      gasPrice,
      block,
    ] = await Promise.all([
      txReadRpc(url, "eth_chainId"),
      txReadRpc(url, "eth_getTransactionCount",
        [sender, "pending"]),
      txReadRpc(url, "eth_getTransactionCount",
        [sender, "latest"]),
      txReadRpc(url, "eth_getBalance",
        [sender, "latest"]),
      txReadRpc(url, "eth_estimateGas", [{
        from: sender,
        to: pool,
        data: calldata,
        value: "0x0",
      }]),
      txReadRpc(url, "eth_gasPrice"),
      txReadRpc(url, "eth_getBlockByNumber",
        ["latest", false]),
    ]);

    assert.equal(BigInt(chain), 11155111n);

    // K32 consumed nonce zero. Any unexpected
    // activity must block transaction preparation.
    assert.equal(BigInt(pendingNonce), 1n);
    assert.equal(BigInt(latestNonce), 1n);

    assert.ok(block?.baseFeePerGas != null);

    const sample = {
      provider: new URL(url).hostname,
      nonce: BigInt(pendingNonce),
      balance: BigInt(balance),
      estimatedGas: BigInt(estimatedGas),
      gasPrice: BigInt(gasPrice),
      baseFee: BigInt(block.baseFeePerGas),
      blockNumber: BigInt(block.number),
    };

    assert.ok(sample.estimatedGas > 0n);
    assert.ok(sample.estimatedGas < 8000000n);
    assert.ok(sample.gasPrice > 0n);

    observations.push(sample);

    console.log(
      "PASS: Gas estimate and nonce verified by",
      sample.provider
    );
  }

  console.log("K37-B public RPC quotes:",
    observations.map(x => ({
      provider: x.provider,
      estimatedGas: x.estimatedGas.toString(),
      gasPriceWei: x.gasPrice.toString(),
      baseFeeWei: x.baseFee.toString(),
      balanceWei: x.balance.toString(),
      nonce: x.nonce.toString(),
    })));
  assert.equal(observations.length, 2);

  const maxEstimate = observations.reduce(
    (max, item) =>
      item.estimatedGas > max
        ? item.estimatedGas : max,
    0n
  );

  const maxBaseFee = observations.reduce(
    (max, item) =>
      item.baseFee > max ? item.baseFee : max,
    0n
  );

  const maxGasPrice = observations.reduce(
    (max, item) =>
      item.gasPrice > max ? item.gasPrice : max,
    0n
  );

  // 20% estimate headroom plus 50,000 gas.
  const gas = maxEstimate +
    maxEstimate / 5n + 50000n;

  console.log("CHECK: Gas limit:", gas.toString());
  assert.ok(gas < 10000000n,
    "Gas limit exceeds 10M ceiling");
  console.log("PASS: Gas limit ceiling");

  const priority =
    maxGasPrice > maxBaseFee
      ? maxGasPrice - maxBaseFee
      : 1n;

  const maxFeePerGas =
    maxBaseFee * 2n + priority;

  assert.ok(priority > 0n);
  assert.ok(maxFeePerGas >= priority);
  console.log("CHECK: Max fee per gas (wei):",
    maxFeePerGas.toString());
  assert.ok(maxFeePerGas <= 100000000000n,
    "Fee per gas exceeds 100 gwei ceiling");
  console.log("PASS: Fee per gas ceiling");

  const gasBudget = gas * maxFeePerGas;

  // Hard fail if the maximum gas exposure
  // exceeds 0.02 Sepolia ETH.
  console.log("CHECK: Maximum gas budget (wei):",
    gasBudget.toString());
  console.log("CHECK: Gas budget cap (wei):",
    "20000000000000000");

  assert.ok(
    gasBudget <= 20000000000000000n,
    "Gas budget exceeds checkpoint safety cap"
  );

  console.log("PASS: Gas budget safety cap");

  for (const sample of observations) {
    assert.ok(
      sample.balance >= gasBudget,
      "Insufficient signer gas balance"
    );
  }

  const transaction = {
    type: "eip1559",
    chainId: 11155111,
    nonce: 1,
    to: pool,
    value: 0n,
    gas,
    maxFeePerGas,
    maxPriorityFeePerGas: priority,
    data: calldata,
  };

  // This transaction is NEVER signed or
  // serialized to a file.
  const unsigned = serializeTransaction(transaction);
  const parsed = parseTransaction(unsigned);

  console.log("CHECK: Unsigned transaction fields:", {
    type: parsed.type,
    chainId: parsed.chainId,
    nonce: parsed.nonce,
    gasMatches: parsed.gas === gas,
    value: String(parsed.value),
    recipientMatches:
      parsed.to?.toLowerCase() === pool.toLowerCase(),
    calldataMatches: parsed.data === calldata,
  });

  assert.equal(parsed.type, "eip1559");
  assert.equal(parsed.chainId, 11155111);
  assert.equal(parsed.nonce, 1);
  assert.equal(parsed.gas, gas);
  assert.equal(transaction.value, 0n);
  assert.equal(
    parsed.value ?? 0n,
    0n,
    "Unsigned transaction must transfer zero ETH"
  );
  assert.equal(
    parsed.to.toLowerCase(),
    pool.toLowerCase()
  );
  assert.ok(
    parsed.data === calldata,
    "Unsigned calldata mismatch"
  );

  const digest = keccak256(unsigned);

  console.log("\n=== Unsigned transaction review ===");
  console.log("Chain: Sepolia (11155111)");
  console.log("From:", sender);
  console.log("To:", pool);
  console.log("Nonce: 1");
  console.log("Transaction value: 0 ETH");
  console.log("Privacy Pools withdrawal: 0.00099 ETH");
  console.log("Remaining private note: 0.00099 ETH");
  console.log("Maximum gas:", gas.toString());
  console.log(
    "Maximum fee per gas (wei):",
    maxFeePerGas.toString()
  );
  console.log(
    "Maximum total gas cost (wei):",
    gasBudget.toString()
  );
  console.log("Unsigned digest:", digest);
  console.log("Signing: REQUIRES EXPLICIT SIGN APPROVAL");
  console.log("Broadcasting: DISABLED");

  return {
    transaction,
    digest,
    unsigned,
    review: {
    providers: observations.map(item => item.provider),
    nonce: "1",
    gasEstimate: maxEstimate.toString(),
    gasLimit: gas.toString(),
    maxFeePerGas: maxFeePerGas.toString(),
    maxPriorityFeePerGas: priority.toString(),
    gasBudgetWei: gasBudget.toString(),
    unsignedTransactionValidated: true,
    },
  };
}


// K37-D: One-shot Sepolia withdrawal broadcaster.
//
// The live proof, calldata, signed transaction and
// hardware-derived secrets remain in process memory.
// Only public transaction status is journaled.

const k37dJournalPath = join(
  work, "r5-e5b9k37d-submission-journal.json"
);

const k37dReadMethods = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getBalance",
  "eth_getTransactionCount",
  "eth_getCode",
  "eth_call",
  "eth_estimateGas",
  "eth_getTransactionReceipt",
  "eth_getTransactionByHash",
]);

async function k37dRpc(
  url, method, params = [], broadcastApproved = false
) {
  assert.ok(providers.includes(url));

  if (method === "eth_sendRawTransaction") {
    assert.equal(
      broadcastApproved,
      true,
      "Explicit BROADCAST approval required"
    );
  } else {
    assert.ok(
      k37dReadMethods.has(method),
      "RPC method not allowlisted"
    );
  }

  const response = await publicReadOnlyFetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 37,
      method,
      params,
    }),
    signal: AbortSignal.timeout(45000),
  });

  const host = new URL(url).hostname;

  if (!response.ok) {
    console.error(
      "FAIL: Final RPC HTTP status",
      host, method, response.status
    );
    throw new Error("Sepolia RPC unavailable");
  }

  const body = await response.json();

  if (body.error || !Object.hasOwn(body, "result")) {
    console.error(
      "FAIL: Final RPC method",
      host, method,
      "code:", body.error?.code ?? "missing-result"
    );
    throw new Error("Sepolia RPC rejected read");
  }

  return body.result;
}

async function k37dBroadcastApproval({
  transactionHash,
  sender,
  pool,
  transaction,
}) {
  const {
    openSync, readSync, writeSync, closeSync,
  } = await import("node:fs");

  const fd = openSync("/dev/tty", "r+");

  try {
    const maxGasBudget =
      transaction.gas * transaction.maxFeePerGas;

    const review = [
      "",
      "=== K37-D FINAL BROADCAST APPROVAL ===",
      "This submits a REAL Sepolia transaction.",
      "It will spend the existing Privacy Pools note.",
      "Chain: Sepolia (11155111)",
      `Signer / processooor: ${sender}`,
      `Pool: ${pool}`,
      "Withdrawal: 0.00099 Sepolia ETH",
      "Remaining private change note: 0.00099 ETH",
      `Nonce: ${transaction.nonce}`,
      `Gas limit: ${transaction.gas}`,
      `Maximum gas budget (wei): ${maxGasBudget}`,
      `Transaction hash: ${transactionHash}`,
      "The original depositor address is publicly linkable.",
      "Proof and transaction signature already verified.",
      "",
      "Type BROADCAST to submit; anything else cancels: ",
    ].join("\n");

    writeSync(fd, Buffer.from(review));

    let response = "";
    const byte = Buffer.alloc(1);

    while (response.length < 32) {
      const count = readSync(
        fd, byte, 0, 1, null
      );

      assert.equal(
        count, 1,
        "Broadcast approval input unavailable"
      );

      const char = String.fromCharCode(byte[0]);

      if (char === "\n") break;
      if (char !== "\r") response += char;
    }

    writeSync(fd, Buffer.from("\n"));

    assert.equal(
      response,
      "BROADCAST",
      "Broadcast authorization declined"
    );

    console.log(
      "PASS: Separate explicit BROADCAST authorization"
    );
  } finally {
    closeSync(fd);
  }
}

async function k37dSubmitVerifiedWithdrawal({
  signed,
  transaction,
  calldata,
  sender,
  pool,
  mapped,
}) {
  const {
    existsSync, writeFileSync, renameSync,
  } = await import("node:fs");

  const {
    decodeEventLog,
    encodeFunctionData,
    parseAbi,
    parseAbiItem,
    recoverTransactionAddress,
    toEventSelector,
    toHex,
  } = await import("viem");

  // Any previous attempt, including an ambiguous
  // RPC failure, must be reconciled before retrying.
  assert.equal(
    existsSync(k37dJournalPath),
    false,
    "Prior K37-D journal exists: reconcile before retry"
  );

  assert.equal(transaction.chainId, 11155111);
  assert.equal(transaction.type, "eip1559");
  assert.equal(transaction.nonce, 1);
  assert.equal(transaction.value, 0n);
  assert.ok(isAddressEqual(transaction.to, pool));
  assert.equal(transaction.data, calldata);

  const recovered = await recoverTransactionAddress({
    serializedTransaction: signed,
  });

  assert.ok(isAddressEqual(recovered, sender));

  assert.equal(
    mapped.withdrawnValue,
    990000000000000n
  );

  const txHash = keccak256(signed);

  stage = "explicit-broadcast-approval";

  await k37dBroadcastApproval({
    transactionHash: txHash,
    sender,
    pool,
    transaction,
  });

  stage = "final-live-recheck";

  console.log(
    "STAGE: Final live verification after approval"
  );

  const maximumGasBudget =
    transaction.gas * transaction.maxFeePerGas;

  assert.ok(
    maximumGasBudget <= 20000000000000000n
  );

  for (const url of providers) {
    const [
      chain,
      latestNonce,
      pendingNonce,
      balance,
      code,
      block,
      currentStateRoot,
      currentAspRoot,
      simulated,
      estimated,
    ] = await Promise.all([
      k37dRpc(url, "eth_chainId"),

      k37dRpc(url, "eth_getTransactionCount",
        [sender, "latest"]),

      k37dRpc(url, "eth_getTransactionCount",
        [sender, "pending"]),

      k37dRpc(url, "eth_getBalance",
        [sender, "latest"]),

      k37dRpc(url, "eth_getCode",
        [pool, "latest"]),

      k37dRpc(url, "eth_getBlockByNumber",
        ["latest", false]),

      k37dRpc(url, "eth_call", [{
        to: pool,
        data: encodeFunctionData({
          abi: parseAbi([
            "function currentRoot() view returns (uint256)"
          ]),
          functionName: "currentRoot",
        }),
      }, "latest"]),

      k37dRpc(url, "eth_call", [{
        to: "0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB",
        data: encodeFunctionData({
          abi: parseAbi([
            "function latestRoot() view returns (uint256)"
          ]),
          functionName: "latestRoot",
        }),
      }, "latest"]),

      k37dRpc(url, "eth_call", [{
        from: sender,
        to: pool,
        data: calldata,
        value: "0x0",
        gas: toHex(transaction.gas),
      }, "latest"]),

      k37dRpc(url, "eth_estimateGas", [{
        from: sender,
        to: pool,
        data: calldata,
        value: "0x0",
      }]),
    ]);

    assert.equal(BigInt(chain), 11155111n);
    assert.equal(BigInt(latestNonce), 1n);
    assert.equal(BigInt(pendingNonce), 1n);

    assert.ok(
      BigInt(balance) >= maximumGasBudget
    );

    assert.ok(code !== "0x");

    assert.ok(block?.baseFeePerGas != null);

    assert.ok(
      BigInt(block.baseFeePerGas) +
        transaction.maxPriorityFeePerGas <=
      transaction.maxFeePerGas,
      "Signed EIP-1559 fee cap is stale"
    );

    assert.equal(
      BigInt(currentStateRoot),
      mapped.stateRoot,
      "Pool root changed since proof generation"
    );

    assert.equal(
      BigInt(currentAspRoot),
      mapped.ASPRoot,
      "ASP root changed since proof generation"
    );

    assert.equal(
      simulated,
      "0x",
      "Live withdrawal simulation failed"
    );

    assert.ok(
      BigInt(estimated) <= transaction.gas,
      "Live gas estimate exceeds signed limit"
    );

    console.log(
      "PASS: Final nonce, roots, gas, and simulation:",
      new URL(url).hostname
    );
  }

  const publicJournal = {
    checkpoint: "R5-E5B9K37D-live-withdrawal",
    status: "submission_attempted",
    chainId: 11155111,
    transactionHash: txHash,
    sender,
    pool,
    nonce: 1,
    withdrawnValueWei: mapped.withdrawnValue.toString(),
    signedTransactionPersisted: false,
    privateWitnessPersisted: false,
  };

  function updateJournal(status, fields = {}) {
    const record = {
      ...publicJournal,
      status,
      ...fields,
    };

    const temporary = k37dJournalPath + ".updating";

    writeFileSync(
      temporary,
      JSON.stringify(record, null, 2),
      { mode: 0o600, flag: "wx" }
    );

    renameSync(temporary, k37dJournalPath);
  }

  // This is the irreversible submission boundary.
  // Persist the PUBLIC hash first. If RPC returns an
  // ambiguous error, never automatically resubmit.
  writeFileSync(
    k37dJournalPath,
    JSON.stringify(publicJournal, null, 2),
    { mode: 0o600, flag: "wx" }
  );

  stage = "sepolia-transaction-submission";

  console.log("STAGE: Submit signed withdrawal");
  console.log("Transaction hash:", txHash);

  let returnedHash;

  try {
    returnedHash = await k37dRpc(
      providers[0],
      "eth_sendRawTransaction",
      [signed],
      true
    );
  } catch {
    throw new Error(
      "Submission result uncertain. Check the journal " +
      "and transaction hash before any retry."
    );
  }

  assert.equal(
    returnedHash.toLowerCase(),
    txHash.toLowerCase(),
    "Unexpected RPC transaction hash"
  );

  updateJournal("submitted");

  console.log(
    "PASS: Sepolia RPC accepted signed withdrawal"
  );

  stage = "withdrawal-receipt-verification";

  let receipts = null;

  for (let attempt = 0; attempt < 36; attempt++) {
    const current = await Promise.all(
      providers.map(url =>
        k37dRpc(
          url,
          "eth_getTransactionReceipt",
          [txHash]
        )
      )
    );

    if (current.every(receipt => receipt !== null)) {
      receipts = current;
      break;
    }

    if ((attempt + 1) % 6 === 0) {
      console.log(
        "STAGE: Awaiting withdrawal receipt consensus"
      );
    }

    await new Promise(resolve =>
      setTimeout(resolve, 5000)
    );
  }

  assert.ok(
    receipts && receipts.length === 2,
    "Receipt pending: reconcile transaction hash"
  );

  assert.equal(
    receipts[0].blockHash.toLowerCase(),
    receipts[1].blockHash.toLowerCase(),
    "RPC providers disagree on mined block"
  );

  for (const receipt of receipts) {
    assert.ok(
      isAddressEqual(receipt.from, sender)
    );
    assert.ok(
      isAddressEqual(receipt.to, pool)
    );
    assert.equal(
      receipt.transactionHash.toLowerCase(),
      txHash.toLowerCase()
    );

    if (receipt.status !== "0x1") {
      updateJournal("mined_reverted", {
        blockNumber:
          BigInt(receipt.blockNumber).toString(),
      });

      throw new Error(
        "Withdrawal mined but reverted"
      );
    }
  }

  const withdrawnEvent = parseAbiItem(
    "event Withdrawn(address indexed _processooor, " +
    "uint256 _value, uint256 _spentNullifier, " +
    "uint256 _newCommitment)"
  );

  const eventTopic =
    toEventSelector(withdrawnEvent).toLowerCase();

  for (const receipt of receipts) {
    const matchingLogs = receipt.logs.filter(log =>
      isAddressEqual(log.address, pool) &&
      log.topics?.[0]?.toLowerCase() === eventTopic
    );

    assert.equal(
      matchingLogs.length, 1,
      "Expected exactly one pool Withdrawn event"
    );

    const decoded = decodeEventLog({
      abi: [withdrawnEvent],
      data: matchingLogs[0].data,
      topics: matchingLogs[0].topics,
      strict: true,
    });

    assert.equal(decoded.eventName, "Withdrawn");

    assert.ok(isAddressEqual(
      decoded.args._processooor,
      sender
    ));

    assert.equal(
      decoded.args._value,
      mapped.withdrawnValue
    );

    assert.equal(
      decoded.args._spentNullifier,
      mapped.existingNullifierHash
    );

    assert.equal(
      decoded.args._newCommitment,
      mapped.newCommitmentHash
    );
  }

  const blockNumber =
    BigInt(receipts[0].blockNumber).toString();

  updateJournal("confirmed", {
    blockNumber,
    receiptVerified: true,
    withdrawnEventVerified: true,
  });

  console.log(
    "PASS: Withdrawal mined in block",
    blockNumber
  );
  console.log(
    "PASS: Two RPC providers verified receipt"
  );
  console.log(
    "PASS: Spent nullifier matches verified proof"
  );
  console.log(
    "PASS: Change commitment matches verified proof"
  );

  return {
    transactionHash: txHash,
    blockNumber,
    receiptVerified: true,
    receiptProviderAgreement: true,
    withdrawnEventVerified: true,
    spentNullifierVerifiedOnChain: true,
    changeCommitmentVerifiedOnChain: true,
    transactionSubmissionStatus: "confirmed",
  };
}

let stage = "preflight";

async function main() {
  verifyPinnedArtifacts();

  stage = "public-witness-verification";
  const publicInputs = await preparePublicInputs();

  // Dry-run the exact stdin import environment
  // without accessing hardware IPC or secrets.
  if (process.argv.includes("--public-preflight")) {
    assert.ok(publicInputs.aspWitness);
    console.log("PASS: All Node imports resolved");
    console.log("PASS: Pinned artifacts verified");
    console.log("PASS: Live state and ASP roots verified");
    console.log("Hardware accessed: NO");
    console.log("Private credentials accessed: NO");
    console.log("Groth16 proof generated: NO");
    return;
  }

  // No remote requests are allowed after this point.
  stage = "offline-prover-configuration";
  const options = configureLocalArtifactsOnly();

  if (process.argv.includes("--prover-preflight")) {
    // Exercise real circuit initialization without
    // physical hardware or private inputs.
    const keepAlive = setInterval(() => {}, 1000);
    const watchdog = setTimeout(() => {
      console.error(
        "FAIL: Offline prover initialization unresolved"
      );
      process.exit(70);
    }, 60000);

    try {
      console.log("STAGE: Initializing local Groth16 prover");

      const localProver = await Prover(options);

      console.log("PASS: Local prover initialized");

      const vkey = await localProver.circuits
        .getVerificationKey("withdraw");

      assert.equal(vkey.byteLength, 4208);

      console.log("PASS: Withdrawal verification key loaded");
      console.log("PASS: No network fetches");
      console.log("Hardware accessed: NO");
      console.log("Private witness accessed: NO");
    } finally {
      clearTimeout(watchdog);
      clearInterval(keepAlive);
    }

    return;
  }

  let rootA;
  let rootB;
  let providerA;
  let providerB;
  let proofKeepAlive;

  try {
    stage = "physical-keycard-recovery";
    [rootA, rootB] = acquireRoots();

    assert.ok(
      timingSafeEqual(rootA, rootB),
      "Independent hardware roots differ"
    );

    const accountIndex = 0;

    providerA = createKeycardR3CredentialProvider(
      rootA, { accountIndex }
    );

    providerB = createKeycardR3CredentialProvider(
      rootB, { accountIndex }
    );

    const coordinates = {
      chainId: 11155111n,
      entrypointAddress: BigInt(
        publicInputs.entrypoint
      ),
      depositIndex: 17,
    };

    const existingA = await providerA.secretManager
      .getDepositSecrets(coordinates);

    const existingB = await providerB.secretManager
      .getDepositSecrets(coordinates);

    for (const field of [
      "nullifier", "salt",
      "precommitment", "nullifierHash",
    ]) {
      assert.equal(
        existingA[field], existingB[field],
        "Independent credential mismatch"
      );
    }

    const { event } = publicInputs;

    assert.equal(
      existingA.precommitment,
      event.args._precommitment,
      "Recovered credential does not own mined note"
    );

    assert.equal(
      commitment({
        balance: event.args._value,
        label: event.args._label,
        precommitment: existingA.precommitment,
      }),
      event.args._commitment
    );

    const changeCoordinates = {
      ...coordinates,
      withdrawIndex: 1,
    };

    const changeA = await providerA.secretManager
      .getSecrets(changeCoordinates);

    const changeB = await providerB.secretManager
      .getSecrets(changeCoordinates);

    for (const field of [
      "nullifier", "salt",
      "precommitment", "nullifierHash",
    ]) {
      assert.equal(
        changeA[field], changeB[field],
        "Change-note credential mismatch"
      );
    }

    assert.notEqual(
      existingA.precommitment,
      changeA.precommitment
    );

    console.log(
      "PASS: Two-session deposit credential recovery"
    );
    console.log(
      "PASS: Hardware-derived change credential"
    );
    console.log(
      "PASS: Mined commitment rederived"
    );

    stage = "withdrawal-proof-generation";

    const withdrawnValue = 990000000000000n;
    const existingValue = event.args._value;
    const changeValue =
      existingValue - withdrawnValue;

    assert.equal(changeValue, 990000000000000n);

    const withdrawal = {
      processooor: getAddress(publicInputs.k32.sender),
      data: "0x",
    };

    const context = BigInt(calculateContext(
      withdrawal,
      publicInputs.scope
    ));

    const state = publicInputs.k35e;
    const asp = publicInputs.aspWitness;

    // Pending promises alone do not keep Node
    // alive. Keep a referenced event-loop handle
    // during snarkjs's worker-based proof lifecycle.
    proofKeepAlive = setInterval(() => {
      console.log(
        "PROVER ACTIVE:",
        stage,
        "(private inputs not logged)"
      );
    }, 30000);

    console.log("STAGE: Initialize Groth16 prover");
    const prover = await Prover(options);
    console.log("PASS: Groth16 prover initialized");

    console.log("STAGE: Generate Groth16 witness/proof");
    const signals = {
      context,
      label: event.args._label,

      existingNullifier: existingA.nullifier,
      existingSecret: existingA.salt,
      existingValue,

      newNullifier: changeA.nullifier,
      newSecret: changeA.salt,
      withdrawnValue,

      stateIndex: BigInt(state.stateIndex),
      stateRoot: BigInt(state.stateRoot),
      stateSiblings: state.stateSiblings.map(BigInt),
      stateTreeDepth: 32n,

      ASPIndex: BigInt(asp.index),
      ASPRoot: asp.root,
      ASPSiblings: asp.siblings,
      ASPTreeDepth: 32n,
    };

    // Keep the witness entirely in process memory.
    const witness = { type: "mem" };

    stage = "withdrawal-witness-calculation";
    console.log("STAGE: Calculate circuit witness");

    const wasm = await prover.circuits.getWasm("withdraw");

    const witnessWatchdog = setTimeout(() => {
      console.error("FAIL: Witness calculation stalled");
      process.exit(72);
    }, 240000);

    try {
      await snarkjs.wtns.calculate(
        signals,
        wasm,
        witness,
        { memorySize: 0 }
      );
    } finally {
      clearTimeout(witnessWatchdog);
    }

    console.log("PASS: Circuit witness calculated in memory");

    stage = "single-thread-groth16-proving";
    console.log("STAGE: Single-thread Groth16 proving");

    const zkey = await prover.circuits
      .getProvingKey("withdraw");

    const proofWatchdog = setTimeout(() => {
      console.error("FAIL: Groth16 proving stalled");
      process.exit(73);
    }, 480000);

    let proofResult;

    try {
      proofResult = await snarkjs.groth16.prove(
        zkey,
        witness,
        undefined,
        { singleThread: true }
      );
    } finally {
      clearTimeout(proofWatchdog);
    }

    const result = {
      ...proofResult,
      mappedSignals: WithdrawSignalMapper(
        proofResult.publicSignals
      ),
    };

    stage = "independent-groth16-verification";
    console.log("PASS: Groth16 proof generated");
    console.log("STAGE: Independent proof verification");

    assert.equal(result.publicSignals.length, 8);

    const mapped = result.mappedSignals;

    assert.equal(mapped.withdrawnValue, withdrawnValue);
    assert.equal(mapped.stateRoot, BigInt(state.stateRoot));
    assert.equal(mapped.ASPRoot, publicInputs.aspRoot);
    assert.equal(mapped.context, context);

    assert.equal(
      mapped.existingNullifierHash,
      existingA.nullifierHash
    );

    const expectedChangeCommitment = commitment({
      balance: changeValue,
      label: event.args._label,
      precommitment: changeA.precommitment,
    });

    assert.equal(
      mapped.newCommitmentHash,
      expectedChangeCommitment,
      "Change commitment mismatch"
    );

    const vkey = JSON.parse(readFileSync(
      join(
        artifactRoot,
        "trusted-setup/final-keys/withdraw.vkey"
      ),
      "utf8"
    ));

    stage = "independent-groth16-verification";
    console.log(
      "STAGE: Explicit single-thread Groth16 pairing verification"
    );

    const verifyWatchdog = setTimeout(() => {
      console.error("FAIL: Pairing verifier stalled");
      process.exit(74);
    }, 120000);

    let verified;

    try {
      verified = await verifyGroth16SingleThread(
        vkey,
        result.publicSignals,
        result.proof
      );
    } finally {
      clearTimeout(verifyWatchdog);
    }

    assert.equal(
      verified, true,
      "Groth16 proof failed verification"
    );

    // K36: contract-level simulation only.
    // This follows successful in-memory Groth16
    // verification, before evidence persistence.
    stage = "direct-withdrawal-calldata";

    const calldata = encodePoolWithdraw(
      withdrawal, result
    );

    const decoded = decodeFunctionData({
      abi: poolAbi,
      data: calldata,
    });

    assert.equal(decoded.functionName, "withdraw");

    assert.ok(isAddressEqual(
      decoded.args[0].processooor,
      publicInputs.k32.sender
    ));

    assert.equal(decoded.args[0].data, "0x");

    assert.equal(
      decoded.args[1].pubSignals.length, 8
    );

    for (let i = 0; i < 8; i++) {
      assert.equal(
        decoded.args[1].pubSignals[i],
        BigInt(result.publicSignals[i]),
        "Encoded proof public signal mismatch"
      );
    }

    console.log(
      "PASS: SDK direct-withdraw calldata encoded"
    );
    console.log(
      "PASS: Calldata public signals match verified proof"
    );

    stage = "sepolia-eth-call-simulation";

    const acceptedProviders = [];

    for (const url of providers) {
      const host = new URL(url).hostname;
      console.log("STAGE: eth_call on", host);

      acceptedProviders.push(
        await simulateDirectWithdrawal(
          url,
          publicInputs.pool,
          getAddress(publicInputs.k32.sender),
          calldata
        )
      );

      console.log("PASS: eth_call accepted by", host);
    }

    assert.equal(acceptedProviders.length, 2);

    console.log(
      "PASS: Both RPC providers accepted direct withdrawal"
    );
    console.log(
      "PASS: Withdrawal executed only in simulated EVM"
    );

    stage = "unsigned-eip1559-preparation";

    const unsignedReview =
      await prepareUnsignedWithdrawal({
        pool: publicInputs.pool,
        sender: getAddress(publicInputs.k32.sender),
        calldata,
      });

    console.log(
      "PASS: EIP-1559 unsigned transaction validated"
    );
    stage = "physical-keycard-signing";

    // Go provides three anonymous file descriptors:
    // FD3: BIP-85 roots received by Node
    // FD4: 32-byte digest sent to Go
    // FD5: 65-byte hardware signature returned to Node
    const {
      readSync: readSignature,
      writeSync: writeDigest,
    } = await import("node:fs");

    const digestBytes = Buffer.from(
      unsignedReview.digest.slice(2), "hex"
    );

    assert.equal(digestBytes.length, 32);
    assert.equal(
      keccak256(unsignedReview.unsigned),
      unsignedReview.digest
    );

    const written = writeDigest(
      4, digestBytes, 0, 32
    );

    digestBytes.fill(0);
    assert.equal(written, 32);

    console.log(
      "STAGE: Await explicit physical SIGN approval"
    );

    let broadcastResult;

    const signatureBytes = Buffer.alloc(65);

    try {
      let offset = 0;

      while (offset < signatureBytes.length) {
        const count = readSignature(
          5,
          signatureBytes,
          offset,
          signatureBytes.length - offset,
          null
        );

        assert.ok(
          count > 0,
          "Physical signature unavailable or declined"
        );

        offset += count;
      }

      assert.ok(signatureBytes[64] <= 1);

      const signature = {
        r: "0x" + signatureBytes
          .subarray(0, 32).toString("hex"),
        s: "0x" + signatureBytes
          .subarray(32, 64).toString("hex"),
        yParity: signatureBytes[64],
      };

      const signed = serializeTransaction(
        unsignedReview.transaction,
        signature
      );

      const parsed = parseTransaction(signed);

      assert.equal(parsed.type, "eip1559");
      assert.equal(parsed.chainId, 11155111);
      assert.equal(parsed.nonce, 1);
      assert.equal(parsed.value ?? 0n, 0n);
      assert.equal(
        parsed.data,
        calldata
      );
      assert.ok(isAddressEqual(
        parsed.to,
        publicInputs.pool
      ));

      const { recoverTransactionAddress } =
        await import("viem");

      const recovered =
        await recoverTransactionAddress({
          serializedTransaction: signed,
        });

      assert.ok(isAddressEqual(
        recovered,
        publicInputs.k32.sender
      ));

      console.log(
        "PASS: Physical Keycard transaction signed"
      );
      console.log(
        "PASS: Recovered signer matches original depositor"
      );
      console.log(
        "PASS: EIP-1559 chain, nonce, pool and calldata verified"
      );
      console.log(
        "PASS: Signed transaction held only in memory"
      );
      broadcastResult =
        await k37dSubmitVerifiedWithdrawal({
          signed,
          transaction: unsignedReview.transaction,
          calldata,
          sender: getAddress(publicInputs.k32.sender),
          pool: publicInputs.pool,
          mapped: result.mappedSignals,
        });

      assert.equal(
        broadcastResult.receiptVerified,
        true
      );
    } finally {
      signatureBytes.fill(0);
    }

    const evidence = {
      checkpoint: "R5-E5B9K37D-live-withdrawal",
      ...unsignedReview.review,
      ...broadcastResult,
      hardwareSigned: true,
      transactionSignerRecovered: true,
      hardwareSignaturePersisted: false,
      signedTransactionPersisted: false,
      ethCallOnly: false,
      unsignedTransactionPersisted: false,
      signingEnabled: true,
      broadcastEnabled: true,
      directWithdrawalCalldataVerified: true,
      contractSimulationAccepted: true,
      simulationProviders: acceptedProviders,
      calldataPersisted: false,
      ethCallOnly: false,
      directWithdrawalCalldataVerified: true,
      contractSimulationAccepted: true,
      simulationProviders: acceptedProviders,
      calldataPersisted: false,
      chainId: 11155111,
      sourceDepositTransactionHash: publicInputs.k32.transactionHash,
      depositIndex: 17,
      withdrawnValueWei: withdrawnValue.toString(),
      remainingValueWei: changeValue.toString(),
      hardwareSessionsAgreed: true,
      minedCredentialRecovered: true,
      changeCredentialReproduced: true,
      stateRootVerified: true,
      aspRootVerified: true,
      groth16ProofGenerated: true,
      groth16Verified: true,
      verificationMethod: "ffjavascript-single-thread-bn128",
      privateWitnessPersisted: false,
      proofPersisted: false,
      signed: true,
      broadcast: true,
    };

    // Evidence contains booleans and public amounts
    // only: no private inputs or proof/public signals.
    writeFileSync(
      outputPath,
      JSON.stringify(evidence, null, 2),
      { mode: 0o600, flag: "wx" }
    );

    console.log("PASS: Groth16 withdrawal proof generated");
    console.log("PASS: Single-thread Groth16 pairing verification");
    console.log("PASS: Change commitment verified");
    console.log("PASS: Public-only evidence saved");
    console.log("Signing: YES, physical Keycard");
    console.log("Broadcasting: YES, receipt verified");
    console.log("Private witness persisted: NO");
    console.log("Proof persisted: NO");
  } finally {
    if (proofKeepAlive) clearInterval(proofKeepAlive);
    rootA?.fill(0);
    rootB?.fill(0);

    // Derived BigInt witness values still reside in
    // process memory until the process terminates.
  }
}

try {
  await main();
} catch {
  // Do not print exceptions that may contain
  // witness inputs or credential information.
  console.error(
    `FAIL: K35-G at stage ${stage}`
  );
  process.exitCode = 1;
}
