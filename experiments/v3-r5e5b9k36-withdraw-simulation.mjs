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
  work, "r5-e5b9k36-simulation.json"
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

    const evidence = {
      checkpoint: "R5-E5B9K36-withdraw-simulation",
      ethCallOnly: true,
      directWithdrawalCalldataVerified: true,
      contractSimulationAccepted: true,
      simulationProviders: acceptedProviders,
      calldataPersisted: false,
      chainId: 11155111,
      transactionHash: publicInputs.k32.transactionHash,
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
      signed: false,
      broadcast: false,
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
    console.log("Signing: NO");
    console.log("Broadcasting: NO");
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
