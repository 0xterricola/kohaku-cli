import assert from "node:assert/strict";
import {
  readSync,
  writeSync,
  writeFileSync,
  renameSync,
  chmodSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  decodeFunctionData,
  formatEther,
  getAddress,
  isAddressEqual,
  keccak256,
  numberToHex,
  parseAbi,
  parseEther,
  parseTransaction,
  recoverAddress,
  recoverTransactionAddress,
  serializeTransaction,
} from "viem";

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

const curveOrder = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);

const depositAbi = parseAbi([
  "function deposit(uint256 _precommitment) payable returns (uint256 _commitment)",
]);

export function prepareK30Transaction(
  intent,
  simulation,
  evidence,
  candidate
) {
  assert.equal(
    simulation.checkpoint,
    "R5-E5B9K29-simulation"
  );

  for (const field of [
    "realCalldataSent",
    "ethCallPassed",
    "ethEstimateGasPassed",
  ]) {
    assert.equal(simulation[field], true);
  }

  assert.equal(simulation.signed, false);
  assert.equal(simulation.broadcast, false);
  assert.equal(simulation.chainId, 11155111);

  assert.ok(isAddressEqual(simulation.sender, sender));
  assert.ok(
    isAddressEqual(simulation.entrypoint, entrypoint)
  );

  assert.equal(simulation.depositValueWei, amount.toString());

  assert.equal(intent.type, "eip1559");
  assert.equal(intent.chainId, 11155111);
  assert.ok(isAddressEqual(intent.from, sender));
  assert.ok(isAddressEqual(intent.to, entrypoint));
  assert.equal(intent.value, amount);

  assert.ok(Number.isSafeInteger(intent.nonce));
  assert.equal(
    BigInt(intent.nonce),
    BigInt(simulation.nonce)
  );

  assert.equal(
    intent.nonce,
    evidence.observedNonce
  );

  assert.ok(
    BigInt(simulation.simulatedAtBlock) >=
      BigInt(evidence.checkedThrough)
  );

  const decoded = decodeFunctionData({
    abi: depositAbi,
    data: intent.data,
  });

  assert.equal(decoded.functionName, "deposit");
  assert.equal(decoded.args.length, 1);
  assert.equal(decoded.args[0], candidate);

  assertUnused(candidate, evidence.allPublicKeys);

  const gas = BigInt(simulation.suggestedGasLimit);
  const maxFeePerGas =
    BigInt(simulation.suggestedMaxFeePerGas);
  const maxPriorityFeePerGas =
    BigInt(simulation.suggestedPriorityFeePerGas);

  assert.ok(gas > BigInt(simulation.realGasEstimate));
  assert.ok(maxFeePerGas > 0n);
  assert.ok(
    maxFeePerGas >= maxPriorityFeePerGas
  );

  const balance = parseEther(
    simulation.senderBalanceETH
  );

  const maximumCost =
    amount + gas * maxFeePerGas;

  assert.equal(
    maximumCost.toString(),
    simulation.maximumCostWei
  );

  assert.ok(
    maximumCost <= balance,
    "Insufficient funds for final signing budget"
  );

  return {
    type: "eip1559",
    chainId: 11155111,
    nonce: intent.nonce,
    to: entrypoint,
    value: amount,
    data: intent.data,
    gas,
    maxFeePerGas,
    maxPriorityFeePerGas,
  };
}

function readSignature() {
  const raw = Buffer.alloc(65);

  try {
    let received = 0;

    while (received < raw.length) {
      const n = readSync(
        5,
        raw,
        received,
        raw.length - received,
        null
      );

      if (n <= 0) {
        throw new Error(
          "Hardware signature IPC incomplete"
        );
      }

      received += n;
    }

    const r = BigInt(
      "0x" + raw.subarray(0, 32).toString("hex")
    );

    const s = BigInt(
      "0x" + raw.subarray(32, 64).toString("hex")
    );

    const parity = raw[64];

    assert.ok(r > 0n && r < curveOrder);
    assert.ok(s > 0n && s < curveOrder);
    assert.ok(parity === 0 || parity === 1);

    // Ethereum requires low-S signatures.
    const highS = s > curveOrder / 2n;

    return {
      r: numberToHex(r, { size: 32 }),
      s: numberToHex(
        highS ? curveOrder - s : s,
        { size: 32 }
      ),
      yParity: highS ? 1 - parity : parity,
    };
  } finally {
    raw.fill(0);
  }
}

export async function completeK32Signing(
  intent,
  simulation,
  evidence,
  candidate,
  broadcastCallback
) {
  const tx = prepareK30Transaction(
    intent,
    simulation,
    evidence,
    candidate
  );

  const unsigned = serializeTransaction(tx);
  const parsedUnsigned = parseTransaction(unsigned);

  assert.equal(parsedUnsigned.type, "eip1559");
  assert.equal(parsedUnsigned.chainId, 11155111);
  assert.equal(parsedUnsigned.nonce, tx.nonce);
  assert.equal(parsedUnsigned.data, tx.data);
  assert.equal(parsedUnsigned.value, tx.value);
  assert.equal(parsedUnsigned.gas, tx.gas);

  const digest = keccak256(unsigned);
  const digestBytes = Buffer.from(
    digest.slice(2), "hex"
  );

  assert.equal(digestBytes.length, 32);

  console.log("");
  console.log("=== K30: REAL SEPOLIA TRANSACTION REVIEW ===");

  console.log(JSON.stringify({
    chainId: tx.chainId,
    sender,
    entrypoint: tx.to,
    depositIndex: 17,
    amountETH: formatEther(tx.value),
    nonce: tx.nonce,
    gasLimit: tx.gas.toString(),
    maxFeePerGasWei:
      tx.maxFeePerGas.toString(),
    maxPriorityFeePerGasWei:
      tx.maxPriorityFeePerGas.toString(),
    maximumCostETH: formatEther(
      tx.value + tx.gas * tx.maxFeePerGas
    ),
    simulatedAtBlock:
      simulation.simulatedAtBlock,
    publicHistoryThrough: evidence.checkedThrough,
    signingDigest: digest,
    realCalldataSimulated: true,
    broadcast: false,
  }, null, 2));

  console.log(
    "Real precommitment is not printed."
  );

  console.log(
    "Review these parameters before typing SIGN."
  );

  try {
    if (writeSync(4, digestBytes) !== 32) {
      throw new Error("Signing digest IPC failed");
    }
  } finally {
    digestBytes.fill(0);
  }

  // Go parent receives the digest, obtains a
  // separate SIGN approval, and invokes Keycard.
  const signature = readSignature();

  const recovered = await recoverAddress({
    hash: digest,
    signature,
  });

  assert.ok(
    isAddressEqual(recovered, sender),
    "Hardware signature recovered wrong account"
  );

  const serialized = serializeTransaction(
    tx,
    signature
  );

  const signed = parseTransaction(serialized);

  assert.equal(signed.type, tx.type);
  assert.equal(signed.chainId, tx.chainId);
  assert.equal(signed.nonce, tx.nonce);
  assert.equal(signed.value, tx.value);
  assert.equal(signed.data, tx.data);
  assert.equal(signed.gas, tx.gas);
  assert.equal(
    signed.maxFeePerGas,
    tx.maxFeePerGas
  );
  assert.equal(
    signed.maxPriorityFeePerGas,
    tx.maxPriorityFeePerGas
  );

  const transactionSigner =
    await recoverTransactionAddress({
      serializedTransaction: serialized,
    });

  assert.ok(
    isAddressEqual(transactionSigner, sender),
    "Serialized transaction signer mismatch"
  );

  const transactionHash = keccak256(serialized);


  assert.equal(
    typeof broadcastCallback,
    "function",
    "Verified broadcast callback required"
  );

  const result = await broadcastCallback({
    transaction: tx,
    serializedTransaction: serialized,
    transactionHash,
    simulation,
    evidence,
    candidate,
  });

  assert.equal(
    result.checkpoint,
    "R5-E5B9K32-broadcast"
  );

  assert.equal(result.receiptVerified, true);
  assert.equal(result.depositEventVerified, true);

  console.log(
    "PASS: Hardware-signed deposit confirmed on-chain"
  );

  return result;
}
