import {
  keccak256,
  parseTransaction,
  type Address,
  type Hex,
} from "viem";
import {
  inspectSignedSepoliaTransaction,
} from "./keycard-sepolia-broadcast.js";
import type {
  SepoliaPreflightClient,
} from "./keycard-sepolia-preflight.js";

export type BroadcastReview = {
  transactionHash: Hex;
  from: Address;
  to: Address;
  chainId: number;
  nonce: number;
  value: bigint;
  gas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  maximumCost: bigint;
  calldataHash: Hex;
};

export class SepoliaSubmissionUncertainError extends Error {
  readonly name = "SepoliaSubmissionUncertainError";

  constructor(
    readonly phase: "broadcast" | "receipt",
    readonly transactionHash: Hex,
    readonly originalError: unknown,
  ) {
    super(
      `Sepolia ${phase} outcome uncertain for ${transactionHash}. ` +
      "Check transaction status before attempting another submission."
    );
  }
}

export type SepoliaSubmissionClient = SepoliaPreflightClient & {
  sendRawTransaction(args: {
    serializedTransaction: Hex;
  }): Promise<Hex>;
  waitForTransactionReceipt(args: {
    hash: Hex;
    confirmations: number;
  }): Promise<{
    transactionHash: Hex;
    status: "success" | "reverted";
    blockNumber: bigint;
  }>;
};

export async function submitSignedSepoliaTransaction(
  client: SepoliaSubmissionClient,
  signed: Hex,
  expectedFrom: Address,
  approve: (review: BroadcastReview) => Promise<boolean>,
) {
  // Everything before approval is read-only.
  const inspected = await inspectSignedSepoliaTransaction(
    client,
    signed,
    expectedFrom,
  );

  const tx = parseTransaction(signed);

  if (
    tx.type !== "eip1559" ||
    !tx.to ||
    tx.nonce === undefined ||
    tx.gas === undefined ||
    tx.maxFeePerGas === undefined ||
    tx.maxPriorityFeePerGas === undefined
  ) {
    throw new Error("Incomplete Sepolia EIP-1559 transaction.");
  }

  const review: BroadcastReview = {
    transactionHash: inspected.transactionHash,
    from: inspected.from,
    to: inspected.to,
    chainId: inspected.chainId,
    nonce: inspected.nonce,
    value: tx.value ?? 0n,
    gas: tx.gas,
    maxFeePerGas: tx.maxFeePerGas,
    maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
    maximumCost: inspected.maximumCost,
    calldataHash: keccak256(tx.data ?? "0x"),
  };

  if (!(await approve(review))) {
    throw new Error("Sepolia broadcast rejected.");
  }

  // This is the only network submission operation.
  // Never automatically retry: the transaction may have propagated.
  let networkHash: Hex;

  try {
    networkHash = await client.sendRawTransaction({
      serializedTransaction: signed,
    });
  } catch (error) {
    throw new SepoliaSubmissionUncertainError(
      "broadcast",
      review.transactionHash,
      error,
    );
  }

  if (
    networkHash.toLowerCase() !==
    review.transactionHash.toLowerCase()
  ) {
    throw new Error(
      "RPC returned an unexpected transaction hash after submission."
    );
  }

  let receipt: Awaited<
    ReturnType<SepoliaSubmissionClient["waitForTransactionReceipt"]>
  >;

  try {
    receipt = await client.waitForTransactionReceipt({
      hash: networkHash,
      confirmations: 1,
    });
  } catch (error) {
    throw new SepoliaSubmissionUncertainError(
      "receipt",
      networkHash,
      error,
    );
  }

  if (
    receipt.transactionHash.toLowerCase() !==
    networkHash.toLowerCase()
  ) {
    throw new Error("Transaction receipt hash mismatch.");
  }

  if (receipt.status !== "success") {
    throw new Error(
      "Sepolia transaction was broadcast but reverted."
    );
  }

  return {
    transactionHash: networkHash,
    blockNumber: receipt.blockNumber,
    status: receipt.status,
  };
}
