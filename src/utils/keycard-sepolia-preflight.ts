import type { Address, Hex } from "viem";

export const SEPOLIA_CHAIN_ID = 11155111;

export type SepoliaTransaction = {
  from: Address;
  to: Address;
  data: Hex;
  value: bigint;
  nonce: number;
  gas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
};

export type SepoliaPreflightClient = {
  getChainId(): Promise<number>;
  getTransactionCount(args: {
    address: Address;
    blockTag: "pending";
  }): Promise<number>;
  getBalance(args: {
    address: Address;
    blockTag: "pending";
  }): Promise<bigint>;
  getBlock(args: {
    blockTag: "pending";
  }): Promise<{ baseFeePerGas: bigint | null }>;
  estimateGas(args: {
    account: Address;
    to: Address;
    data: Hex;
    value: bigint;
    maxFeePerGas: bigint;
    maxPriorityFeePerGas: bigint;
  }): Promise<bigint>;
};

export async function preflightSepoliaTransaction(
  client: SepoliaPreflightClient,
  tx: SepoliaTransaction,
) {
  const chainId = await client.getChainId();

  if (chainId !== SEPOLIA_CHAIN_ID) {
    throw new Error(
      `Wrong network: expected Sepolia ${SEPOLIA_CHAIN_ID}, got ${chainId}.`
    );
  }

  if (
    !Number.isSafeInteger(tx.nonce) ||
    tx.nonce < 0 ||
    tx.value < 0n ||
    tx.gas <= 0n ||
    tx.maxFeePerGas < 0n ||
    tx.maxPriorityFeePerGas < 0n ||
    tx.maxPriorityFeePerGas > tx.maxFeePerGas
  ) {
    throw new Error("Invalid transaction parameters.");
  }

  const nonce = await client.getTransactionCount({
    address: tx.from,
    blockTag: "pending",
  });

  if (tx.nonce !== nonce) {
    throw new Error(
      `Nonce mismatch: transaction=${tx.nonce}, pending=${nonce}.`
    );
  }

  const block = await client.getBlock({ blockTag: "pending" });

  if (block.baseFeePerGas === null) {
    throw new Error("Sepolia base fee unavailable.");
  }

  if (tx.maxFeePerGas < block.baseFeePerGas) {
    throw new Error("Maximum fee is below the current base fee.");
  }

  const estimatedGas = await client.estimateGas({
    account: tx.from,
    to: tx.to,
    data: tx.data,
    value: tx.value,
    maxFeePerGas: tx.maxFeePerGas,
    maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
  });

  if (tx.gas < estimatedGas) {
    throw new Error(
      `Gas limit too low: provided=${tx.gas}, estimated=${estimatedGas}.`
    );
  }

  const balance = await client.getBalance({
    address: tx.from,
    blockTag: "pending",
  });

  const maximumCost = tx.value + tx.gas * tx.maxFeePerGas;

  if (balance < maximumCost) {
    throw new Error(
      `Insufficient balance: available=${balance}, required=${maximumCost}.`
    );
  }

  return {
    chainId,
    nonce,
    balance,
    baseFeePerGas: block.baseFeePerGas,
    estimatedGas,
    maximumCost,
  };
}
