import {
  isAddressEqual,
  parseTransaction,
  recoverTransactionAddress,
  type Address,
  type Hex,
} from "viem";
import {
  preflightSepoliaTransaction,
  SEPOLIA_CHAIN_ID,
  type SepoliaPreflightClient,
} from "./keycard-sepolia-preflight.js";
import {
  verifySignedKeycardTransaction,
} from "./keycard-verify-transaction.js";

// Read-only validation. This function never broadcasts.
export async function inspectSignedSepoliaTransaction(
  client: SepoliaPreflightClient,
  signed: Hex,
  expectedFrom: Address,
) {
  if (!signed.startsWith("0x02")) {
    throw new Error(
      "Only signed Sepolia EIP-1559 transactions are allowed."
    );
  }

  const tx = parseTransaction(signed);

  if (
    tx.type !== "eip1559" ||
    tx.chainId !== SEPOLIA_CHAIN_ID
  ) {
    throw new Error("Only signed Sepolia EIP-1559 transactions are allowed.");
  }

  if (
    !tx.to ||
    tx.nonce === undefined ||
    tx.gas === undefined ||
    tx.maxFeePerGas === undefined ||
    tx.maxPriorityFeePerGas === undefined
  ) {
    throw new Error("Incomplete signed transaction.");
  }

  const recovered = await recoverTransactionAddress({
    serializedTransaction: signed as `0x02${string}`,
  });

  if (!isAddressEqual(recovered, expectedFrom)) {
    throw new Error("Unexpected hardware signer.");
  }

  const transaction = {
    from: recovered,
    to: tx.to,
    chainId: SEPOLIA_CHAIN_ID,
    nonce: tx.nonce,
    gas: tx.gas,
    value: tx.value ?? 0n,
    data: tx.data ?? "0x",
    maxFeePerGas: tx.maxFeePerGas,
    maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
  };

  const hash = await verifySignedKeycardTransaction(
    signed,
    transaction,
  );

  const preflight = await preflightSepoliaTransaction(
    client,
    transaction,
  );

  return {
    transactionHash: hash,
    from: recovered,
    to: tx.to,
    ...preflight,
  };
}
