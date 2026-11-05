import {
  createPublicClient,
  encodeFunctionData,
  formatEther,
  getAddress,
  keccak256,
} from "viem";

import { sepolia } from "viem/chains";

import {
  PrivacyPoolsV1_0xBow,
} from "@kohaku-eth/privacy-pools";

import {
  makeReadOnlyTransport,
} from "../src/utils/keycard-r3-readonly-rpc.mjs";

const rpcUrl =
  process.env.SEPOLIA_RPC_URL ||
  "https://ethereum-sepolia-rpc.publicnode.com";

const client = createPublicClient({
  chain: sepolia,
  transport: makeReadOnlyTransport(rpcUrl),
});

const expectedChain = 11155111;
const sender = getAddress(
  "0x155a8332a3504d5f532742ae6531cd0e28035972"
);

const amount = 2000000000000000n;

// Public fixture, NOT a hardware-derived precommitment.
const syntheticPrecommitment = 12345678901234567890n;

const config = PrivacyPoolsV1_0xBow[expectedChain];

if (!config?.entrypoint?.entrypointAddress) {
  throw new Error("Sepolia SDK entrypoint missing");
}

const entrypoint = getAddress(
  config.entrypoint.entrypointAddress
);

if (
  entrypoint.toLowerCase() !==
  "0x34a2068192b1297f2a7f85d7d8cde66f8f0921cb"
) {
  throw new Error("Unexpected SDK entrypoint");
}

const depositAbi = [{
  type: "function",
  name: "deposit",
  stateMutability: "payable",
  inputs: [
    {
      name: "_precommitment",
      type: "uint256",
    },
  ],
  outputs: [
    {
      name: "_commitment",
      type: "uint256",
    },
  ],
}];

const data = encodeFunctionData({
  abi: depositAbi,
  functionName: "deposit",
  args: [syntheticPrecommitment],
});

function diagnostic(error) {
  const message = String(
    error?.shortMessage ??
    error?.message ??
    error
  );

  // Never print an API-key-bearing RPC URL.
  return message
    .replaceAll(rpcUrl, "[RPC]")
    .slice(0, 320);
}

async function main() {
  console.log(
    "=== R5-E5B9K19: Sepolia read-only readiness ==="
  );

  const chainId = await client.getChainId();

  if (chainId !== expectedChain) {
    throw new Error(
      `Wrong RPC chain: ${chainId}`
    );
  }

  console.log("PASS: Sepolia chain ID verified");

  const [
    blockNumber,
    bytecode,
    balance,
    nonce,
    fees,
  ] = await Promise.all([
    client.getBlockNumber(),
    client.getBytecode({
      address: entrypoint,
    }),
    client.getBalance({
      address: sender,
    }),
    client.getTransactionCount({
      address: sender,
      blockTag: "pending",
    }),
    client.estimateFeesPerGas({
      type: "eip1559",
    }),
  ]);

  if (!bytecode || bytecode === "0x") {
    throw new Error(
      "Sepolia entrypoint has no deployed bytecode"
    );
  }

  console.log(
    "PASS: Entrypoint contract bytecode exists"
  );

  const maxFeePerGas = fees.maxFeePerGas;
  const maxPriorityFeePerGas =
    fees.maxPriorityFeePerGas;

  if (
    maxFeePerGas === undefined ||
    maxPriorityFeePerGas === undefined
  ) {
    throw new Error(
      "EIP-1559 fee information unavailable"
    );
  }

  let gasEstimate = null;
  let simulationError = null;

  try {
    gasEstimate = await client.estimateGas({
      account: sender,
      to: entrypoint,
      data,
      value: amount,
    });
  } catch (error) {
    simulationError = diagnostic(error);
  }

  const estimatedCost =
    gasEstimate === null
      ? null
      : amount + gasEstimate * maxFeePerGas;

  const funded =
    estimatedCost !== null &&
    balance >= estimatedCost;

  const ready =
    gasEstimate !== null &&
    funded;

  console.log(
    "PASS: Hardware sender balance inspected"
  );

  console.log(
    "PASS: Pending nonce inspected"
  );

  console.log(
    "PASS: Current EIP-1559 fees inspected"
  );

  if (gasEstimate !== null) {
    console.log(
      "PASS: Synthetic deposit gas estimation"
    );
  } else {
    console.log(
      "BLOCKED: Synthetic deposit gas estimation"
    );
  }

  console.log(JSON.stringify({
    checkpoint: "R5-E5B9K19",
    chainId,
    blockNumber: blockNumber.toString(),
    entrypoint,
    entrypointCodeHash: keccak256(bytecode),
    sender,
    senderBalanceWei: balance.toString(),
    senderBalanceEth: formatEther(balance),
    pendingNonce: nonce,
    depositAmountWei: amount.toString(),
    syntheticPrecommitment: true,
    maxFeePerGasWei: maxFeePerGas.toString(),
    maxPriorityFeePerGasWei:
      maxPriorityFeePerGas.toString(),
    estimatedGas:
      gasEstimate?.toString() ?? null,
    estimatedMaxCostWei:
      estimatedCost?.toString() ?? null,
    balanceSufficient: funded,
    simulationError,
    transactionReadyForFurtherReview: ready,
    realCredentialReuseChecked: false,
    realTransactionSigned: false,
    broadcast: false,
  }, null, 2));

  console.log(
    ready
      ? "PASS: K19 synthetic transaction feasibility"
      : "BLOCKED: K19 transaction feasibility"
  );

  console.log(
    "PASS: R5-E5B9K19 read-only inspection completed"
  );
}

await main();
