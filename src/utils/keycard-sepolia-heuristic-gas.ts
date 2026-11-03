import type { Address, Hex } from "viem";
import {
  estimateEip7702BatchUserOpFee,
} from "./eip7702-batch-userop.js";

type Estimator = typeof estimateEip7702BatchUserOpFee;

type Call = {
  to: Address;
  data: Hex;
  value: bigint;
};

/**
 * Read-only, signer-free heuristic gas estimate.
 *
 * Never supplies owner or privateKey to the existing estimator.
 * Not a bundler-validated UserOperation gas estimate.
 */
export async function previewKeycardSepoliaGas(opts: {
  client: Parameters<Estimator>[0]["client"];
  chainId: number;
  owner: Address;
  calls: readonly Call[];
  rpcUrl: string;
  estimator?: Estimator;
}) {
  if (
    opts.chainId !== 11155111 ||
    opts.client.chain?.id !== 11155111
  ) {
    throw new Error("Hardware gas preview requires Sepolia.");
  }

  if (opts.calls.length < 2) {
    throw new Error("Hardware gas preview requires two calls.");
  }

  const estimator =
    opts.estimator ?? estimateEip7702BatchUserOpFee;

  // The no-owner branch cannot request an authorization signature.
  const preview = await estimator({
    client: opts.client,
    chainId: 11155111n,
    senderAddress: opts.owner,
    calls: opts.calls,
    rpcUrl: opts.rpcUrl,
    withoutTor: true,
  });

  return {
    mode: "keycard-sepolia-heuristic-gas-preview",
    estimateType: "heuristic-not-bundler-validated",
    chainId: 11155111,
    owner: opts.owner,
    preview,
    authorizationSigned: false,
    signingPerformed: false,
    submissionPerformed: false,
  };
}
