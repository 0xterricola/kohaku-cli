import {
  getAddress,
  isAddressEqual,
  parseAbi,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";
import { SIMPLE_7702_IMPLEMENTATION } from "./simple-7702.js";
import { buildKeycardSepoliaUnsignedIntent } from "./keycard-sepolia-unsigned-intent.js";
import type { KeycardSigningReview } from "./keycard-sepolia-signing-gate.js";

const ENTRYPOINT =
  "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108";

const NONCE_ABI = parseAbi([
  "function getNonce(address sender, uint192 key) view returns (uint256)",
]);

type Client = Pick<
  PublicClient,
  "getChainId" | "getBytecode" |
  "getTransactionCount" | "readContract"
>;

type Call = {
  to: Address;
  data: Hex;
  value: bigint;
};

/**
 * Independently check the state committed to the signing review.
 *
 * Does not access hardware, sign, persist or submit.
 * Signing-payload digest verification remains the owner's responsibility.
 */
export async function verifyKeycardSepoliaLiveState(opts: {
  client: Client;
  owner: Address;
  calls: readonly Call[];
  expectedEoaNonce: number;
  expectedUserOpNonce: bigint;
  expectedDelegationNeeded: boolean;
  expectedIntentDigest: Hex;
  review: KeycardSigningReview;
}) {
  const owner = getAddress(opts.owner);
  const review = opts.review;

  if (
    review.chainId !== 11155111 ||
    !isAddressEqual(owner, getAddress(review.owner)) ||
    !isAddressEqual(owner, getAddress(review.expectedOwner))
  ) {
    throw new Error("Signing review identity or chain mismatch.");
  }

  if (
    review.unsignedIntentDigest.toLowerCase() !==
    opts.expectedIntentDigest.toLowerCase()
  ) {
    throw new Error("Signing review intent mismatch.");
  }

  const isUserOp = review.stage === "erc4337-userop";

  const expectedStageNonce =
    review.stage === "eip7702-authorization"
      ? BigInt(opts.expectedEoaNonce)
      : isUserOp
        ? review.nonce
        : null;

  const nonceKey = isUserOp
    ? review.nonce >> 64n
    : 0n;

  const expectedOnChainUserOpNonce = isUserOp
    ? review.nonce
    : opts.expectedUserOpNonce;

  if (
    review.nonce < 0n ||
    nonceKey >= (1n << 192n)
  ) {
    throw new Error("Invalid ERC-4337 nonce.");
  }

  if (
    expectedStageNonce === null ||
    review.nonce !== expectedStageNonce
  ) {
    throw new Error("Signing review nonce mismatch.");
  }

  const chainId = await opts.client.getChainId();
  if (chainId !== 11155111) {
    throw new Error("Live RPC is not Sepolia.");
  }

  const [eoaNonce, userOpNonce, code] = await Promise.all([
    opts.client.getTransactionCount({
      address: owner,
      blockTag: "pending",
    }),
    opts.client.readContract({
      address: ENTRYPOINT,
      abi: NONCE_ABI,
      functionName: "getNonce",
      args: [owner, nonceKey],
    }),
    opts.client.getBytecode({ address: owner }),
  ]);

  if (eoaNonce !== opts.expectedEoaNonce) {
    throw new Error("Stale pending EOA nonce.");
  }

  if (userOpNonce !== expectedOnChainUserOpNonce) {
    throw new Error("Stale ERC-4337 nonce.");
  }

  const currentCode = (code ?? "0x").toLowerCase();
  const delegationCode =
    `0xef0100${SIMPLE_7702_IMPLEMENTATION.slice(2)}`.toLowerCase();

  if (
    currentCode !== "0x" &&
    currentCode !== delegationCode
  ) {
    throw new Error("Incompatible account delegation.");
  }

  const delegationNeeded = currentCode === "0x";

  if (delegationNeeded !== opts.expectedDelegationNeeded) {
    throw new Error("Account delegation state changed.");
  }

  const freshIntent = buildKeycardSepoliaUnsignedIntent({
    owner,
    chainId,
    pendingEoaNonce: eoaNonce,
    delegationNeeded,
    calls: opts.calls,
  });

  if (
    freshIntent.digest.toLowerCase() !==
    opts.expectedIntentDigest.toLowerCase()
  ) {
    throw new Error("Unsigned intent changed.");
  }

  return {
    nonce: expectedStageNonce,
    unsignedIntentDigest: freshIntent.digest,
    pendingEoaNonce: eoaNonce,
    userOperationNonce: userOpNonce,
    delegationNeeded,
  };
}
