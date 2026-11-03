import {
  encodeAbiParameters,
  getAddress,
  keccak256,
  parseAbiParameters,
  type Address,
  type Hex,
} from "viem";
import { SIMPLE_7702_IMPLEMENTATION } from "./simple-7702.js";

type Call = {
  to: Address;
  data: Hex;
  value: bigint;
};

const REVIEW_PARAMETERS = parseAbiParameters(
  "string domain, uint256 chainId, address owner, " +
  "address implementation, uint256 pendingEoaNonce, " +
  "bool delegationNeeded, address[] targets, " +
  "bytes[] payloads, uint256[] values",
);

/**
 * Pure unsigned intent commitment.
 *
 * This is NOT an ERC-4337 UserOperation hash.
 * It performs no RPC, hardware, signing, or submission.
 */
export function buildKeycardSepoliaUnsignedIntent(opts: {
  owner: Address;
  chainId: number;
  pendingEoaNonce: number;
  delegationNeeded: boolean;
  calls: readonly Call[];
}) {
  if (opts.chainId !== 11155111) {
    throw new Error("Unsigned hardware intent requires Sepolia.");
  }

  if (
    !Number.isSafeInteger(opts.pendingEoaNonce) ||
    opts.pendingEoaNonce < 0
  ) {
    throw new Error("Invalid pending EOA nonce.");
  }

  if (opts.calls.length < 2) {
    throw new Error("Unsigned hardware intent requires two calls.");
  }

  const owner = getAddress(opts.owner);

  const calls = opts.calls.map((call) => {
    if (!/^0x(?:[0-9a-fA-F]{2})*$/.test(call.data)) {
      throw new Error("Invalid unsigned call data.");
    }

    if (typeof call.value !== "bigint" || call.value < 0n) {
      throw new Error("Invalid unsigned call value.");
    }

    return {
      to: getAddress(call.to),
      data: call.data,
      value: call.value,
    };
  });

  const digest = keccak256(
    encodeAbiParameters(REVIEW_PARAMETERS, [
      "kohaku-key:v2:sepolia:unsigned-intent:1",
      BigInt(opts.chainId),
      owner,
      SIMPLE_7702_IMPLEMENTATION,
      BigInt(opts.pendingEoaNonce),
      opts.delegationNeeded,
      calls.map(call => call.to),
      calls.map(call => call.data),
      calls.map(call => call.value),
    ]),
  );

  return {
    kind: "kohaku-key-sepolia-unsigned-intent",
    version: 1,
    digest,
    digestKind: "intent-only-not-userop-hash",
  };
}
