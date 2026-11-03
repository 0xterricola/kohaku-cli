import { type Address, type Hex } from "viem";
import {
  createApprovedKeycardSepoliaOwner,
} from "./keycard-sepolia-approved-owner.js";
import {
  verifyKeycardSepoliaLiveState,
} from "./keycard-sepolia-live-state.js";

type ApprovedOptions =
  Parameters<typeof createApprovedKeycardSepoliaOwner>[0];

type StateOptions =
  Parameters<typeof verifyKeycardSepoliaLiveState>[0];

/**
 * Connect the guarded signer to independently queried chain state.
 *
 * The approved-owner implementation snapshots and hashes
 * each signing payload. This adapter checks fresh chain
 * state and the independently reconstructed unsigned intent.
 *
 * No signing occurs during construction.
 */
export function createLiveApprovedKeycardSepoliaOwner(opts: {
  client: StateOptions["client"];
  owner: ApprovedOptions["owner"];
  expectedOwner: Address;
  calls: StateOptions["calls"];
  expectedEoaNonce: number;
  expectedUserOpNonce: bigint;
  expectedDelegationNeeded: boolean;
  expectedIntentDigest: Hex;
  expectedCallData: Hex;
  approve: ApprovedOptions["approve"];
}) {
  return createApprovedKeycardSepoliaOwner({
    owner: opts.owner,
    expectedOwner: opts.expectedOwner,
    unsignedIntentDigest: opts.expectedIntentDigest,
    expectedCallData: opts.expectedCallData,
    approve: opts.approve,

    revalidate: async review => {
      const fresh = await verifyKeycardSepoliaLiveState({
        client: opts.client,
        owner: opts.expectedOwner,
        calls: opts.calls,
        expectedEoaNonce: opts.expectedEoaNonce,
        expectedUserOpNonce: opts.expectedUserOpNonce,
        expectedDelegationNeeded:
          opts.expectedDelegationNeeded,
        expectedIntentDigest: opts.expectedIntentDigest,
        review,
      });

      // The guarded signer recomputes the signing payload
      // digest independently from this chain-state callback.
      return {
        nonce: fresh.nonce,
        unsignedIntentDigest: fresh.unsignedIntentDigest,
      };
    },
  });
}
