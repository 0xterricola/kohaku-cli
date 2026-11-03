import {
  getAddress,
  hashTypedData,
  isAddressEqual,
  recoverAddress,
  serializeSignature,
  type Address,
  type Hex,
} from "viem";
import { toAccount, type LocalAccount } from "viem/accounts";
import { hashAuthorization } from "viem/utils";
import { SIMPLE_7702_IMPLEMENTATION } from "./simple-7702.js";
import {
  signWithKeycardApproval,
  type KeycardSigningReview,
} from "./keycard-sepolia-signing-gate.js";

const ENTRYPOINT_V08 =
  "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108";

type SigningOwner = LocalAccount & {
  signAuthorization:
    NonNullable<LocalAccount["signAuthorization"]>;
};

type FreshState = {
  nonce: bigint;
  unsignedIntentDigest: Hex;
};

/**
 * Guarded owner for Sepolia EIP-7702/ERC-4337 only.
 *
 * No hardware or network activity occurs during construction.
 * Live revalidation is supplied externally and must independently
 * check the nonce, operation digest, intent and delegation state.
 */
export function createApprovedKeycardSepoliaOwner(opts: {
  owner: SigningOwner;
  expectedOwner: Address;
  unsignedIntentDigest: Hex;
  expectedCallData?: Hex;
  approve: (review: KeycardSigningReview) => Promise<boolean>;
  revalidate: (
    review: KeycardSigningReview,
  ) => Promise<FreshState>;
}) {
  const address = getAddress(opts.owner.address);

  if (!isAddressEqual(address, getAddress(opts.expectedOwner))) {
    throw new Error("Guarded owner identity mismatch.");
  }

  if (
    !/^0x[0-9a-fA-F]{64}$/.test(opts.unsignedIntentDigest)
  ) {
    throw new Error("Invalid guarded unsigned intent.");
  }

  const intent = opts.unsignedIntentDigest;

  const forbidden = async (): Promise<never> => {
    throw new Error("Signing method not permitted by Sepolia gate.");
  };

  return toAccount({
    address,

    signMessage: forbidden,
    signTransaction: forbidden,

    async signAuthorization(authorization) {
      const delegate = getAddress(
        authorization.contractAddress ??
          authorization.address,
      );

      if (
        !isAddressEqual(delegate, SIMPLE_7702_IMPLEMENTATION)
      ) {
        throw new Error("Unexpected EIP-7702 delegate.");
      }

      if (authorization.chainId !== 11155111) {
        throw new Error("Authorization requires Sepolia.");
      }

      if (
        !Number.isSafeInteger(authorization.nonce) ||
        authorization.nonce < 0
      ) {
        throw new Error("Invalid EIP-7702 nonce.");
      }

      const request = {
        address: delegate,
        chainId: authorization.chainId,
        nonce: authorization.nonce,
      };

      const digest = hashAuthorization({
        contractAddress: delegate,
        chainId: request.chainId,
        nonce: request.nonce,
      });

      return signWithKeycardApproval({
        review: {
          stage: "eip7702-authorization",
          chainId: 11155111,
          owner: address,
          expectedOwner: opts.expectedOwner,
          nonce: BigInt(request.nonce),
          digest,
          unsignedIntentDigest: intent,
        },
        approve: opts.approve,
        revalidate: async review => {
          const fresh = await opts.revalidate(review);
          return {
            ...fresh,
            digest: hashAuthorization({
              contractAddress: delegate,
              chainId: request.chainId,
              nonce: request.nonce,
            }),
          };
        },
        sign: async () => {
          const signed =
            await opts.owner.signAuthorization(request);

          const recovered = await recoverAddress({
            hash: digest,
            signature: serializeSignature(signed),
          });

          if (!isAddressEqual(recovered, address)) {
            throw new Error(
              "EIP-7702 signer recovery mismatch.",
            );
          }

          return signed;
        },
      });
    },

    async signTypedData(typedData) {
      // Snapshot the payload before asynchronous approvals.
      const payload = structuredClone(typedData);
      const domain = payload.domain as unknown as
        | {
            name?: string;
            version?: string;
            chainId?: number | bigint;
            verifyingContract?: string;
          }
        | undefined;
      const message = payload.message as {
        sender?: unknown;
        nonce?: unknown;
        callData?: unknown;
      };

      if (
        payload.primaryType !== "PackedUserOperation" ||
        domain?.name !== "ERC4337" ||
        domain.version !== "1" ||
        domain.chainId !== 11155111 ||
        typeof domain?.verifyingContract !== "string" ||
        !isAddressEqual(
          getAddress(domain.verifyingContract),
          ENTRYPOINT_V08,
        )
      ) {
        throw new Error("Unsupported UserOperation typed-data domain.");
      }

      if (
        typeof message.sender !== "string" ||
        !isAddressEqual(getAddress(message.sender), address)
      ) {
        throw new Error("UserOperation sender mismatch.");
      }

      if (
        typeof message.nonce !== "bigint" ||
        message.nonce < 0n
      ) {
        throw new Error("Invalid UserOperation nonce.");
      }

      if (
        opts.expectedCallData !== undefined &&
        (
          typeof message.callData !== "string" ||
          message.callData.toLowerCase() !==
            opts.expectedCallData.toLowerCase()
        )
      ) {
        throw new Error(
          "UserOperation calldata differs from reviewed batch.",
        );
      }

      const digest = hashTypedData(payload);

      return signWithKeycardApproval({
        review: {
          stage: "erc4337-userop",
          chainId: 11155111,
          owner: address,
          expectedOwner: opts.expectedOwner,
          nonce: message.nonce,
          digest,
          unsignedIntentDigest: intent,
        },
        approve: opts.approve,
        revalidate: async review => {
          const fresh = await opts.revalidate(review);
          return {
            ...fresh,
            digest: hashTypedData(payload),
          };
        },
        sign: async () => {
          // Detect mutation before forwarding to the signer.
          if (hashTypedData(payload) !== digest) {
            throw new Error("UserOperation payload changed.");
          }

          const signature =
            await opts.owner.signTypedData(payload);

          const recovered = await recoverAddress({
            hash: digest,
            signature,
          });

          if (!isAddressEqual(recovered, address)) {
            throw new Error(
              "UserOperation signer recovery mismatch.",
            );
          }

          return signature;
        },
      });
    },
  });
}
