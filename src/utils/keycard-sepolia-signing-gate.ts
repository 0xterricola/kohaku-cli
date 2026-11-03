import {
  getAddress,
  isAddressEqual,
  type Address,
  type Hex,
} from "viem";

export type KeycardSigningStage =
  | "eip7702-authorization"
  | "erc4337-userop";

export type KeycardSigningReview = Readonly<{
  stage: KeycardSigningStage;
  chainId: number;
  owner: Address;
  expectedOwner: Address;
  nonce: bigint;
  digest: Hex;
  unsignedIntentDigest: Hex;
}>;

type FreshState = {
  nonce: bigint;
  digest: Hex;
  unsignedIntentDigest: Hex;
};

function validDigest(value: unknown): value is Hex {
  return (
    typeof value === "string" &&
    /^0x[0-9a-fA-F]{64}$/.test(value)
  );
}

/**
 * Independent approval before each hardware signing operation.
 *
 * Revalidation must independently recompute the nonce
 * and digest after approval.
 *
 * This utility does not itself access hardware or the network.
 */
export async function signWithKeycardApproval<T>(opts: {
  review: KeycardSigningReview;
  approve: (
    review: KeycardSigningReview,
  ) => Promise<boolean>;
  revalidate: (
    review: KeycardSigningReview,
  ) => Promise<FreshState>;
  sign: (digest: Hex) => Promise<T>;
}): Promise<T> {
  const review = opts.review;

  if (review.chainId !== 11155111) {
    throw new Error("Signing gate requires Sepolia.");
  }

  if (
    review.stage !== "eip7702-authorization" &&
    review.stage !== "erc4337-userop"
  ) {
    throw new Error("Unsupported hardware signing stage.");
  }

  const owner = getAddress(review.owner);
  const expectedOwner = getAddress(review.expectedOwner);

  if (!isAddressEqual(owner, expectedOwner)) {
    throw new Error("Hardware signing owner mismatch.");
  }

  if (
    typeof review.nonce !== "bigint" ||
    review.nonce < 0n
  ) {
    throw new Error("Invalid signing nonce.");
  }

  if (
    !validDigest(review.digest) ||
    !validDigest(review.unsignedIntentDigest)
  ) {
    throw new Error("Invalid signing review digest.");
  }

  if (
    typeof opts.approve !== "function" ||
    typeof opts.revalidate !== "function" ||
    typeof opts.sign !== "function"
  ) {
    throw new Error("Explicit signing controls required.");
  }

  // Preserve exactly what the user approves.
  const snapshot = Object.freeze({
    stage: review.stage,
    chainId: review.chainId,
    owner,
    expectedOwner,
    nonce: review.nonce,
    digest: review.digest.toLowerCase() as Hex,
    unsignedIntentDigest:
      review.unsignedIntentDigest.toLowerCase() as Hex,
  });

  if ((await opts.approve(snapshot)) !== true) {
    throw new Error("Hardware signing approval declined.");
  }

  // Revalidate after approval, before any signing callback.
  const fresh = await opts.revalidate(snapshot);

  if (
    !fresh ||
    fresh.nonce !== snapshot.nonce ||
    !validDigest(fresh.digest) ||
    !validDigest(fresh.unsignedIntentDigest) ||
    fresh.digest.toLowerCase() !== snapshot.digest ||
    fresh.unsignedIntentDigest.toLowerCase() !==
      snapshot.unsignedIntentDigest
  ) {
    throw new Error(
      "Signing review is stale; prepare and approve again.",
    );
  }

  return opts.sign(snapshot.digest);
}
