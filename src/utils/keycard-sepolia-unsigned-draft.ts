import {
  getAddress,
  isAddressEqual,
  keccak256,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";
import { toAccount, type PrivateKeyAccount } from "viem/accounts";
import { toSimple7702SmartAccount } from "viem/account-abstraction";
import { SIMPLE_7702_IMPLEMENTATION } from "./simple-7702.js";

type Call = {
  to: Address;
  data: Hex;
  value: bigint;
};

/**
 * Resolve the real EntryPoint nonce and encode the call batch.
 *
 * No physical hardware, signing, authorization, gas estimation,
 * journal writes, or UserOperation submission.
 */
export async function prepareKeycardSepoliaUnsignedDraft(opts: {
  client: PublicClient;
  owner: Address;
  calls: readonly Call[];
}) {
  if (opts.client.chain?.id !== 11155111) {
    throw new Error("Unsigned draft requires Sepolia.");
  }

  if (opts.calls.length < 2) {
    throw new Error("Unsigned draft requires at least two calls.");
  }

  const ownerAddress = getAddress(opts.owner);

  const rejectSigning = async (): Promise<never> => {
    throw new Error(
      "SECURITY: signing forbidden during unsigned preparation.",
    );
  };

  const owner = toAccount({
    address: ownerAddress,
    signMessage: rejectSigning,
    signTypedData: rejectSigning,
    signTransaction: rejectSigning,
    signAuthorization: rejectSigning,
  }) as PrivateKeyAccount;

  const account = await toSimple7702SmartAccount({
    client: opts.client,
    owner,
    implementation: SIMPLE_7702_IMPLEMENTATION,
  });

  const sender = await account.getAddress();

  if (!isAddressEqual(sender, ownerAddress)) {
    throw new Error("Unsigned draft sender mismatch.");
  }

  const nonce = await account.getNonce({ key: 0n });
  const callData = await account.encodeCalls([...opts.calls]);
  const stub = await account.getStubSignature();

  return {
    sender,
    entryPoint: account.entryPoint.address,
    entryPointVersion: account.entryPoint.version,
    nonceKey: "0",
    userOperationNonce: nonce.toString(),
    callData,
    callDataHash: keccak256(callData),
    stubSignatureBytes: (stub.length - 2) / 2,
    gasEstimated: false,
    authorizationSigned: false,
    signingPerformed: false,
    submissionPerformed: false,
  };
}
