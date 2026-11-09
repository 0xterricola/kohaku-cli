import type { WithdrawProveOutput } from "../../../kohaku-sdk-research/packages/privacy-pools/src/state/thunks/withdrawThunk";
type Credential = {
  precommitment: bigint;
  nullifier: bigint;
  salt: bigint;
  nullifierHash: bigint;
};

type MembershipProof = {
  index: number;
  root: bigint;
  siblings: bigint[];
};

export function proveShellDemoWithdrawal(input: {
  existing: Credential;
  change: Credential;
  deposit: {
    netValue: bigint;
    label: bigint;
    noteCommitment: bigint;
    stateProof: MembershipProof;
  };
  membership: {
    stateProof: MembershipProof;
    aspProof: MembershipProof;
  };
  scope?: bigint;
  processooor?: `0x${string}`;
}): Promise<{
  proof: WithdrawProveOutput["proof"];
  publicSignals: WithdrawProveOutput["publicSignals"];
  mappedSignals: WithdrawProveOutput["mappedSignals"];
  withdrawnValue: bigint;
  changeValue: bigint;
  context: bigint;
  scope: bigint;
}>;
