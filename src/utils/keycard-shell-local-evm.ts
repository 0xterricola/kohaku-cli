import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";

import { SecretManager as PrivacyPoolsSecretManager } from "@kohaku-eth/privacy-pools";
import { toWithdrawProof } from "../../../kohaku-sdk-research/packages/privacy-pools/src/utils/encoding.utils";
import { proveShellDemoWithdrawal } from "./keycard-shell-demo-prover.mjs";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  buildMerkleTree,
  proofFromTree,
} from "../../../kohaku-sdk-research/packages/privacy-pools/src/utils/proof.util";

import { exchangeShellQr } from "./keycard-shell-qr-exchange.js";
import { createShellQrR3Provider } from "./keycard-shell-qr-r3-provider.js";

import {
  createPublicClient,
  createWalletClient,
  defineChain,
  encodeFunctionData,
  getAddress,
  http,
  parseAbi,
  parseEventLogs,
  type Abi,
  type Address,
  type Hex,
} from "viem";

const RPC = "http://127.0.0.1:18545";
const CHAIN_ID = 31337;
const GROSS = 2_000_000_000_000_000n;
const NET = 1_980_000_000_000_000n;

const NATIVE_ASSET =
  "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";

const ARTIFACT_ROOT = resolve(
  process.cwd(),
  "../privacy-pools-core/packages/contracts/out",
);

type Artifact = {
  abi: Abi;
  bytecode: {
    object: string;
    linkReferences?: Record<
      string,
      Record<string, Array<{ start: number; length: number }>>
    >;
  };
};

function loadArtifact(name: string): Artifact {
  return JSON.parse(
    readFileSync(
      resolve(ARTIFACT_ROOT, `${name}.sol`, `${name}.json`),
      "utf8",
    ),
  ) as Artifact;
}

function linkBytecode(
  artifact: Artifact,
  libraries: Record<string, Address> = {},
): Hex {
  let bytecode = artifact.bytecode.object;

  for (const references of Object.values(
    artifact.bytecode.linkReferences ?? {},
  )) {
    for (const [name, positions] of Object.entries(references)) {
      const address = libraries[name];
      assert.ok(address, `Missing Solidity library: ${name}`);

      for (const position of positions) {
        assert.equal(position.length, 20);

        const start = 2 + position.start * 2;
        const end = start + 40;

        assert.match(
          bytecode.slice(start, end),
          /^__\$[0-9a-fA-F]{34}\$__$/,
        );

        bytecode =
          bytecode.slice(0, start) +
          getAddress(address).slice(2).toLowerCase() +
          bytecode.slice(end);
      }
    }
  }

  assert.match(bytecode, /^0x[0-9a-fA-F]+$/);
  return bytecode as Hex;
}

export async function runLocalEvmDeposit(
  options: { hardware?: boolean } = {},
): Promise<void> {
  if (options.hardware && !process.stdin.isTTY) {
    throw new Error("Hardware QR exchange requires an interactive terminal");
  }
  console.log("\nKohaku Key V4 — Local Privacy Pools deposit");
  console.log("RPC:", RPC);
  console.log(options.hardware
    ? "Hardware credentials: KEYCARD SHELL QR"
    : "Hardware credentials: NOT USED");
  console.log("Sepolia broadcasting: DISABLED");

  const chain = defineChain({
    id: CHAIN_ID,
    name: "Isolated Anvil",
    nativeCurrency: {
      name: "Ether",
      symbol: "ETH",
      decimals: 18,
    },
    rpcUrls: { default: { http: [RPC] } },
    testnet: true,
  });

  const client = createPublicClient({
    chain,
    transport: http(RPC),
  });

  assert.equal(await client.getChainId(), CHAIN_ID);
  assert.equal(
    await client.getBlockNumber(),
    0n,
    "A fresh Anvil chain is required",
  );

  const rpcWallet = createWalletClient({
    chain,
    transport: http(RPC),
  });

  const accounts = await rpcWallet.getAddresses();
  assert.ok(accounts.length >= 2);

  const owner = getAddress(accounts[0]);
  const postman = getAddress(accounts[1]);

  const wallet = createWalletClient({
    account: owner,
    chain,
    transport: http(RPC),
  });

  async function confirm(hash: Hex) {
    const receipt = await client.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, "success");
    return receipt;
  }

  async function deploy(
    name: string,
    args: readonly unknown[] = [],
    libraries: Record<string, Address> = {},
  ): Promise<Address> {
    const artifact = loadArtifact(name);

    const hash = await wallet.deployContract({
      abi: artifact.abi,
      bytecode: linkBytecode(artifact, libraries),
      args,
    });

    const receipt = await confirm(hash);
    assert.ok(receipt.contractAddress);

    const address = getAddress(receipt.contractAddress);
    const code = await client.getBytecode({ address });
    assert.ok(code && code.length > 2);

    console.log(`PASS: ${name} deployed`);
    return address;
  }

  console.log("\n=== Deploy official contracts ===");

  const t3 = await deploy("PoseidonT3");
  const t4 = await deploy("PoseidonT4");
  const withdrawalVerifier = await deploy("WithdrawalVerifier");
  const commitmentVerifier = await deploy("CommitmentVerifier");
  const implementation = await deploy("Entrypoint");

  const entrypointAbi = loadArtifact("Entrypoint").abi;

  const initialization = encodeFunctionData({
    abi: entrypointAbi,
    functionName: "initialize",
    args: [owner, postman],
  });

  const entrypoint = await deploy("ERC1967Proxy", [
    implementation,
    initialization,
  ]);

  const pool = await deploy(
    "PrivacyPoolSimple",
    [entrypoint, withdrawalVerifier, commitmentVerifier],
    { PoseidonT3: t3, PoseidonT4: t4 },
  );

  const poolAbi = loadArtifact("PrivacyPoolSimple").abi;

  await confirm(
    await wallet.writeContract({
      address: entrypoint,
      abi: entrypointAbi,
      functionName: "registerPool",
      args: [NATIVE_ASSET, pool, 1n, 100n, 100n],
    }),
  );

  const scope = await client.readContract({
    address: pool,
    abi: poolAbi,
    functionName: "SCOPE",
  }) as bigint;

  const registered = await client.readContract({
    address: entrypoint,
    abi: entrypointAbi,
    functionName: "scopeToPool",
    args: [scope],
  }) as Address;

  assert.equal(getAddress(registered), pool);
  console.log("PASS: Native ETH pool registered");

  let precommitment = 0n;

  type Credential = {
    precommitment: bigint;
    nullifier: bigint;
    salt: bigint;
    nullifierHash: bigint;
  };

  let disposableCredentials:
    | { existing: Credential; change: Credential }
    | undefined;

  let hardwareDepositCredentials: Credential | undefined;

  if (!options.hardware) {
    const seed = randomBytes(32);

    try {
      const manager = PrivacyPoolsSecretManager({
        host: {
          keystore: {
            deriveAt(requested: string) {
              return `0x${createHmac("sha256", seed)
                .update(requested)
                .digest("hex")}` as Hex;
            },
          },
        } as unknown as Parameters<
          typeof PrivacyPoolsSecretManager
        >[0]["host"],
        accountIndex: 0,
      });

      const coordinates = {
        chainId: BigInt(CHAIN_ID),
        entrypointAddress: BigInt(entrypoint),
        depositIndex: 15,
      };

      const existing = await manager.getDepositSecrets(coordinates);
      const change = await manager.getSecrets({
        ...coordinates,
        withdrawIndex: 1,
      });

      assert.notEqual(existing.precommitment, change.precommitment);

      disposableCredentials = { existing, change };
      precommitment = existing.precommitment;
    } finally {
      seed.fill(0);
    }

    console.log("PASS: Consistent disposable credentials derived in memory");
  }

  if (options.hardware) {
    console.log("\\n=== Authenticate Keycard Shell QR credentials ===");
    console.log("Chain: 31337 | Account: 0 | Deposit index: 15");
    console.log("Entrypoint: locally deployed proxy");

    const provider = createShellQrR3Provider(
      (request, fingerprint) =>
        exchangeShellQr(request, fingerprint, {}),
    );

    try {
      const secrets = await provider.secretManager.getDepositSecrets({
        chainId: BigInt(CHAIN_ID),
        entrypointAddress: BigInt(entrypoint),
        depositIndex: 15,
      });

      precommitment = secrets.precommitment;
      assert.ok(precommitment > 0n);
      hardwareDepositCredentials = secrets;
    } finally {
      provider.dispose();
    }

    console.log("PASS: Hardware-derived precommitment obtained");
    console.log("Credential values: NOT PRINTED OR SAVED");
  }

  assert.ok(precommitment > 0n);

  console.log("\n=== Execute local test deposit ===");

  const initialRoot = await client.readContract({
    address: pool,
    abi: poolAbi,
    functionName: "currentRoot",
  }) as bigint;

  const initialNonce = await client.readContract({
    address: pool,
    abi: poolAbi,
    functionName: "nonce",
  }) as bigint;

  assert.equal(initialNonce, 0n);

  const depositAbi = parseAbi([
    "function deposit(uint256 _precommitment) payable returns (uint256 _commitment)",
  ]);

  const receipt = await confirm(
    await wallet.writeContract({
      address: entrypoint,
      abi: depositAbi,
      functionName: "deposit",
      args: [precommitment],
      value: GROSS,
    }),
  );

  const poolEvents = parseEventLogs({
    abi: poolAbi,
    eventName: "Deposited",
    logs: receipt.logs.filter(
      log => getAddress(log.address) === pool,
    ),
  });

  assert.equal(poolEvents.length, 1);

  const event = poolEvents[0].args as {
    _depositor: Address;
    _commitment: bigint;
    _label: bigint;
    _value: bigint;
    _precommitmentHash: bigint;
  };

  assert.equal(getAddress(event._depositor), owner);
  assert.equal(event._value, NET);
  assert.equal(event._precommitmentHash, precommitment);
  assert.ok(event._label > 0n);
  assert.ok(event._commitment > 0n);

  const entrypointEvents = parseEventLogs({
    abi: entrypointAbi,
    eventName: "Deposited",
    logs: receipt.logs.filter(
      log => getAddress(log.address) === entrypoint,
    ),
  });

  assert.equal(entrypointEvents.length, 1);

  const entrypointEvent = entrypointEvents[0].args as {
    _commitment: bigint;
    _amount: bigint;
  };

  assert.equal(entrypointEvent._commitment, event._commitment);
  assert.equal(entrypointEvent._amount, NET);

  const root = await client.readContract({
    address: pool,
    abi: poolAbi,
    functionName: "currentRoot",
  }) as bigint;

  const nonce = await client.readContract({
    address: pool,
    abi: poolAbi,
    functionName: "nonce",
  }) as bigint;

  const depositor = await client.readContract({
    address: pool,
    abi: poolAbi,
    functionName: "depositors",
    args: [event._label],
  }) as Address;

  assert.equal(nonce, 1n);
  assert.notEqual(root, initialRoot);
  assert.equal(getAddress(depositor), owner);
  assert.equal(await client.getBalance({ address: pool }), NET);

  console.log("\\n=== Verify actual Merkle membership ===");

  const stateTree = await buildMerkleTree([event._commitment]);
  const stateProof = proofFromTree(stateTree, event._commitment);

  const onchainTreeSize = await client.readContract({
    address: pool,
    abi: poolAbi,
    functionName: "currentTreeSize",
  }) as bigint;

  assert.equal(onchainTreeSize, 1n);
  assert.equal(stateTree.root, root, "SDK/on-chain state root mismatch");
  assert.equal(stateProof.root, root);
  assert.equal(stateProof.index, 0);
  assert.equal(stateProof.siblings.length, 32);

  console.log("PASS: SDK Merkle root matches actual pool root");
  console.log("PASS: Real deposit membership witness generated");

  console.log("\\n=== Create local ASP association set ===");

  const aspTree = await buildMerkleTree([event._label]);
  const aspProof = proofFromTree(aspTree, event._label);

  assert.equal(aspProof.root, aspTree.root);
  assert.equal(aspProof.index, 0);
  assert.equal(aspProof.siblings.length, 32);

  const postmanWallet = createWalletClient({
    account: postman,
    chain,
    transport: http(RPC),
  });

  // Local fixture metadata only. This is not a real IPFS CID.
  const localAspReference =
    "local-only-asp-fixture-not-an-ipfs-cid-00001";

  assert.ok(localAspReference.length >= 32);
  assert.ok(localAspReference.length <= 64);

  await confirm(
    await postmanWallet.writeContract({
      address: entrypoint,
      abi: entrypointAbi,
      functionName: "updateRoot",
      args: [aspTree.root, localAspReference],
    }),
  );

  const latestAspRoot = await client.readContract({
    address: entrypoint,
    abi: entrypointAbi,
    functionName: "latestRoot",
  }) as bigint;

  const firstAspRoot = await client.readContract({
    address: entrypoint,
    abi: entrypointAbi,
    functionName: "rootByIndex",
    args: [0n],
  }) as bigint;

  assert.equal(latestAspRoot, aspProof.root);
  assert.equal(firstAspRoot, aspProof.root);

  console.log("PASS: ASP root submitted by authorized postman");
  console.log("PASS: SDK ASP witness matches latest on-chain ASP root");
  console.log("PASS: Both membership proofs contain 32 siblings");


  if (options.hardware) {
    assert.ok(
      hardwareDepositCredentials,
      "Hardware deposit credentials required",
    );

    console.log("\\n=== Authenticate hardware change credentials ===");
    console.log("Account: 0 | Deposit: 15 | Withdrawal: 1");
    console.log("A second Keycard Shell QR approval is required");

    const provider = createShellQrR3Provider(
      (request, fingerprint) =>
        exchangeShellQr(request, fingerprint, {}),
    );

    try {
      const change = await provider.secretManager.getSecrets({
        chainId: BigInt(CHAIN_ID),
        entrypointAddress: BigInt(entrypoint),
        depositIndex: 15,
        withdrawIndex: 1,
      });

      assert.notEqual(
        hardwareDepositCredentials.precommitment,
        change.precommitment,
      );

      disposableCredentials = {
        existing: hardwareDepositCredentials,
        change,
      };
    } finally {
      provider.dispose();
    }

    console.log("PASS: Hardware change credentials authenticated");
    console.log("Credential values not printed or saved");
  }

  if (disposableCredentials) {
    console.log("\\n=== Generate proof against actual local state ===");

    const verified = await proveShellDemoWithdrawal({
      existing: disposableCredentials.existing,
      change: disposableCredentials.change,
      deposit: {
        netValue: NET,
        label: event._label,
        noteCommitment: event._commitment,
        stateProof,
      },
      membership: {
        stateProof,
        aspProof,
      },
      scope,
      processooor: owner,
    });

    assert.equal(verified.scope, scope);
    assert.equal(verified.publicSignals.length, 8);

    console.log("PASS: Real state Groth16 proof generated");
    console.log("PASS: Proof independently verified");

    console.log("\\n=== Verify proof using deployed Solidity ===");

    const contractProof = toWithdrawProof(verified);

    const accepted = await client.readContract({
      address: withdrawalVerifier,
      abi: loadArtifact("WithdrawalVerifier").abi,
      functionName: "verifyProof",
      args: [
        contractProof.pA,
        contractProof.pB,
        contractProof.pC,
        contractProof.pubSignals,
      ],
    }) as boolean;

    assert.equal(accepted, true);

    console.log("PASS: Solidity WithdrawalVerifier accepted proof");
    console.log("PASS: Solidity verification used eth_call");

    console.log("\\n=== Execute actual local withdrawal ===");

    const withdrawal = {
      processooor: owner,
      data: "0x" as const,
    };

    const balanceBefore = await client.getBalance({
      address: owner,
    });

    const poolBalanceBefore = await client.getBalance({
      address: pool,
    });

    assert.equal(poolBalanceBefore, NET);

    const withdrawalReceipt = await confirm(
      await wallet.writeContract({
        address: pool,
        abi: poolAbi,
        functionName: "withdraw",
        args: [withdrawal, contractProof],
      }),
    );

    const withdrawnEvents = parseEventLogs({
      abi: poolAbi,
      eventName: "Withdrawn",
      logs: withdrawalReceipt.logs.filter(
        log => getAddress(log.address) === pool,
      ),
    });

    assert.equal(withdrawnEvents.length, 1);

    console.log("PASS: Withdrawal transaction confirmed");
    console.log("PASS: Official Withdrawn event emitted");

    console.log("\\n=== Verify withdrawal state transitions ===");

    const withdrawnValue = verified.withdrawnValue;

    assert.equal(withdrawnValue, 990_000_000_000_000n);

    const balanceAfter = await client.getBalance({
      address: owner,
    });

    const gasCost =
      withdrawalReceipt.gasUsed *
      withdrawalReceipt.effectiveGasPrice;

    assert.equal(
      balanceAfter + gasCost - balanceBefore,
      withdrawnValue,
      "Withdrawal recipient balance mismatch",
    );

    const poolBalanceAfter = await client.getBalance({
      address: pool,
    });

    assert.equal(
      poolBalanceAfter,
      poolBalanceBefore - withdrawnValue,
    );

    const spent = await client.readContract({
      address: pool,
      abi: poolAbi,
      functionName: "nullifierHashes",
      args: [verified.mappedSignals.existingNullifierHash],
    }) as boolean;

    assert.equal(spent, true);

    const newRoot = await client.readContract({
      address: pool,
      abi: poolAbi,
      functionName: "currentRoot",
    }) as bigint;

    const newTreeSize = await client.readContract({
      address: pool,
      abi: poolAbi,
      functionName: "currentTreeSize",
    }) as bigint;

    assert.notEqual(newRoot, root);
    assert.equal(newTreeSize, 2n);

    console.log("PASS: Recipient received 0.00099 ETH before gas");
    console.log("PASS: Pool balance reduced to 0.00099 ETH");
    console.log("PASS: Existing nullifier marked spent");
    console.log("PASS: Change commitment inserted into Merkle tree");

    console.log("\\n=== Verify replay protection ===");

    let replayRejected = false;

    try {
      await client.simulateContract({
        address: pool,
        abi: poolAbi,
        functionName: "withdraw",
        args: [withdrawal, contractProof],
        account: owner,
      });
    } catch (error) {
      assert.ok(
        String(error).includes("NullifierAlreadySpent"),
        "Replay must revert specifically with NullifierAlreadySpent",
      );
      replayRejected = true;
    }

    assert.equal(
      replayRejected,
      true,
      "Withdrawal replay unexpectedly succeeded",
    );

    console.log("PASS: Replay rejected — NullifierAlreadySpent");
    console.log("PASS: Replay tested through eth_call only");
    console.log("PASS: One local withdrawal transaction submitted");
  }


  console.log("PASS: Real deposit transaction");
  console.log("PASS: Official deposit events");
  console.log("PASS: Real Poseidon commitment");
  console.log("PASS: On-chain deposit label");
  console.log("PASS: Merkle root updated");
  console.log("PASS: Initial net deposit 0.00198 ETH");
  console.log("PASS: Chain ID 31337");
  console.log("PASS: No Sepolia transactions");
  console.log("\nLOCAL EVM DEPOSIT CHECKPOINT PASSED");
}
