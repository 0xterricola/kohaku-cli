import assert from "node:assert/strict";
import { test } from "node:test";
import {
  encodeFunctionData,
  parseAbi,
} from "viem";

import {
  prepareK30Transaction,
} from "../experiments/v3-r5e5b9k30-transaction-signing.mjs";

const sender =
  "0x155a8332A3504D5F532742Ae6531cd0e28035972";

const entrypoint =
  "0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB";

const candidate = 123n;

function fixture() {
  return {
    intent: {
      type: "eip1559",
      chainId: 11155111,
      from: sender,
      to: entrypoint,
      value: 2000000000000000n,
      nonce: 0,
      data: encodeFunctionData({
        abi: parseAbi([
          "function deposit(uint256 _precommitment) payable",
        ]),
        functionName: "deposit",
        args: [candidate],
      }),
    },
    simulation: {
      checkpoint: "R5-E5B9K29-simulation",
      chainId: 11155111,
      sender,
      entrypoint,
      nonce: "0",
      depositValueWei: "2000000000000000",
      senderBalanceETH: "0.05",
      simulatedAtBlock: "12071565",
      realCalldataSent: true,
      ethCallPassed: true,
      ethEstimateGasPassed: true,
      realGasEstimate: "763264",
      suggestedGasLimit: "954080",
      suggestedMaxFeePerGas: "45",
      suggestedPriorityFeePerGas: "3",
      maximumCostWei: "2000000042933600",
      signed: false,
      broadcast: false,
    },
    evidence: {
      observedNonce: 0,
      checkedThrough: "12071526",
      allPublicKeys: ["456"],
    },
  };
}

test("real simulated EIP-1559 intent accepted", () => {
  const { intent, simulation, evidence } = fixture();

  const tx = prepareK30Transaction(
    intent, simulation, evidence, candidate
  );

  assert.equal(tx.chainId, 11155111);
  assert.equal(tx.gas, 954080n);
  assert.equal(tx.maxFeePerGas, 45n);
});

test("wrong chain refused", () => {
  const { intent, simulation, evidence } = fixture();
  intent.chainId = 1;

  assert.throws(() =>
    prepareK30Transaction(
      intent, simulation, evidence, candidate
    )
  );
});

test("unsimulated calldata refused", () => {
  const { intent, simulation, evidence } = fixture();
  simulation.ethCallPassed = false;

  assert.throws(() =>
    prepareK30Transaction(
      intent, simulation, evidence, candidate
    )
  );
});

test("changed nonce refused", () => {
  const { intent, simulation, evidence } = fixture();
  simulation.nonce = "1";

  assert.throws(() =>
    prepareK30Transaction(
      intent, simulation, evidence, candidate
    )
  );
});

test("wrong credential refused", () => {
  const { intent, simulation, evidence } = fixture();

  assert.throws(() =>
    prepareK30Transaction(
      intent, simulation, evidence, 999n
    )
  );
});

test("reused credential refused", () => {
  const { intent, simulation, evidence } = fixture();
  evidence.allPublicKeys = ["123"];

  assert.throws(() =>
    prepareK30Transaction(
      intent, simulation, evidence, candidate
    ),
    /reuse detected/
  );
});

test("insufficient fee budget refused", () => {
  const { intent, simulation, evidence } = fixture();
  simulation.senderBalanceETH = "0.001";

  assert.throws(() =>
    prepareK30Transaction(
      intent, simulation, evidence, candidate
    )
  );
});
