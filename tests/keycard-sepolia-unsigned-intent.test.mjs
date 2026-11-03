import assert from "node:assert/strict";
import { test } from "node:test";
import {
  buildKeycardSepoliaUnsignedIntent as build,
} from "../src/utils/keycard-sepolia-unsigned-intent.ts";

const owner = "0xB8A0f79E6d64c948E9F5ea32aD93647777915EBa";
const other = "0x0000000000000000000000000000000000000001";

const calls = [
  { to: owner, data: "0x", value: 0n },
  { to: other, data: "0x1234", value: 1n },
];

const base = {
  owner,
  chainId: 11155111,
  pendingEoaNonce: 1,
  delegationNeeded: true,
  calls,
};

test("unsigned intent is deterministic", () => {
  const a = build(base);
  assert.equal(a.digest, build(base).digest);
  assert.match(a.digest, /^0x[0-9a-f]{64}$/);
  assert.equal(a.digestKind, "intent-only-not-userop-hash");
});

test("owner, nonce and delegation affect digest", () => {
  const original = build(base).digest;

  assert.notEqual(build({ ...base, owner: other }).digest, original);
  assert.notEqual(build({ ...base, pendingEoaNonce: 2 }).digest, original);
  assert.notEqual(build({ ...base, delegationNeeded: false }).digest, original);
});

test("calldata, value and ordering affect digest", () => {
  const original = build(base).digest;

  assert.notEqual(build({
    ...base,
    calls: [calls[0], { ...calls[1], data: "0xabcd" }],
  }).digest, original);

  assert.notEqual(build({
    ...base,
    calls: [calls[0], { ...calls[1], value: 2n }],
  }).digest, original);

  assert.notEqual(build({
    ...base,
    calls: [...calls].reverse(),
  }).digest, original);
});

test("invalid parameters fail closed", () => {
  assert.throws(
    () => build({ ...base, chainId: 1 }),
    /requires Sepolia/,
  );
  assert.throws(
    () => build({ ...base, calls: [calls[0]] }),
    /requires two calls/,
  );
  assert.throws(
    () => build({ ...base, pendingEoaNonce: -1 }),
    /Invalid pending EOA nonce/,
  );
  assert.throws(
    () => build({
      ...base,
      calls: [calls[0], { ...calls[1], value: -1n }],
    }),
    /Invalid unsigned call value/,
  );
});
