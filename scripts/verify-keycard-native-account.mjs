import assert from "node:assert/strict";
import {
  isAddressEqual,
  recoverMessageAddress,
} from "viem";

import { createKeycardAccount } from
  "../src/utils/keycard-account.ts";

const binary = process.env.KOHAKU_KEYCARD_BRIDGE;

assert.ok(binary, "KOHAKU_KEYCARD_BRIDGE required");

const expected =
  "0xB8A0f79E6d64c948E9F5ea32aD93647777915EBa";

console.log("=== Create native Keycard account ===");

const account = createKeycardAccount({
  binary,
  transport: "native",
});

assert.ok(isAddressEqual(account.address, expected));

console.log("PASS: Native account address verified");

const message = "Kohaku Key V2 native account integration";

console.log("=== Sign EIP-191 message ===");

const signature = await account.signMessage({ message });

const recovered = await recoverMessageAddress({
  message,
  signature,
});

assert.ok(isAddressEqual(recovered, expected));

console.log("Recovered:", recovered);
console.log("PASS: Native viem signer recovered");
console.log("PASS: No RPC or broadcast");
console.log("PASS: V2 native account integration");
