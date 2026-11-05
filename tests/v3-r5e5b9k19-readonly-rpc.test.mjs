import assert from "node:assert/strict";
import { test } from "node:test";

import {
  makeReadOnlyTransport,
} from "../src/utils/keycard-r3-readonly-rpc.mjs";

test("RPC guard rejects all transaction submissions", async () => {
  let requests = 0;

  const transport = makeReadOnlyTransport(
    "https://example.invalid/rpc",
    async () => {
      requests++;
      throw new Error("No network expected");
    }
  );

  const client = transport({
    chain: undefined,
    retryCount: 0,
    timeout: 1000,
  });

  for (const method of [
    "eth_sendRawTransaction",
    "eth_sendTransaction",
    "personal_sign",
    "eth_sign",
    "eth_signTypedData_v4",
    "wallet_sendCalls",
    "debug_traceTransaction",
  ]) {
    await assert.rejects(
      client.request({ method, params: [] }),
      /RPC method prohibited/
    );
  }

  assert.equal(requests, 0);

  console.log(
    "PASS: Signing and broadcasting RPC prohibited"
  );
});

test("RPC guard permits read-only chain inspection", async () => {
  const seen = [];

  const transport = makeReadOnlyTransport(
    "https://example.invalid/rpc",
    async (_url, init) => {
      const body = JSON.parse(init.body);
      seen.push(body.method);

      return {
        ok: true,
        async json() {
          return {
            jsonrpc: "2.0",
            id: body.id,
            result: "0xaa36a7",
          };
        },
      };
    }
  );

  const client = transport({
    chain: undefined,
    retryCount: 0,
    timeout: 1000,
  });

  const result = await client.request({
    method: "eth_chainId",
    params: [],
  });

  assert.equal(result, "0xaa36a7");
  assert.deepEqual(seen, ["eth_chainId"]);

  console.log("PASS: Read-only RPC permitted");
});

test("RPC guard refuses insecure remote HTTP", () => {
  assert.throws(
    () => makeReadOnlyTransport(
      "http://example.invalid/rpc"
    ),
    /HTTPS or loopback/
  );

  console.log(
    "PASS: Unencrypted remote RPC rejected"
  );
});
