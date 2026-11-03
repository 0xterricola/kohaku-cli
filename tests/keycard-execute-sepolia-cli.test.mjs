import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { SIMPLE_7702_IMPLEMENTATION } from
  "../src/utils/simple-7702.ts";

const owner = "0xB8A0f79E6d64c948E9F5ea32aD93647777915EBa";
const other = "0x1111111111111111111111111111111111111111";

function run(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "dist/index.js",
        "keycard-execute-sepolia", ...args],
      {
        cwd: process.cwd(),
        env: { ...process.env, NO_COLOR: "1" },
        timeout: 15000,
      },
    );

    let output = "";
    child.stdout.on("data", data => output += data);
    child.stderr.on("data", data => output += data);
    child.on("error", reject);
    child.on("close", code => resolve({ code, output }));
  });
}

async function withMockRpc(config, callback) {
  const methods = [];

  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;

    const rpc = JSON.parse(body);
    methods.push(rpc.method);

    const results = {
      eth_chainId: config.chainId ?? "0xaa36a7",
      eth_getTransactionCount: "0x1",
      eth_getBalance: "0x11c37937e08000",
    };

    if (rpc.method === "eth_getCode") {
      const address = rpc.params[0].toLowerCase();

      results.eth_getCode =
        address === SIMPLE_7702_IMPLEMENTATION.toLowerCase()
          ? "0x6001"
          : config.senderCode ?? "0x";
    }

    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({
      jsonrpc: "2.0",
      id: rpc.id,
      ...(rpc.method in results
        ? { result: results[rpc.method] }
        : {
            error: {
              code: -32601,
              message: "Unexpected RPC method",
            },
          }),
    }));
  });

  await new Promise(resolve =>
    server.listen(0, "127.0.0.1", resolve),
  );

  try {
    const { port } = server.address();

    const args = [
      "--from", owner,
      "--targets", `${owner},${other}`,
      "--payloads", "0x,0x",
      "--values", "0,0",
      "--rpc-url", `http://127.0.0.1:${port}`,
    ];

    await callback(args, methods);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

test("read-only readiness validates a proposed batch", async () => {
  await withMockRpc({}, async (args, methods) => {
    const result = await run(args);

    assert.equal(result.code, 0, result.output);
    assert.match(result.output, /keycard-sepolia-userop-readiness/);
    assert.match(result.output, /"delegationNeeded": true/);
    assert.match(result.output, /"broadcast": false/);
    assert.match(result.output, /"signingPerformed": false/);
    assert.match(result.output, /"submissionPerformed": false/);

    assert.ok(methods.includes("eth_chainId"));
    assert.ok(!methods.includes("eth_sendUserOperation"));
    assert.ok(!methods.includes("eth_sendRawTransaction"));
  });
});

test("broadcast requires an interactive terminal before RPC access", async () => {
  await withMockRpc({}, async (args, methods) => {
    const result = await run([...args, "--broadcast"]);

    assert.notEqual(result.code, 0);
    assert.match(result.output, /Interactive terminal required/);
    assert.equal(methods.length, 0);
  });
});

test("rejects a non-Sepolia RPC chain", async () => {
  await withMockRpc({ chainId: "0x1" }, async (args, methods) => {
    const result = await run(args);

    assert.notEqual(result.code, 0);
    assert.match(result.output, /RPC is not Sepolia/);
    assert.ok(!methods.includes("eth_sendUserOperation"));
  });
});

test("rejects foreign account delegation", async () => {
  await withMockRpc({
    senderCode: `0xef0100${other.slice(2)}`,
  }, async (args, methods) => {
    const result = await run(args);

    assert.notEqual(result.code, 0);
    assert.match(result.output, /incompatible existing code/);
    assert.ok(!methods.includes("eth_sendUserOperation"));
  });
});

test("hardware verification requires an explicit bridge", async () => {
  await withMockRpc({}, async (args, methods) => {
    const result = await run([
      ...args,
      "--verify-keycard",
    ]);

    assert.notEqual(result.code, 0);
    assert.match(result.output, /requires an absolute --keycard-bridge path/);
    assert.equal(methods.length, 0);
  });
});

test("hardware verification rejects non-interactive execution", async () => {
  await withMockRpc({}, async (args, methods) => {
    const result = await run([
      ...args,
      "--verify-keycard",
      "--keycard-bridge",
      "/nonexistent/keycard-bridge",
    ]);

    assert.notEqual(result.code, 0);
    assert.match(result.output, /Interactive terminal required/);
    assert.equal(methods.length, 0);
  });
});

test("hardware bridge cannot be silently ignored", async () => {
  await withMockRpc({}, async (args, methods) => {
    const result = await run([
      ...args,
      "--keycard-bridge",
      "/nonexistent/keycard-bridge",
    ]);

    assert.notEqual(result.code, 0);
    assert.match(result.output, /require --verify-keycard/);
    assert.equal(methods.length, 0);
  });
});

test("broadcast with a bridge still rejects non-TTY execution", async () => {
  await withMockRpc({}, async (args, methods) => {
    const result = await run([
      ...args,
      "--broadcast",
      "--keycard-bridge",
      "/nonexistent/keycard-bridge",
    ]);

    assert.notEqual(result.code, 0);
    assert.match(result.output, /Interactive terminal required/);
    assert.equal(methods.length, 0);
  });
});
