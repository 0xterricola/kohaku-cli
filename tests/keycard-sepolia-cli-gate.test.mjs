import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { spawn } from "node:child_process";

test("wrong Sepolia RPC network fails before Keycard authentication", async () => {
  let requests = 0;

  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    const rpc = JSON.parse(body);
    requests++;

    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({
      jsonrpc: "2.0",
      id: rpc.id,
      result: "0x1",
    }));
  });

  await new Promise((resolve) =>
    server.listen(0, "127.0.0.1", resolve)
  );

  try {
    const { port } = server.address();

    const args = [
      "--import", "tsx", "dist/index.js", "transact-raw",
      "--signer", "keycard",
      "--keycard-transport", "native",
      "--keycard-sepolia-offline",
      "--keycard-bridge", "/nonexistent/keycard-bridge",
      "--from", "0xB8A0f79E6d64c948E9F5ea32aD93647777915EBa",
      "--targets", "0x000000000000000000000000000000000000dEaD",
      "--payloads", "0x",
      "--values", "0",
      "--chain-id", "11155111",
      "--nonce", "0",
      "--gas", "21000",
      "--max-fee-per-gas", "1000000000",
      "--max-priority-fee-per-gas", "100000000",
      "--rpc-url", `http://127.0.0.1:${port}`,
      "--non-interactive",
    ];

    const result = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, args, {
        cwd: process.cwd(),
        env: { ...process.env, NO_COLOR: "1" },
      });

      let output = "";
      child.stdout.on("data", chunk => output += chunk);
      child.stderr.on("data", chunk => output += chunk);
      child.on("error", reject);
      child.on("close", code => resolve({ code, output }));
    });

    assert.notEqual(result.code, 0);
    assert.match(result.output, /Wrong network/);
    assert.doesNotMatch(result.output, /Keycard PIN:|Approve this Keycard signing intent/);
    assert.equal(requests, 1);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test("valid Sepolia preflight still requires interactive approval", async () => {
  const methods = [];

  const block = {
    number: "0x1",
    hash: `0x${"11".repeat(32)}`,
    parentHash: `0x${"22".repeat(32)}`,
    nonce: "0x0000000000000000",
    sha3Uncles: `0x${"00".repeat(32)}`,
    logsBloom: `0x${"00".repeat(256)}`,
    transactionsRoot: `0x${"00".repeat(32)}`,
    stateRoot: `0x${"00".repeat(32)}`,
    receiptsRoot: `0x${"00".repeat(32)}`,
    miner: `0x${"00".repeat(20)}`,
    difficulty: "0x0",
    totalDifficulty: "0x0",
    extraData: "0x",
    size: "0x1",
    gasLimit: "0x1c9c380",
    gasUsed: "0x0",
    timestamp: "0x1",
    transactions: [],
    uncles: [],
    baseFeePerGas: "0x3b9aca00",
  };

  const results = {
    eth_chainId: "0xaa36a7",
    eth_getTransactionCount: "0x0",
    eth_getBlockByNumber: block,
    eth_estimateGas: "0x5208",
    eth_getBalance: "0xde0b6b3a7640000",
  };

  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;

    const rpc = JSON.parse(body);
    methods.push(rpc.method);

    response.setHeader("content-type", "application/json");

    if (!(rpc.method in results)) {
      response.end(JSON.stringify({
        jsonrpc: "2.0",
        id: rpc.id,
        error: {
          code: -32601,
          message: `Unexpected RPC: ${rpc.method}`,
        },
      }));
      return;
    }

    response.end(JSON.stringify({
      jsonrpc: "2.0",
      id: rpc.id,
      result: results[rpc.method],
    }));
  });

  await new Promise(resolve =>
    server.listen(0, "127.0.0.1", resolve)
  );

  try {
    const { port } = server.address();

    const args = [
      "--import", "tsx", "dist/index.js", "transact-raw",
      "--signer", "keycard",
      "--keycard-transport", "native",
      "--keycard-sepolia-offline",
      "--keycard-bridge", "/nonexistent/keycard-bridge",
      "--from", "0xB8A0f79E6d64c948E9F5ea32aD93647777915EBa",
      "--targets", "0x000000000000000000000000000000000000dEaD",
      "--payloads", "0x",
      "--values", "0",
      "--chain-id", "11155111",
      "--nonce", "0",
      "--gas", "21000",
      "--max-fee-per-gas", "2000000000",
      "--max-priority-fee-per-gas", "100000000",
      "--rpc-url", `http://127.0.0.1:${port}`,
      "--non-interactive",
    ];

    const result = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, args, {
        cwd: process.cwd(),
        env: { ...process.env, NO_COLOR: "1" },
        timeout: 15000,
      });

      let output = "";
      child.stdout.on("data", chunk => output += chunk);
      child.stderr.on("data", chunk => output += chunk);
      child.on("error", reject);
      child.on("close", code => resolve({ code, output }));
    });

    assert.notEqual(result.code, 0);
    assert.match(result.output, /Sepolia RPC preflight/);
    assert.match(
      result.output,
      /Interactive Keycard approval required/,
    );
    assert.doesNotMatch(result.output, /Keycard PIN:/);

    for (const method of Object.keys(results)) {
      assert.ok(
        methods.includes(method),
        `Missing RPC preflight check: ${method}`,
      );
    }
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
