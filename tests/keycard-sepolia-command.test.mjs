import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import {
  mkdtempSync, writeFileSync, rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const account = privateKeyToAccount(`0x${"11".repeat(32)}`);

function run(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "dist/index.js",
       "keycard-submit-sepolia", ...args],
      {
        cwd: process.cwd(),
        env: { ...process.env, NO_COLOR: "1" },
        timeout: 15000,
      },
    );

    let output = "";
    child.stdout.on("data", chunk => output += chunk);
    child.stderr.on("data", chunk => output += chunk);
    child.on("error", reject);
    child.on("close", code => resolve({ code, output }));
  });
}

test("CLI inspection performs preflight without broadcasting", async () => {
  const dir = mkdtempSync(join(tmpdir(), "kohaku-submit-cli-"));
  const file = join(dir, "signed.hex");
  const methods = [];

  const signed = await account.signTransaction({
    type: "eip1559",
    chainId: 11155111,
    nonce: 0,
    to: account.address,
    data: "0x",
    value: 0n,
    gas: 21000n,
    maxFeePerGas: 1000000000n,
    maxPriorityFeePerGas: 100000000n,
  });

  writeFileSync(file, signed, { mode: 0o600 });

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
    baseFeePerGas: "0xe",
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
    response.end(JSON.stringify({
      jsonrpc: "2.0",
      id: rpc.id,
      ...(rpc.method in results
        ? { result: results[rpc.method] }
        : {
            error: {
              code: -32601,
              message: `Unexpected RPC: ${rpc.method}`,
            },
          }),
    }));
  });

  await new Promise(resolve =>
    server.listen(0, "127.0.0.1", resolve)
  );

  try {
    const { port } = server.address();
    const args = [
      "--signed-file", file,
      "--expected-from", account.address,
      "--rpc-url", `http://127.0.0.1:${port}`,
    ];

    const inspect = await run(args);

    assert.equal(inspect.code, 0, inspect.output);
    assert.match(inspect.output, /keycard-sepolia-inspection/);
    assert.match(inspect.output, /"broadcast": false/);
    assert.match(inspect.output, new RegExp(keccak256(signed)));
    assert.ok(!methods.includes("eth_sendRawTransaction"));

    const before = methods.length;
    const blocked = await run([...args, "--broadcast"]);

    assert.notEqual(blocked.code, 0);
    assert.match(blocked.output, /Interactive terminal required/);
    assert.equal(methods.length, before);
  } finally {
    await new Promise(resolve => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});
