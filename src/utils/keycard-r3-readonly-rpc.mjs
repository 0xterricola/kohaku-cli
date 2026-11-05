import { custom } from "viem";

export const READ_ONLY_METHODS = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getCode",
  "eth_getBalance",
  "eth_getTransactionCount",
  "eth_feeHistory",
  "eth_maxPriorityFeePerGas",
  "eth_gasPrice",
  "eth_estimateGas",
  "eth_call",
  "eth_getLogs",
]);

export function makeReadOnlyTransport(
  rpcUrl,
  fetchImpl = fetch,
) {
  const parsed = new URL(rpcUrl);

  const loopback =
    parsed.hostname === "localhost" ||
    parsed.hostname === "127.0.0.1";

  if (
    parsed.protocol !== "https:" &&
    !(loopback && parsed.protocol === "http:")
  ) {
    throw new Error(
      "HTTPS or loopback RPC required"
    );
  }

  let nextId = 0;

  return custom({
    async request({ method, params }) {
      if (!READ_ONLY_METHODS.has(method)) {
        throw new Error(
          `RPC method prohibited: ${method}`
        );
      }

      const response = await fetchImpl(rpcUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: ++nextId,
          method,
          params: params ?? [],
        }),
      });

      if (!response.ok) {
        throw new Error(
          `RPC HTTP status ${response.status}`
        );
      }

      const body = await response.json();

      if (body.error) {
        throw new Error(
          `RPC error ${body.error.code}: ` +
          String(body.error.message).slice(0, 240)
        );
      }

      return body.result;
    },
  });
}
