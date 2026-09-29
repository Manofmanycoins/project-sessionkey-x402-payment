import { Hono } from "hono";
import { privateKeyToAccount } from "viem/accounts";
import { x402Client } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { wrapFetchWithPayment } from "@x402/fetch";

const app = new Hono();

const SESSIONKEY = {
  basename: "sessionkey.base.eth",
  agentId: 95962,
  expectedWallet: "0xAB05Ea86008615F8808d18f966109527BbB99981",
  network: "eip155:84532"
};

const VEGETABLES = {
  basename: "vegetables.base.eth",
  agentId: 95581,
  recipient: "0x5549EF31863DCD74BE3C5872eF19A3EFC27Cf169"
};

function getSessionkeyAccount(env) {
  const key = env?.SESSIONKEY_PRIVATE_KEY;
  if (!key) throw new Error("SESSIONKEY_PRIVATE_KEY secret is not configured");

  const normalizedKey = key.startsWith("0x") ? key : `0x${key}`;
  const account = privateKeyToAccount(normalizedKey);

  if (account.address.toLowerCase() !== SESSIONKEY.expectedWallet.toLowerCase()) {
    throw new Error(
      `Signer mismatch: derived ${account.address}, expected ${SESSIONKEY.expectedWallet}`
    );
  }
  return account;
}

function getVegetablesFetch(env) {
  if (!env?.VEGETABLES_SERVICE?.fetch) {
    throw new Error("VEGETABLES_SERVICE service binding is not configured");
  }

  // x402's fetch wrapper expects a fetch-compatible function.
  // Route every request through the direct Cloudflare service binding.
  return (input, init) => {
    const request =
      input instanceof Request ? input : new Request(input, init);
    return env.VEGETABLES_SERVICE.fetch(request);
  };
}

app.get("/", (c) =>
  c.json({
    service: "Project Sessionkey x402 Payment",
    buyer: {
      basename: SESSIONKEY.basename,
      erc8004Agent: SESSIONKEY.agentId,
      wallet: SESSIONKEY.expectedWallet
    },
    seller: {
      basename: VEGETABLES.basename,
      erc8004Agent: VEGETABLES.agentId,
      recipient: VEGETABLES.recipient
    },
    network: SESSIONKEY.network,
    transport: "Cloudflare Service Binding",
    signingKeyConfigured: Boolean(c.env?.SESSIONKEY_PRIVATE_KEY),
    vegetablesServiceConfigured: Boolean(c.env?.VEGETABLES_SERVICE),
    endpoints: ["/signer-check", "/binding-check", "/pay-vegetables"]
  })
);

app.get("/health", (c) =>
  c.json({ ok: true, service: "project-sessionkey-x402-payment" })
);

app.get("/signer-check", (c) => {
  try {
    const account = getSessionkeyAccount(c.env);
    return c.json({
      ok: true,
      derivedAddress: account.address,
      expectedAddress: SESSIONKEY.expectedWallet,
      matchesExpectedSessionkeyWallet: true
    });
  } catch (error) {
    return c.json({ ok: false, error: error?.message ?? String(error) }, 500);
  }
});

/*
 * SAFE ROUTE TEST.
 * Calls Vegetables /premium directly through the service binding WITHOUT
 * an x402 client. Expected result: HTTP 402. No payment is signed here.
 */
app.get("/binding-check", async (c) => {
  try {
    const directFetch = getVegetablesFetch(c.env);
    const response = await directFetch("https://vegetables.internal/premium", {
      method: "GET",
      headers: { accept: "application/json" }
    });

    const bodyText = await response.text();

    return c.json({
      ok: response.status === 402,
      expectedStatus: 402,
      actualStatus: response.status,
      paymentRequiredPresent: Boolean(
        response.headers.get("payment-required")
      ),
      body: bodyText
    });
  } catch (error) {
    return c.json({ ok: false, error: error?.message ?? String(error) }, 500);
  }
});

/*
 * INTENTIONAL PAYMENT ENDPOINT.
 * Do not refresh/repeat casually: this may settle another test-USDC payment.
 */
app.get("/pay-vegetables", async (c) => {
  try {
    const account = getSessionkeyAccount(c.env);
    const directFetch = getVegetablesFetch(c.env);

    const client = new x402Client();
    client.register(SESSIONKEY.network, new ExactEvmScheme(account));

    const paidFetch = wrapFetchWithPayment(directFetch, client);

    const response = await paidFetch(
      "https://vegetables.internal/premium",
      {
        method: "GET",
        headers: { accept: "application/json" }
      }
    );

    const bodyText = await response.text();
    let body;
    try {
      body = JSON.parse(bodyText);
    } catch {
      body = bodyText;
    }

    const paymentResponse = response.headers.get("payment-response");

    return c.json({
      ok: response.ok,
      finalStatus: response.status,
      buyer: {
        basename: SESSIONKEY.basename,
        erc8004Agent: SESSIONKEY.agentId,
        wallet: account.address
      },
      seller: {
        basename: VEGETABLES.basename,
        erc8004Agent: VEGETABLES.agentId,
        recipient: VEGETABLES.recipient
      },
      network: SESSIONKEY.network,
      transport: "Cloudflare Service Binding",
      paymentResponsePresent: Boolean(paymentResponse),
      paymentResponse,
      protectedResponse: body
    });
  } catch (error) {
    return c.json({ ok: false, error: error?.message ?? String(error) }, 500);
  }
});

app.notFound((c) =>
  c.json(
    {
      error: "Not found",
      endpoints: [
        "/",
        "/health",
        "/signer-check",
        "/binding-check",
        "/pay-vegetables"
      ]
    },
    404
  )
);

export default app;
