import { Hono } from "hono";
import { privateKeyToAccount } from "viem/accounts";
import { x402Client } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { wrapFetchWithPayment } from "@x402/fetch";

const app = new Hono();

const SESSIONKEY = {
  basename: "sessionkey.base.eth",
  agentId: 95962,
  expectedWallet:
    "0xAB05Ea86008615F8808d18f966109527BbB99981",
  network: "eip155:84532"
};

const VEGETABLES = {
  basename: "vegetables.base.eth",
  agentId: 95581,
  recipient:
    "0x5549EF31863DCD74BE3C5872eF19A3EFC27Cf169",
  publicUrl:
    "https://projectvegetables-x402-v2.bigwaynesbbq.workers.dev"
};

function getSessionkeyAccount(env) {
  const key = env?.SESSIONKEY_PRIVATE_KEY;

  if (!key) {
    throw new Error(
      "SESSIONKEY_PRIVATE_KEY secret is not configured"
    );
  }

  const normalizedKey = key.startsWith("0x")
    ? key
    : `0x${key}`;

  const account = privateKeyToAccount(normalizedKey);

  if (
    account.address.toLowerCase() !==
    SESSIONKEY.expectedWallet.toLowerCase()
  ) {
    throw new Error(
      `Signer mismatch: derived ${account.address}, expected ${SESSIONKEY.expectedWallet}`
    );
  }

  return account;
}

function getVegetablesFetch(env) {
  if (!env?.VEGETABLES_SERVICE?.fetch) {
    throw new Error(
      "VEGETABLES_SERVICE service binding is not configured"
    );
  }

  return (input, init) => {
    const request = new Request(input, init);

    return env.VEGETABLES_SERVICE.fetch(request);
  };
}

async function readResponse(response) {
  const bodyText = await response.text();

  let body;

  try {
    body = JSON.parse(bodyText);
  } catch {
    body = bodyText;
  }

  return {
    status: response.status,
    ok: response.ok,
    body
  };
}

/*
 * PUBLIC INFORMATION
 *
 * No payment can be initiated from this route.
 */
app.get("/", (c) =>
  c.json({
    service: "Project Sessionkey x402 Payment",
    securityPhase: "13.1",
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
    signingKeyConfigured: Boolean(
      c.env?.SESSIONKEY_PRIVATE_KEY
    ),
    vegetablesServiceConfigured: Boolean(
      c.env?.VEGETABLES_SERVICE
    ),
    paymentExecution: {
      method: "POST",
      endpoint: "/pay-vegetables",
      getRequestsCanSpend: false
    },
    safeEndpoints: [
      "GET /health",
      "GET /signer-check",
      "GET /binding-check",
      "GET /pay-vegetables"
    ],
    paymentEndpoint:
      "POST /pay-vegetables"
  })
);

app.get("/health", (c) =>
  c.json({
    ok: true,
    service: "project-sessionkey-x402-payment",
    securityPhase: "13.1"
  })
);

/*
 * SAFE SIGNER CHECK
 *
 * Derives the public address only.
 * Does not sign or submit a transaction.
 */
app.get("/signer-check", (c) => {
  try {
    const account = getSessionkeyAccount(c.env);

    return c.json({
      ok: true,
      derivedAddress: account.address,
      expectedAddress: SESSIONKEY.expectedWallet,
      matchesExpectedSessionkeyWallet: true,
      paymentAttempted: false
    });
  } catch (error) {
    return c.json(
      {
        ok: false,
        error: error?.message ?? String(error),
        paymentAttempted: false
      },
      500
    );
  }
});

/*
 * SAFE BINDING CHECK
 *
 * Intentionally performs a normal unsigned request
 * to Vegetables.
 *
 * Expected result: HTTP 402.
 *
 * It cannot sign or pay.
 */
app.get("/binding-check", async (c) => {
  try {
    const directFetch = getVegetablesFetch(c.env);

    const response = await directFetch(
      `${VEGETABLES.publicUrl}/premium`,
      {
        method: "GET",
        headers: {
          accept: "application/json"
        }
      }
    );

    const bodyText = await response.text();

    return c.json({
      ok: response.status === 402,
      expectedStatus: 402,
      actualStatus: response.status,
      paymentRequiredPresent: Boolean(
        response.headers.get("payment-required")
      ),
      paymentAttempted: false,
      body: bodyText
    });
  } catch (error) {
    return c.json(
      {
        ok: false,
        error: error?.message ?? String(error),
        paymentAttempted: false
      },
      500
    );
  }
});

/*
 * CRITICAL SAFETY CHANGE
 *
 * A browser GET to /pay-vegetables is now inert.
 *
 * Refreshing or opening this URL cannot invoke
 * the signer and cannot initiate an x402 payment.
 */
app.get("/pay-vegetables", (c) =>
  c.json(
    {
      ok: false,
      paymentAttempted: false,
      paymentExecuted: false,
      message:
        "Payment execution is disabled for GET requests.",
      requiredMethod: "POST",
      endpoint: "/pay-vegetables",
      securityPhase: "13.1"
    },
    405,
    {
      Allow: "POST"
    }
  )
);

/*
 * PAYMENT EXECUTION
 *
 * Only POST is capable of reaching the signer.
 *
 * Additional policy controls and idempotency
 * protection will be added in the next #13 steps.
 */
app.post("/pay-vegetables", async (c) => {
  try {
    const account = getSessionkeyAccount(c.env);
    const directFetch = getVegetablesFetch(c.env);

    const client = new x402Client();

    client.register(
      SESSIONKEY.network,
      new ExactEvmScheme(account)
    );

    const paidFetch = wrapFetchWithPayment(
      directFetch,
      client
    );

    const response = await paidFetch(
      `${VEGETABLES.publicUrl}/premium`,
      {
        method: "GET",
        headers: {
          accept: "application/json"
        }
      }
    );

    const bodyText = await response.text();

    let body;

    try {
      body = JSON.parse(bodyText);
    } catch {
      body = bodyText;
    }

    const paymentResponse =
      response.headers.get("payment-response");

    return c.json({
      ok: response.ok,
      finalStatus: response.status,
      paymentAttempted: true,
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
      requestMethod: "POST",
      paymentResponsePresent: Boolean(
        paymentResponse
      ),
      paymentResponse,
      protectedResponse: body
    });
  } catch (error) {
    return c.json(
      {
        ok: false,
        paymentAttempted: true,
        error: error?.message ?? String(error)
      },
      500
    );
  }
});

app.notFound((c) =>
  c.json(
    {
      error: "Not found",
      paymentAttempted: false,
      endpoints: [
        "GET /",
        "GET /health",
        "GET /signer-check",
        "GET /binding-check",
        "GET /pay-vegetables",
        "POST /pay-vegetables"
      ]
    },
    404
  )
);

export default app;
