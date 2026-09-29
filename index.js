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
  recipient: "0x5549EF31863DCD74BE3C5872eF19A3EFC27Cf169",
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
    signingKeyConfigured: Boolean(
      c.env?.SESSIONKEY_PRIVATE_KEY
    ),
    vegetablesServiceConfigured: Boolean(
      c.env?.VEGETABLES_SERVICE
    ),
    endpoints: [
      "/health",
      "/signer-check",
      "/bound-facilitator-check",
      "/bound-x402-init-check",
      "/binding-check",
      "/pay-vegetables"
    ]
  })
);

app.get("/health", (c) =>
  c.json({
    ok: true,
    service: "project-sessionkey-x402-payment"
  })
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
    return c.json(
      {
        ok: false,
        error: error?.message ?? String(error)
      },
      500
    );
  }
});

/*
 * SAFE DIAGNOSTIC #1
 *
 * Sessionkey -> Service Binding -> Vegetables
 * -> facilitator-check
 *
 * No signing.
 * No payment.
 * No USDC movement.
 */
app.get("/bound-facilitator-check", async (c) => {
  try {
    const directFetch = getVegetablesFetch(c.env);

    const response = await directFetch(
      `${VEGETABLES.publicUrl}/facilitator-check`,
      {
        method: "GET",
        headers: {
          accept: "application/json"
        }
      }
    );

    const result = await readResponse(response);

    return c.json({
      diagnostic:
        "Sessionkey -> Service Binding -> Vegetables facilitator-check",
      actualStatus: result.status,
      responseOk: result.ok,
      vegetablesResponse: result.body
    });
  } catch (error) {
    return c.json(
      {
        diagnostic:
          "Sessionkey -> Service Binding -> Vegetables facilitator-check",
        error: error?.message ?? String(error)
      },
      500
    );
  }
});

/*
 * SAFE DIAGNOSTIC #2
 *
 * THIS IS THE IMPORTANT TEST.
 *
 * Sessionkey -> Service Binding -> Vegetables
 * -> fresh x402 resource server
 * -> facilitator
 *
 * No signing.
 * No payment.
 * No USDC movement.
 */
app.get("/bound-x402-init-check", async (c) => {
  try {
    const directFetch = getVegetablesFetch(c.env);

    const response = await directFetch(
      `${VEGETABLES.publicUrl}/x402-init-check`,
      {
        method: "GET",
        headers: {
          accept: "application/json"
        }
      }
    );

    const result = await readResponse(response);

    return c.json({
      diagnostic:
        "Sessionkey -> Service Binding -> Vegetables fresh x402 initialization",
      actualStatus: result.status,
      responseOk: result.ok,
      vegetablesResponse: result.body
    });
  } catch (error) {
    return c.json(
      {
        diagnostic:
          "Sessionkey -> Service Binding -> Vegetables fresh x402 initialization",
        error: error?.message ?? String(error)
      },
      500
    );
  }
});

/*
 * SAFE /premium challenge test.
 *
 * Expected eventual result:
 * HTTP 402 with payment-required header.
 *
 * No x402 client is created here.
 * Therefore this route cannot sign or pay.
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
      body: bodyText
    });
  } catch (error) {
    return c.json(
      {
        ok: false,
        error: error?.message ?? String(error)
      },
      500
    );
  }
});

/*
 * REAL PAYMENT ROUTE.
 *
 * DO NOT OPEN THIS ROUTE DURING DIAGNOSTICS.
 *
 * A successful invocation may authorize and settle
 * a Base Sepolia USDC payment.
 */
app.get("/pay-vegetables", async (c) => {
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
      endpoints: [
        "/",
        "/health",
        "/signer-check",
        "/bound-facilitator-check",
        "/bound-x402-init-check",
        "/binding-check",
        "/pay-vegetables"
      ]
    },
    404
  )
);

export default app;
