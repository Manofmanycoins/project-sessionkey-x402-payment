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

/*
 * ============================================================
 * PAYMENT GUARD DURABLE OBJECT
 * ============================================================
 *
 * Persistent, strongly coordinated idempotency protection.
 *
 * This object does NOT hold the private key.
 * This object does NOT sign payments.
 * This object does NOT communicate with x402.
 *
 * Its job is to decide whether a purchase request ID has
 * already been reserved or completed.
 */
export class PaymentGuard {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (
      request.method === "POST" &&
      url.pathname === "/reserve"
    ) {
      return this.reserve(request);
    }

    if (
      request.method === "POST" &&
      url.pathname === "/complete"
    ) {
      return this.complete(request);
    }

    if (
      request.method === "POST" &&
      url.pathname === "/fail"
    ) {
      return this.fail(request);
    }

    if (
      request.method === "GET" &&
      url.pathname === "/status"
    ) {
      return this.status(url);
    }

    return Response.json(
      {
        ok: false,
        error: "PaymentGuard route not found"
      },
      {
        status: 404
      }
    );
  }

  async reserve(request) {
    let body;

    try {
      body = await request.json();
    } catch {
      return Response.json(
        {
          ok: false,
          error: "Invalid JSON"
        },
        {
          status: 400
        }
      );
    }

    const requestId =
      typeof body?.requestId === "string"
        ? body.requestId.trim()
        : "";

    if (!requestId) {
      return Response.json(
        {
          ok: false,
          error: "requestId is required"
        },
        {
          status: 400
        }
      );
    }

    const storageKey = `payment:${requestId}`;

    /*
     * Durable Object requests are serialized around this
     * object's storage operations.
     *
     * transaction() gives us an atomic read/write reservation.
     */
    const result =
      await this.ctx.storage.transaction(
        async (txn) => {
          const existing =
            await txn.get(storageKey);

          if (existing) {
            return {
              allowed: false,
              duplicate: true,
              record: existing
            };
          }

          const now =
            new Date().toISOString();

          const record = {
            requestId,
            status: "reserved",
            createdAt: now,
            updatedAt: now,
            metadata:
              body?.metadata ?? null
          };

          await txn.put(
            storageKey,
            record
          );

          return {
            allowed: true,
            duplicate: false,
            record
          };
        }
      );

    return Response.json({
      ok: true,
      ...result
    });
  }

  async complete(request) {
    let body;

    try {
      body = await request.json();
    } catch {
      return Response.json(
        {
          ok: false,
          error: "Invalid JSON"
        },
        {
          status: 400
        }
      );
    }

    const requestId =
      typeof body?.requestId === "string"
        ? body.requestId.trim()
        : "";

    if (!requestId) {
      return Response.json(
        {
          ok: false,
          error: "requestId is required"
        },
        {
          status: 400
        }
      );
    }

    const storageKey =
      `payment:${requestId}`;

    const existing =
      await this.ctx.storage.get(
        storageKey
      );

    if (!existing) {
      return Response.json(
        {
          ok: false,
          error:
            "Payment reservation does not exist"
        },
        {
          status: 404
        }
      );
    }

    const updated = {
      ...existing,
      status: "completed",
      updatedAt:
        new Date().toISOString(),
      result:
        body?.result ?? null
    };

    await this.ctx.storage.put(
      storageKey,
      updated
    );

    return Response.json({
      ok: true,
      record: updated
    });
  }

  async fail(request) {
    let body;

    try {
      body = await request.json();
    } catch {
      return Response.json(
        {
          ok: false,
          error: "Invalid JSON"
        },
        {
          status: 400
        }
      );
    }

    const requestId =
      typeof body?.requestId === "string"
        ? body.requestId.trim()
        : "";

    if (!requestId) {
      return Response.json(
        {
          ok: false,
          error: "requestId is required"
        },
        {
          status: 400
        }
      );
    }

    const storageKey =
      `payment:${requestId}`;

    const existing =
      await this.ctx.storage.get(
        storageKey
      );

    if (!existing) {
      return Response.json(
        {
          ok: false,
          error:
            "Payment reservation does not exist"
        },
        {
          status: 404
        }
      );
    }

    const updated = {
      ...existing,
      status: "failed",
      updatedAt:
        new Date().toISOString(),
      result:
        body?.result ?? null
    };

    await this.ctx.storage.put(
      storageKey,
      updated
    );

    return Response.json({
      ok: true,
      record: updated
    });
  }

  async status(url) {
    const requestId =
      url.searchParams
        .get("requestId")
        ?.trim() ?? "";

    if (!requestId) {
      return Response.json(
        {
          ok: false,
          error: "requestId is required"
        },
        {
          status: 400
        }
      );
    }

    const record =
      await this.ctx.storage.get(
        `payment:${requestId}`
      );

    return Response.json({
      ok: true,
      exists: Boolean(record),
      record: record ?? null
    });
  }
}

/*
 * ============================================================
 * SESSIONKEY HELPERS
 * ============================================================
 */

function getSessionkeyAccount(env) {
  const key =
    env?.SESSIONKEY_PRIVATE_KEY;

  if (!key) {
    throw new Error(
      "SESSIONKEY_PRIVATE_KEY secret is not configured"
    );
  }

  const normalizedKey =
    key.startsWith("0x")
      ? key
      : `0x${key}`;

  const account =
    privateKeyToAccount(
      normalizedKey
    );

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
  if (
    !env?.VEGETABLES_SERVICE?.fetch
  ) {
    throw new Error(
      "VEGETABLES_SERVICE service binding is not configured"
    );
  }

  return (input, init) => {
    const request =
      new Request(input, init);

    return env.VEGETABLES_SERVICE.fetch(
      request
    );
  };
}

function getPaymentGuard(env) {
  if (!env?.PAYMENT_GUARD) {
    throw new Error(
      "PAYMENT_GUARD Durable Object binding is not configured"
    );
  }

  /*
   * All payment requests intentionally use the
   * same Durable Object instance.
   *
   * This gives the Sessionkey agent one authoritative
   * payment coordination point.
   */
  const id =
    env.PAYMENT_GUARD.idFromName(
      "sessionkey-payment-guard"
    );

  return env.PAYMENT_GUARD.get(id);
}

async function callGuard(
  env,
  path,
  method,
  body
) {
  const guard =
    getPaymentGuard(env);

  const response =
    await guard.fetch(
      `https://payment-guard.internal${path}`,
      {
        method,
        headers: {
          "content-type":
            "application/json"
        },
        body:
          body === undefined
            ? undefined
            : JSON.stringify(body)
      }
    );

  const result =
    await response.json();

  if (!response.ok) {
    throw new Error(
      result?.error ??
        "PaymentGuard request failed"
    );
  }

  return result;
}

/*
 * ============================================================
 * PUBLIC INFORMATION
 * ============================================================
 */

app.get("/", (c) =>
  c.json({
    service:
      "Project Sessionkey x402 Payment",
    securityPhase: "13.2",
    buyer: {
      basename:
        SESSIONKEY.basename,
      erc8004Agent:
        SESSIONKEY.agentId,
      wallet:
        SESSIONKEY.expectedWallet
    },
    seller: {
      basename:
        VEGETABLES.basename,
      erc8004Agent:
        VEGETABLES.agentId,
      recipient:
        VEGETABLES.recipient
    },
    network:
      SESSIONKEY.network,
    transport:
      "Cloudflare Service Binding",
    paymentGuard: {
      type: "Durable Object",
      persistent: true,
      idempotencyRequired: true
    },
    paymentExecution: {
      method: "POST",
      endpoint:
        "/pay-vegetables",
      getRequestsCanSpend: false,
      idempotencyHeader:
        "Idempotency-Key"
    },
    safeEndpoints: [
      "GET /health",
      "GET /signer-check",
      "GET /binding-check",
      "GET /pay-vegetables",
      "GET /guard-self-test"
    ]
  })
);

app.get("/health", (c) =>
  c.json({
    ok: true,
    service:
      "project-sessionkey-x402-payment",
    securityPhase: "13.2",
    paymentGuardConfigured:
      Boolean(
        c.env?.PAYMENT_GUARD
      )
  })
);

/*
 * SAFE SIGNER CHECK
 *
 * No signing or payment.
 */
app.get("/signer-check", (c) => {
  try {
    const account =
      getSessionkeyAccount(c.env);

    return c.json({
      ok: true,
      derivedAddress:
        account.address,
      expectedAddress:
        SESSIONKEY.expectedWallet,
      matchesExpectedSessionkeyWallet:
        true,
      paymentAttempted: false
    });
  } catch (error) {
    return c.json(
      {
        ok: false,
        error:
          error?.message ??
          String(error),
        paymentAttempted: false
      },
      500
    );
  }
});

/*
 * SAFE X402 BINDING CHECK
 *
 * Expected result from Vegetables: 402.
 * No signer is used.
 */
app.get(
  "/binding-check",
  async (c) => {
    try {
      const directFetch =
        getVegetablesFetch(c.env);

      const response =
        await directFetch(
          `${VEGETABLES.publicUrl}/premium`,
          {
            method: "GET",
            headers: {
              accept:
                "application/json"
            }
          }
        );

      const bodyText =
        await response.text();

      return c.json({
        ok:
          response.status === 402,
        expectedStatus: 402,
        actualStatus:
          response.status,
        paymentRequiredPresent:
          Boolean(
            response.headers.get(
              "payment-required"
            )
          ),
        paymentAttempted: false,
        body: bodyText
      });
    } catch (error) {
      return c.json(
        {
          ok: false,
          error:
            error?.message ??
            String(error),
          paymentAttempted: false
        },
        500
      );
    }
  }
);

/*
 * ============================================================
 * SAFE IDEMPOTENCY SELF-TEST
 * ============================================================
 *
 * This endpoint NEVER loads the private key.
 * It NEVER contacts Vegetables.
 * It NEVER invokes x402.
 *
 * It reserves the same diagnostic request ID twice.
 *
 * Expected:
 *   first reservation  -> allowed true
 *   second reservation -> duplicate true
 *
 * A unique key can be supplied:
 *
 * /guard-self-test?key=test1
 */
app.get(
  "/guard-self-test",
  async (c) => {
    try {
      const suppliedKey =
        c.req.query("key")?.trim();

      const testKey =
        suppliedKey ||
        "default-test";

      const requestId =
        `diagnostic:${testKey}`;

      const metadata = {
        type:
          "idempotency-self-test",
        paymentCapable: false
      };

      const first =
        await callGuard(
          c.env,
          "/reserve",
          "POST",
          {
            requestId,
            metadata
          }
        );

      const second =
        await callGuard(
          c.env,
          "/reserve",
          "POST",
          {
            requestId,
            metadata
          }
        );

      return c.json({
        ok:
          first.allowed === true &&
          second.duplicate === true,
        securityPhase: "13.2",
        test:
          "persistent-idempotency",
        requestId,
        signerLoaded: false,
        paymentAttempted: false,
        firstReservation:
          first,
        secondReservation:
          second,
        expected: {
          firstAllowed: true,
          secondBlockedAsDuplicate:
            true
        }
      });
    } catch (error) {
      return c.json(
        {
          ok: false,
          signerLoaded: false,
          paymentAttempted: false,
          error:
            error?.message ??
            String(error)
        },
        500
      );
    }
  }
);

/*
 * ============================================================
 * GET PAYMENT ROUTE REMAINS INERT
 * ============================================================
 */

app.get(
  "/pay-vegetables",
  (c) =>
    c.json(
      {
        ok: false,
        paymentAttempted: false,
        paymentExecuted: false,
        message:
          "Payment execution is disabled for GET requests.",
        requiredMethod: "POST",
        requiredHeader:
          "Idempotency-Key",
        endpoint:
          "/pay-vegetables",
        securityPhase: "13.2"
      },
      405,
      {
        Allow: "POST"
      }
    )
);

/*
 * ============================================================
 * PAYMENT EXECUTION
 * ============================================================
 *
 * IMPORTANT ORDER:
 *
 * 1. Validate Idempotency-Key
 * 2. Reserve it persistently
 * 3. ONLY THEN load signer
 * 4. Execute x402
 * 5. Mark reservation completed or failed
 *
 * Duplicate request IDs are rejected BEFORE
 * the private key is loaded.
 */
app.post(
  "/pay-vegetables",
  async (c) => {
    const requestId =
      c.req.header(
        "Idempotency-Key"
      )?.trim();

    if (!requestId) {
      return c.json(
        {
          ok: false,
          paymentAttempted: false,
          signerLoaded: false,
          error:
            "Idempotency-Key header is required"
        },
        400
      );
    }

    if (
      requestId.length < 8 ||
      requestId.length > 128
    ) {
      return c.json(
        {
          ok: false,
          paymentAttempted: false,
          signerLoaded: false,
          error:
            "Idempotency-Key must be between 8 and 128 characters"
        },
        400
      );
    }

    let reservation;

    try {
      reservation =
        await callGuard(
          c.env,
          "/reserve",
          "POST",
          {
            requestId,
            metadata: {
              buyer:
                SESSIONKEY.basename,
              seller:
                VEGETABLES.basename,
              endpoint:
                "/premium",
              network:
                SESSIONKEY.network
            }
          }
        );
    } catch (error) {
      return c.json(
        {
          ok: false,
          paymentAttempted: false,
          signerLoaded: false,
          stage:
            "idempotency-reservation",
          error:
            error?.message ??
            String(error)
        },
        500
      );
    }

    if (!reservation.allowed) {
      return c.json(
        {
          ok: false,
          duplicate: true,
          paymentAttempted: false,
          signerLoaded: false,
          requestId,
          message:
            "Duplicate payment request blocked by PaymentGuard.",
          existingRecord:
            reservation.record
        },
        409
      );
    }

    /*
     * Nothing above this point loads the signer.
     *
     * The private key becomes usable only after the
     * persistent PaymentGuard authorizes this request ID.
     */

    try {
      const account =
        getSessionkeyAccount(
          c.env
        );

      const directFetch =
        getVegetablesFetch(
          c.env
        );

      const client =
        new x402Client();

      client.register(
        SESSIONKEY.network,
        new ExactEvmScheme(
          account
        )
      );

      const paidFetch =
        wrapFetchWithPayment(
          directFetch,
          client
        );

      const response =
        await paidFetch(
          `${VEGETABLES.publicUrl}/premium`,
          {
            method: "GET",
            headers: {
              accept:
                "application/json"
            }
          }
        );

      const bodyText =
        await response.text();

      let body;

      try {
        body =
          JSON.parse(bodyText);
      } catch {
        body = bodyText;
      }

      const paymentResponse =
        response.headers.get(
          "payment-response"
        );

      if (!response.ok) {
        await callGuard(
          c.env,
          "/fail",
          "POST",
          {
            requestId,
            result: {
              finalStatus:
                response.status,
              paymentResponsePresent:
                Boolean(
                  paymentResponse
                )
            }
          }
        );

        return c.json(
          {
            ok: false,
            requestId,
            finalStatus:
              response.status,
            paymentAttempted: true,
            signerLoaded: true,
            protectedResponse:
              body
          },
          response.status
        );
      }

      await callGuard(
        c.env,
        "/complete",
        "POST",
        {
          requestId,
          result: {
            finalStatus:
              response.status,
            paymentResponsePresent:
              Boolean(
                paymentResponse
              ),
            completedAt:
              new Date().toISOString()
          }
        }
      );

      return c.json({
        ok: true,
        requestId,
        finalStatus:
          response.status,
        paymentAttempted: true,
        signerLoaded: true,
        buyer: {
          basename:
            SESSIONKEY.basename,
          erc8004Agent:
            SESSIONKEY.agentId,
          wallet:
            account.address
        },
        seller: {
          basename:
            VEGETABLES.basename,
          erc8004Agent:
            VEGETABLES.agentId,
          recipient:
            VEGETABLES.recipient
        },
        network:
          SESSIONKEY.network,
        transport:
          "Cloudflare Service Binding",
        paymentGuard:
          "completed",
        paymentResponsePresent:
          Boolean(
            paymentResponse
          ),
        paymentResponse,
        protectedResponse:
          body
      });
    } catch (error) {
      /*
       * Keep the request ID consumed.
       *
       * We deliberately DO NOT delete a failed reservation.
       * Automatic reuse could be dangerous because a network
       * failure does not necessarily prove settlement failed.
       */
      try {
        await callGuard(
          c.env,
          "/fail",
          "POST",
          {
            requestId,
            result: {
              error:
                error?.message ??
                String(error),
              failedAt:
                new Date().toISOString()
            }
          }
        );
      } catch {
        /*
         * Never allow audit-record failure to cause
         * an automatic second payment attempt.
         */
      }

      return c.json(
        {
          ok: false,
          requestId,
          paymentAttempted: true,
          signerLoaded: true,
          error:
            error?.message ??
            String(error)
        },
        500
      );
    }
  }
);

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
        "GET /guard-self-test",
        "GET /pay-vegetables",
        "POST /pay-vegetables"
      ]
    },
    404
  )
);

export default app;
