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

const SPENDING_POLICY = Object.freeze({
  version: "13.6",

  network: "eip155:84532",
  scheme: "exact",

  asset:
    "0x036CbD53842c5426634e7929541eC2318f3dCF7e",

  assetSymbol: "USDC",
  assetDecimals: 6,

  maxTransactionAtomic: 50000n,
  maxTransactionDisplay: "0.05 USDC",

  dailyLimitAtomic: 250000n,
  dailyLimitDisplay: "0.25 USDC",

  velocityMaxPayments: 3,
  velocityWindowMs: 10 * 60 * 1000,
  velocityWindowDisplay: "10 minutes",

  allowedRecipient:
    "0x5549EF31863DCD74BE3C5872eF19A3EFC27Cf169"
});

function atomicToUsdcString(value) {
  const atomic = BigInt(value);
  const whole = atomic / 1000000n;
  const fraction = (
    atomic % 1000000n
  )
    .toString()
    .padStart(6, "0")
    .replace(/0+$/, "");

  return fraction
    ? `${whole}.${fraction} USDC`
    : `${whole} USDC`;
}

function utcDayKey(timestamp = Date.now()) {
  return new Date(timestamp)
    .toISOString()
    .slice(0, 10);
}


function sanitizeAuditValue(value, depth = 0) {
  if (depth > 6) {
    return "[max-depth]";
  }

  if (
    value === null ||
    value === undefined ||
    typeof value === "boolean" ||
    typeof value === "number"
  ) {
    return value ?? null;
  }

  if (typeof value === "bigint") {
    return value.toString();
  }

  if (typeof value === "string") {
    return value.length > 1000
      ? `${value.slice(0, 1000)}â¦`
      : value;
  }

  if (Array.isArray(value)) {
    return value
      .slice(0, 50)
      .map((item) =>
        sanitizeAuditValue(item, depth + 1)
      );
  }

  if (typeof value === "object") {
    const clean = {};

    for (
      const [key, item] of Object.entries(value)
    ) {
      if (
        /authorization|private|secret|token|signature|paymentresponse/i.test(
          key
        )
      ) {
        clean[key] = "[redacted]";
        continue;
      }

      clean[key] =
        sanitizeAuditValue(
          item,
          depth + 1
        );
    }

    return clean;
  }

  return String(value);
}

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
      url.pathname === "/authorize-budget"
    ) {
      return this.authorizeBudget(request);
    }

    if (
      request.method === "POST" &&
      url.pathname === "/diagnostic-authorize-budget"
    ) {
      return this.diagnosticAuthorizeBudget(
        request
      );
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

    if (
      request.method === "GET" &&
      url.pathname === "/budget-status"
    ) {
      return this.budgetStatus();
    }

    if (
      request.method === "GET" &&
      url.pathname === "/security-status"
    ) {
      return this.securityStatus();
    }

    if (
      request.method === "POST" &&
      url.pathname === "/security-state"
    ) {
      return this.setSecurityState(
        request
      );
    }

    if (
      request.method === "POST" &&
      url.pathname === "/audit"
    ) {
      return this.writeAudit(request);
    }

    if (
      request.method === "GET" &&
      url.pathname === "/audit-log"
    ) {
      return this.auditLog(url);
    }

    return Response.json(
      {
        ok: false,
        error: "PaymentGuard route not found"
      },
      { status: 404 }
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
        { status: 400 }
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
        { status: 400 }
      );
    }

    const storageKey =
      `payment:${requestId}`;

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
            budgetAuthorized: false,
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

    await this.appendAudit({
      eventType:
        result.allowed
          ? "payment_reserved"
          : "duplicate_blocked",
      stage: "idempotency-reservation",
      outcome:
        result.allowed
          ? "allowed"
          : "blocked",
      requestId,
      details: {
        duplicate:
          result.duplicate === true
      }
    });

    return Response.json({
      ok: true,
      ...result
    });
  }

  async authorizeBudget(request) {
    let body;

    try {
      body = await request.json();
    } catch {
      return Response.json(
        {
          ok: false,
          error: "Invalid JSON"
        },
        { status: 400 }
      );
    }

    const requestId =
      typeof body?.requestId === "string"
        ? body.requestId.trim()
        : "";

    const amountString =
      typeof body?.amount === "string"
        ? body.amount.trim()
        : "";

    if (!requestId) {
      return Response.json(
        {
          ok: false,
          error: "requestId is required"
        },
        { status: 400 }
      );
    }

    let amount;

    try {
      amount = BigInt(amountString);
    } catch {
      return Response.json(
        {
          ok: false,
          error: "amount is invalid"
        },
        { status: 400 }
      );
    }

    if (amount <= 0n) {
      return Response.json(
        {
          ok: false,
          error:
            "amount must be greater than zero"
        },
        { status: 400 }
      );
    }

    const nowMs = Date.now();
    const nowIso =
      new Date(nowMs).toISOString();

    const day =
      utcDayKey(nowMs);

    const paymentKey =
      `payment:${requestId}`;

    const dailyKey =
      `daily:${day}`;

    const velocityKey =
      "velocity:authorizations";

    const result =
      await this.ctx.storage.transaction(
        async (txn) => {
          const payment =
            await txn.get(paymentKey);

          if (!payment) {
            return {
              allowed: false,
              reason:
                "Payment reservation does not exist"
            };
          }

          if (
            payment.budgetAuthorized === true
          ) {
            return {
              allowed: false,
              reason:
                "Budget already authorized for this request",
              record: payment
            };
          }

          const daily =
            (await txn.get(dailyKey)) ?? {
              day,
              authorizedAtomic: "0",
              authorizationCount: 0
            };

          const dailyUsed =
            BigInt(
              daily.authorizedAtomic ?? "0"
            );

          const proposedDaily =
            dailyUsed + amount;

          if (
            proposedDaily >
            SPENDING_POLICY.dailyLimitAtomic
          ) {
            return {
              allowed: false,
              reason:
                "Daily spending authorization limit exceeded",
              dailyUsedAtomic:
                dailyUsed.toString(),
              requestedAtomic:
                amount.toString(),
              proposedDailyAtomic:
                proposedDaily.toString(),
              dailyLimitAtomic:
                SPENDING_POLICY.dailyLimitAtomic.toString()
            };
          }

          const storedVelocity =
            (await txn.get(
              velocityKey
            )) ?? [];

          const cutoff =
            nowMs -
            SPENDING_POLICY.velocityWindowMs;

          const recentVelocity =
            Array.isArray(
              storedVelocity
            )
              ? storedVelocity.filter(
                  (entry) =>
                    Number(
                      entry?.timestampMs
                    ) > cutoff
                )
              : [];

          if (
            recentVelocity.length >=
            SPENDING_POLICY.velocityMaxPayments
          ) {
            return {
              allowed: false,
              reason:
                "Payment velocity limit exceeded",
              recentAuthorizations:
                recentVelocity.length,
              velocityMaxPayments:
                SPENDING_POLICY.velocityMaxPayments,
              velocityWindow:
                SPENDING_POLICY.velocityWindowDisplay
            };
          }

          const updatedDaily = {
            day,
            authorizedAtomic:
              proposedDaily.toString(),
            authorizationCount:
              Number(
                daily.authorizationCount ??
                  0
              ) + 1,
            updatedAt: nowIso
          };

          const updatedVelocity = [
            ...recentVelocity,
            {
              requestId,
              amountAtomic:
                amount.toString(),
              timestampMs: nowMs,
              timestamp: nowIso
            }
          ];

          const updatedPayment = {
            ...payment,
            budgetAuthorized: true,
            budgetAuthorizedAtomic:
              amount.toString(),
            budgetAuthorizedAt:
              nowIso,
            updatedAt: nowIso
          };

          await txn.put(
            dailyKey,
            updatedDaily
          );

          await txn.put(
            velocityKey,
            updatedVelocity
          );

          await txn.put(
            paymentKey,
            updatedPayment
          );

          return {
            allowed: true,
            reason:
              "Persistent budget and velocity policy passed",
            amountAtomic:
              amount.toString(),
            dailyUsedBeforeAtomic:
              dailyUsed.toString(),
            dailyUsedAfterAtomic:
              proposedDaily.toString(),
            dailyLimitAtomic:
              SPENDING_POLICY.dailyLimitAtomic.toString(),
            recentAuthorizationsAfter:
              updatedVelocity.length,
            velocityMaxPayments:
              SPENDING_POLICY.velocityMaxPayments,
            velocityWindow:
              SPENDING_POLICY.velocityWindowDisplay,
            record:
              updatedPayment
          };
        }
      );

    await this.appendAudit({
      eventType:
        result.allowed
          ? "budget_authorized"
          : "budget_blocked",
      stage: "persistent-budget",
      outcome:
        result.allowed
          ? "allowed"
          : "blocked",
      requestId,
      details: {
        amountAtomic:
          amount.toString(),
        reason:
          result.reason ?? null
      }
    });

    return Response.json({
      ok: true,
      ...result
    });
  }

  async diagnosticAuthorizeBudget(
    request
  ) {
    let body;

    try {
      body = await request.json();
    } catch {
      return Response.json(
        {
          ok: false,
          error: "Invalid JSON"
        },
        { status: 400 }
      );
    }

    const testKey =
      typeof body?.testKey === "string"
        ? body.testKey.trim()
        : "";

    const requestId =
      typeof body?.requestId === "string"
        ? body.requestId.trim()
        : "";

    const amountString =
      typeof body?.amount === "string"
        ? body.amount.trim()
        : "";

    if (!testKey) {
      return Response.json(
        {
          ok: false,
          error: "testKey is required"
        },
        { status: 400 }
      );
    }

    if (!requestId) {
      return Response.json(
        {
          ok: false,
          error: "requestId is required"
        },
        { status: 400 }
      );
    }

    let amount;

    try {
      amount =
        BigInt(amountString);
    } catch {
      return Response.json(
        {
          ok: false,
          error: "amount is invalid"
        },
        { status: 400 }
      );
    }

    if (amount <= 0n) {
      return Response.json(
        {
          ok: false,
          error:
            "amount must be greater than zero"
        },
        { status: 400 }
      );
    }

    const nowMs = Date.now();

    const nowIso =
      new Date(
        nowMs
      ).toISOString();

    const day =
      utcDayKey(nowMs);

    const dailyKey =
      `diagnostic:${testKey}:daily:${day}`;

    const velocityKey =
      `diagnostic:${testKey}:velocity`;

    const requestKey =
      `diagnostic:${testKey}:request:${requestId}`;

    const result =
      await this.ctx.storage.transaction(
        async (txn) => {
          const existing =
            await txn.get(
              requestKey
            );

          if (existing) {
            return {
              allowed: false,
              duplicate: true,
              reason:
                "Diagnostic request already used",
              record: existing
            };
          }

          const daily =
            (await txn.get(
              dailyKey
            )) ?? {
              day,
              authorizedAtomic: "0",
              authorizationCount: 0
            };

          const dailyUsed =
            BigInt(
              daily.authorizedAtomic ??
                "0"
            );

          const proposedDaily =
            dailyUsed + amount;

          if (
            proposedDaily >
            SPENDING_POLICY.dailyLimitAtomic
          ) {
            const blockedRecord = {
              requestId,
              allowed: false,
              reason:
                "Daily spending authorization limit exceeded",
              createdAt: nowIso
            };

            await txn.put(
              requestKey,
              blockedRecord
            );

            return {
              allowed: false,
              duplicate: false,
              reason:
                "Daily spending authorization limit exceeded",
              dailyUsedAtomic:
                dailyUsed.toString(),
              requestedAtomic:
                amount.toString(),
              proposedDailyAtomic:
                proposedDaily.toString(),
              dailyLimitAtomic:
                SPENDING_POLICY.dailyLimitAtomic.toString()
            };
          }

          const storedVelocity =
            (await txn.get(
              velocityKey
            )) ?? [];

          const cutoff =
            nowMs -
            SPENDING_POLICY.velocityWindowMs;

          const recentVelocity =
            Array.isArray(
              storedVelocity
            )
              ? storedVelocity.filter(
                  (entry) =>
                    Number(
                      entry?.timestampMs
                    ) > cutoff
                )
              : [];

          if (
            recentVelocity.length >=
            SPENDING_POLICY.velocityMaxPayments
          ) {
            const blockedRecord = {
              requestId,
              allowed: false,
              reason:
                "Payment velocity limit exceeded",
              createdAt: nowIso
            };

            await txn.put(
              requestKey,
              blockedRecord
            );

            return {
              allowed: false,
              duplicate: false,
              reason:
                "Payment velocity limit exceeded",
              recentAuthorizations:
                recentVelocity.length,
              velocityMaxPayments:
                SPENDING_POLICY.velocityMaxPayments,
              velocityWindow:
                SPENDING_POLICY.velocityWindowDisplay
            };
          }

          const updatedDaily = {
            day,
            authorizedAtomic:
              proposedDaily.toString(),
            authorizationCount:
              Number(
                daily.authorizationCount ??
                  0
              ) + 1,
            updatedAt:
              nowIso
          };

          const updatedVelocity = [
            ...recentVelocity,
            {
              requestId,
              amountAtomic:
                amount.toString(),
              timestampMs:
                nowMs,
              timestamp:
                nowIso
            }
          ];

          const requestRecord = {
            requestId,
            allowed: true,
            amountAtomic:
              amount.toString(),
            createdAt:
              nowIso
          };

          await txn.put(
            dailyKey,
            updatedDaily
          );

          await txn.put(
            velocityKey,
            updatedVelocity
          );

          await txn.put(
            requestKey,
            requestRecord
          );

          return {
            allowed: true,
            duplicate: false,
            reason:
              "Diagnostic budget and velocity policy passed",
            amountAtomic:
              amount.toString(),
            dailyUsedBeforeAtomic:
              dailyUsed.toString(),
            dailyUsedAfterAtomic:
              proposedDaily.toString(),
            recentAuthorizationsAfter:
              updatedVelocity.length,
            velocityMaxPayments:
              SPENDING_POLICY.velocityMaxPayments,
            velocityWindow:
              SPENDING_POLICY.velocityWindowDisplay
          };
        }
      );

    return Response.json({
      ok: true,
      diagnostic: true,
      realBudgetModified:
        false,
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
        { status: 400 }
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
        { status: 400 }
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
        { status: 404 }
      );
    }

    const updated = {
      ...existing,
      status: "completed",
      updatedAt:
        new Date().toISOString(),
      result: body?.result ?? null
    };

    await this.ctx.storage.put(
      storageKey,
      updated
    );

    await this.appendAudit({
      eventType: "payment_completed",
      stage:
        body?.result?.stage ??
        "x402-payment",
      outcome: "completed",
      requestId,
      details: {
        finalStatus:
          body?.result?.finalStatus ??
          null,
        paymentResponsePresent:
          body?.result
            ?.paymentResponsePresent ??
          false
      }
    });

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
        { status: 400 }
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
        { status: 400 }
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
        { status: 404 }
      );
    }

    const updated = {
      ...existing,
      status: "failed",
      updatedAt:
        new Date().toISOString(),
      result: body?.result ?? null
    };

    await this.ctx.storage.put(
      storageKey,
      updated
    );

    await this.appendAudit({
      eventType: "payment_failed",
      stage:
        body?.result?.stage ??
        "unknown",
      outcome: "failed",
      requestId,
      details: {
        reason:
          body?.result?.reason ??
          body?.result?.error ??
          null,
        policyAllowed:
          body?.result
            ?.policyAllowed ??
          null,
        budgetAllowed:
          body?.result
            ?.budgetAllowed ??
          null,
        finalStatus:
          body?.result
            ?.finalStatus ??
          null
      }
    });

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
        { status: 400 }
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

  async budgetStatus() {
    const nowMs = Date.now();
    const day =
      utcDayKey(nowMs);

    const daily =
      (await this.ctx.storage.get(
        `daily:${day}`
      )) ?? {
        day,
        authorizedAtomic: "0",
        authorizationCount: 0
      };

    const storedVelocity =
      (await this.ctx.storage.get(
        "velocity:authorizations"
      )) ?? [];

    const cutoff =
      nowMs -
      SPENDING_POLICY.velocityWindowMs;

    const recentVelocity =
      Array.isArray(storedVelocity)
        ? storedVelocity.filter(
            (entry) =>
              Number(
                entry?.timestampMs
              ) > cutoff
          )
        : [];

    const dailyUsed =
      BigInt(
        daily.authorizedAtomic ?? "0"
      );

    const dailyRemaining =
      SPENDING_POLICY.dailyLimitAtomic >
      dailyUsed
        ? SPENDING_POLICY.dailyLimitAtomic -
          dailyUsed
        : 0n;

    return Response.json({
      ok: true,
      day,
      daily: {
        authorizedAtomic:
          dailyUsed.toString(),
        authorizedDisplay:
          atomicToUsdcString(
            dailyUsed
          ),
        limitAtomic:
          SPENDING_POLICY.dailyLimitAtomic.toString(),
        limitDisplay:
          SPENDING_POLICY.dailyLimitDisplay,
        remainingAtomic:
          dailyRemaining.toString(),
        remainingDisplay:
          atomicToUsdcString(
            dailyRemaining
          ),
        authorizationCount:
          Number(
            daily.authorizationCount ??
              0
          )
      },
      velocity: {
        window:
          SPENDING_POLICY.velocityWindowDisplay,
        maximum:
          SPENDING_POLICY.velocityMaxPayments,
        current:
          recentVelocity.length,
        remaining:
          Math.max(
            0,
            SPENDING_POLICY.velocityMaxPayments -
              recentVelocity.length
          )
      }
    });
  }

  async securityStatus() {
    const storageKey =
      "security:payment-control";

    const stored =
      await this.ctx.storage.get(
        storageKey
      );

    const paymentsEnabled =
      stored?.paymentsEnabled !== false;

    return Response.json({
      ok: true,
      paymentsEnabled,
      source:
        stored
          ? "persistent"
          : "default-enabled",
      changedAt:
        stored?.changedAt ?? null,
      changedBy:
        stored?.changedBy ?? null
    });
  }

  async setSecurityState(request) {
    let body;

    try {
      body = await request.json();
    } catch {
      return Response.json(
        {
          ok: false,
          error: "Invalid JSON"
        },
        { status: 400 }
      );
    }

    if (
      typeof body?.paymentsEnabled !==
      "boolean"
    ) {
      return Response.json(
        {
          ok: false,
          error:
            "paymentsEnabled boolean is required"
        },
        { status: 400 }
      );
    }

    const now =
      new Date().toISOString();

    const record = {
      paymentsEnabled:
        body.paymentsEnabled,
      changedAt: now,
      changedBy:
        typeof body?.changedBy ===
          "string" &&
        body.changedBy.trim()
          ? body.changedBy.trim()
          : "security-admin"
    };

    await this.ctx.storage.put(
      "security:payment-control",
      record
    );

    await this.appendAudit({
      eventType:
        body.paymentsEnabled
          ? "payments_enabled"
          : "payments_disabled",
      stage: "emergency-kill-switch",
      outcome: "allowed",
      requestId: null,
      details: {
        paymentsEnabled:
          body.paymentsEnabled,
        changedBy:
          record.changedBy
      }
    });

    return Response.json({
      ok: true,
      ...record
    });
  }

  async appendAudit(event) {
    const now =
      new Date().toISOString();

    return this.ctx.storage.transaction(
      async (txn) => {
        const sequenceKey =
          "audit:sequence";

        const current =
          Number(
            (await txn.get(
              sequenceKey
            )) ?? 0
          );

        const sequence =
          current + 1;

        const record = {
          sequence,
          timestamp: now,
          eventType:
            typeof event?.eventType ===
              "string" &&
            event.eventType.trim()
              ? event.eventType.trim()
              : "unknown",
          stage:
            typeof event?.stage ===
              "string" &&
            event.stage.trim()
              ? event.stage.trim()
              : null,
          outcome:
            typeof event?.outcome ===
              "string" &&
            event.outcome.trim()
              ? event.outcome.trim()
              : null,
          requestId:
            typeof event?.requestId ===
              "string" &&
            event.requestId.trim()
              ? event.requestId.trim()
              : null,
          details:
            sanitizeAuditValue(
              event?.details ?? null
            )
        };

        await txn.put(
          sequenceKey,
          sequence
        );

        await txn.put(
          `audit:event:${String(
            sequence
          ).padStart(12, "0")}`,
          record
        );

        return record;
      }
    );
  }

  async writeAudit(request) {
    let body;

    try {
      body = await request.json();
    } catch {
      return Response.json(
        {
          ok: false,
          error: "Invalid JSON"
        },
        { status: 400 }
      );
    }

    const record =
      await this.appendAudit(body);

    return Response.json({
      ok: true,
      record
    });
  }

  async auditLog(url) {
    const requested =
      Number(
        url.searchParams.get("limit") ??
          "50"
      );

    const limit =
      Number.isFinite(requested)
        ? Math.min(
            Math.max(
              Math.trunc(requested),
              1
            ),
            100
          )
        : 50;

    const entries =
      await this.ctx.storage.list({
        prefix: "audit:event:",
        reverse: true,
        limit
      });

    const records =
      Array.from(
        entries.values()
      );

    const sequence =
      Number(
        (await this.ctx.storage.get(
          "audit:sequence"
        )) ?? 0
      );

    return Response.json({
      ok: true,
      persistent: true,
      appendOnly: true,
      totalEvents: sequence,
      returned: records.length,
      records
    });
  }
}

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

  const id =
    env.PAYMENT_GUARD.idFromName(
      "sessionkey-payment-guard"
    );

  return env.PAYMENT_GUARD.get(id);
}

async function getSecurityState(env) {
  const guard =
    getPaymentGuard(env);

  const response =
    await guard.fetch(
      "https://payment-guard.internal/security-status"
    );

  const result =
    await response.json();

  if (!response.ok) {
    throw new Error(
      result?.error ??
        "Security status request failed"
    );
  }

  return result;
}

function isSecurityAdminAuthorized(c) {
  const expected =
    c.env?.SECURITY_ADMIN_TOKEN;

  if (
    typeof expected !== "string" ||
    !expected
  ) {
    return false;
  }

  const authorization =
    c.req.header("Authorization") ??
    "";

  const prefix =
    "Bearer ";

  if (
    !authorization.startsWith(
      prefix
    )
  ) {
    return false;
  }

  const supplied =
    authorization
      .slice(prefix.length)
      .trim();

  return (
    supplied.length > 0 &&
    supplied === expected
  );
}

async function setPaymentsEnabled(
  env,
  paymentsEnabled
) {
  return callGuard(
    env,
    "/security-state",
    "POST",
    {
      paymentsEnabled,
      changedBy:
        "security-admin-api"
    }
  );
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

async function logAudit(
  env,
  event
) {
  return callGuard(
    env,
    "/audit",
    "POST",
    event
  );
}

async function getAuditLog(
  env,
  limit = 50
) {
  const guard =
    getPaymentGuard(env);

  const safeLimit =
    Math.min(
      Math.max(
        Number(limit) || 50,
        1
      ),
      100
    );

  const response =
    await guard.fetch(
      `https://payment-guard.internal/audit-log?limit=${safeLimit}`
    );

  const result =
    await response.json();

  if (!response.ok) {
    throw new Error(
      result?.error ??
        "Audit log request failed"
    );
  }

  return result;
}

function decodeBase64Json(value) {
  if (
    typeof value !== "string" ||
    !value.trim()
  ) {
    throw new Error(
      "PAYMENT-REQUIRED header is missing"
    );
  }

  try {
    const decoded = atob(value);
    return JSON.parse(decoded);
  } catch {
    throw new Error(
      "PAYMENT-REQUIRED header is invalid"
    );
  }
}

function inspectPaymentPolicy(
  paymentRequired
) {
  if (
    !paymentRequired ||
    paymentRequired.x402Version !== 2
  ) {
    return {
      allowed: false,
      reason:
        "Unsupported or missing x402 version"
    };
  }

  if (
    !Array.isArray(
      paymentRequired.accepts
    ) ||
    paymentRequired.accepts.length === 0
  ) {
    return {
      allowed: false,
      reason:
        "Seller supplied no payment requirements"
    };
  }

  const matching =
    paymentRequired.accepts.find(
      (requirement) =>
        requirement?.scheme ===
          SPENDING_POLICY.scheme &&
        requirement?.network ===
          SPENDING_POLICY.network &&
        typeof requirement?.asset ===
          "string" &&
        requirement.asset.toLowerCase() ===
          SPENDING_POLICY.asset.toLowerCase() &&
        typeof requirement?.payTo ===
          "string" &&
        requirement.payTo.toLowerCase() ===
          SPENDING_POLICY.allowedRecipient.toLowerCase()
    );

  if (!matching) {
    return {
      allowed: false,
      reason:
        "No seller payment option matches the deterministic spending policy"
    };
  }

  let amount;

  try {
    amount =
      BigInt(matching.amount);
  } catch {
    return {
      allowed: false,
      reason:
        "Seller payment amount is invalid"
    };
  }

  if (amount <= 0n) {
    return {
      allowed: false,
      reason:
        "Seller payment amount must be greater than zero"
    };
  }

  if (
    amount >
    SPENDING_POLICY.maxTransactionAtomic
  ) {
    return {
      allowed: false,
      reason:
        `Payment exceeds maximum transaction policy of ${SPENDING_POLICY.maxTransactionDisplay}`,
      requirement: {
        scheme: matching.scheme,
        network: matching.network,
        amount: matching.amount,
        asset: matching.asset,
        payTo: matching.payTo
      }
    };
  }

  return {
    allowed: true,
    reason:
      "Payment requirement passed deterministic policy",
    requirement: {
      scheme: matching.scheme,
      network: matching.network,
      amount: matching.amount,
      asset: matching.asset,
      payTo: matching.payTo
    }
  };
}

async function fetchPaymentChallenge(
  env
) {
  const directFetch =
    getVegetablesFetch(env);

  const response =
    await directFetch(
      `${VEGETABLES.publicUrl}/premium`,
      {
        method: "GET",
        headers: {
          accept: "application/json"
        }
      }
    );

  if (response.status !== 402) {
    throw new Error(
      `Expected seller HTTP 402 challenge, received ${response.status}`
    );
  }

  const header =
    response.headers.get(
      "payment-required"
    );

  const paymentRequired =
    decodeBase64Json(header);

  return {
    response,
    paymentRequired
  };
}

app.get("/", (c) =>
  c.json({
    service:
      "Project Sessionkey x402 Payment",
    securityPhase: "13.6",

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
      idempotencyRequired: true,
      dailyBudgetEnforced: true,
      velocityLimitEnforced: true,
      emergencyKillSwitch: true,
      persistentAuditLog: true
    },

    spendingPolicy: {
      deterministic: true,
      failClosed: true,
      signerLoadsAfterPolicy: true,

      scheme:
        SPENDING_POLICY.scheme,

      network:
        SPENDING_POLICY.network,

      asset:
        SPENDING_POLICY.assetSymbol,

      assetContract:
        SPENDING_POLICY.asset,

      maximumTransaction:
        SPENDING_POLICY.maxTransactionDisplay,

      dailyLimit:
        SPENDING_POLICY.dailyLimitDisplay,

      velocity:
        `${SPENDING_POLICY.velocityMaxPayments} payments / ${SPENDING_POLICY.velocityWindowDisplay}`,

      allowedRecipient:
        SPENDING_POLICY.allowedRecipient
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
      "GET /policy",
      "GET /policy-check",
      "GET /budget-status",
      "GET /budget-self-test",
      "GET /security-status",
      "GET /audit-status",
      "GET /signer-check",
      "GET /binding-check",
      "GET /guard-self-test",
      "GET /pay-vegetables"
    ],

    protectedAdminEndpoints: [
      "POST /admin/payments/disable",
      "POST /admin/payments/enable",
      "GET /admin/audit-log",
      "POST /admin/audit-self-test"
    ],

    adminAuthentication:
      "Authorization: Bearer <SECURITY_ADMIN_TOKEN>"
  })
);

app.get("/health", (c) =>
  c.json({
    ok: true,
    service:
      "project-sessionkey-x402-payment",
    securityPhase: "13.6",

    paymentGuardConfigured:
      Boolean(
        c.env?.PAYMENT_GUARD
      ),

    spendingPolicyConfigured:
      true,

    dailyBudgetConfigured:
      true,

    velocityLimitConfigured:
      true,

    diagnosticBudgetTestConfigured:
      true,

    emergencyKillSwitchConfigured:
      true,

    persistentAuditLogConfigured:
      true,

    securityAdminSecretConfigured:
      Boolean(
        c.env?.SECURITY_ADMIN_TOKEN
      )
  })
);

app.get("/policy", (c) =>
  c.json({
    ok: true,
    securityPhase: "13.6",
    paymentAttempted: false,
    signerLoaded: false,

    policy: {
      deterministic: true,
      failClosed: true,

      allowedScheme:
        SPENDING_POLICY.scheme,

      allowedNetwork:
        SPENDING_POLICY.network,

      allowedAsset:
        SPENDING_POLICY.assetSymbol,

      allowedAssetContract:
        SPENDING_POLICY.asset,

      maximumTransaction:
        SPENDING_POLICY.maxTransactionDisplay,

      dailyLimit:
        SPENDING_POLICY.dailyLimitDisplay,

      velocityMaxPayments:
        SPENDING_POLICY.velocityMaxPayments,

      velocityWindow:
        SPENDING_POLICY.velocityWindowDisplay,

      allowedRecipient:
        SPENDING_POLICY.allowedRecipient
    }
  })
);

app.get(
  "/policy-check",
  async (c) => {
    try {
      const {
        paymentRequired
      } =
        await fetchPaymentChallenge(
          c.env
        );

      const decision =
        inspectPaymentPolicy(
          paymentRequired
        );

      return c.json({
        ok: decision.allowed,
        securityPhase: "13.6",
        test:
          "deterministic-spending-policy",
        signerLoaded: false,
        paymentAttempted: false,
        decision,
        sellerChallenge: {
          x402Version:
            paymentRequired.x402Version,
          accepts:
            paymentRequired.accepts
        }
      });
    } catch (error) {
      return c.json(
        {
          ok: false,
          securityPhase: "13.6",
          signerLoaded: false,
          paymentAttempted: false,
          decision: {
            allowed: false,
            reason:
              "Policy check failed closed"
          },
          error:
            error?.message ??
            String(error)
        },
        500
      );
    }
  }
);

app.get(
  "/budget-status",
  async (c) => {
    try {
      const guard =
        getPaymentGuard(c.env);

      const response =
        await guard.fetch(
          "https://payment-guard.internal/budget-status"
        );

      const result =
        await response.json();

      return c.json({
        ...result,
        securityPhase: "13.6",
        signerLoaded: false,
        paymentAttempted: false
      });
    } catch (error) {
      return c.json(
        {
          ok: false,
          securityPhase: "13.6",
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

app.get(
  "/budget-self-test",
  async (c) => {
    try {
      const suppliedKey =
        c.req
          .query("key")
          ?.trim();

      const testKey =
        suppliedKey ||
        `budget-${Date.now()}`;

      const amount =
        "10000";

      const results = [];

      for (
        let i = 1;
        i <= 4;
        i += 1
      ) {
        const result =
          await callGuard(
            c.env,
            "/diagnostic-authorize-budget",
            "POST",
            {
              testKey,
              requestId:
                `attempt-${i}`,
              amount
            }
          );

        results.push({
          attempt: i,
          requestedAtomic:
            amount,
          requestedDisplay:
            "0.01 USDC",
          allowed:
            result.allowed,
          duplicate:
            result.duplicate ??
            false,
          reason:
            result.reason,
          recentAuthorizationsAfter:
            result.recentAuthorizationsAfter ??
            result.recentAuthorizations ??
            null,
          diagnostic: true
        });
      }

      const expected =
        results[0]?.allowed ===
          true &&
        results[1]?.allowed ===
          true &&
        results[2]?.allowed ===
          true &&
        results[3]?.allowed ===
          false &&
        results[3]?.reason ===
          "Payment velocity limit exceeded";

      return c.json({
        ok: expected,
        securityPhase:
          "13.6",
        test:
          "isolated-budget-velocity-self-test",
        testKey,
        signerLoaded:
          false,
        paymentAttempted:
          false,
        realBudgetModified:
          false,
        diagnosticAmountEach:
          "0.01 USDC",
        policy: {
          dailyLimit:
            SPENDING_POLICY.dailyLimitDisplay,
          velocityMaximum:
            SPENDING_POLICY.velocityMaxPayments,
          velocityWindow:
            SPENDING_POLICY.velocityWindowDisplay
        },
        results,
        expected: {
          attempt1:
            "ALLOW",
          attempt2:
            "ALLOW",
          attempt3:
            "ALLOW",
          attempt4:
            "BLOCK_VELOCITY"
        }
      });
    } catch (error) {
      return c.json(
        {
          ok: false,
          securityPhase:
            "13.6",
          test:
            "isolated-budget-velocity-self-test",
          signerLoaded:
            false,
          paymentAttempted:
            false,
          realBudgetModified:
            false,
          error:
            error?.message ??
            String(error)
        },
        500
      );
    }
  }
);

app.get(
  "/security-status",
  async (c) => {
    try {
      const state =
        await getSecurityState(
          c.env
        );

      return c.json({
        ok: true,
        securityPhase: "13.6",
        paymentsEnabled:
          state.paymentsEnabled,
        killSwitchActive:
          state.paymentsEnabled === false,
        source:
          state.source,
        changedAt:
          state.changedAt,
        changedBy:
          state.changedBy,
        signerLoaded: false,
        paymentAttempted: false
      });
    } catch (error) {
      return c.json(
        {
          ok: false,
          securityPhase: "13.6",
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

app.post(
  "/admin/payments/disable",
  async (c) => {
    if (
      !isSecurityAdminAuthorized(c)
    ) {
      return c.json(
        {
          ok: false,
          securityPhase: "13.6",
          signerLoaded: false,
          paymentAttempted: false,
          error: "Unauthorized"
        },
        401
      );
    }

    try {
      const state =
        await setPaymentsEnabled(
          c.env,
          false
        );

      return c.json({
        ok: true,
        securityPhase: "13.6",
        paymentsEnabled:
          state.paymentsEnabled,
        killSwitchActive: true,
        changedAt:
          state.changedAt,
        signerLoaded: false,
        paymentAttempted: false
      });
    } catch (error) {
      return c.json(
        {
          ok: false,
          securityPhase: "13.6",
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

app.post(
  "/admin/payments/enable",
  async (c) => {
    if (
      !isSecurityAdminAuthorized(c)
    ) {
      return c.json(
        {
          ok: false,
          securityPhase: "13.6",
          signerLoaded: false,
          paymentAttempted: false,
          error: "Unauthorized"
        },
        401
      );
    }

    try {
      const state =
        await setPaymentsEnabled(
          c.env,
          true
        );

      return c.json({
        ok: true,
        securityPhase: "13.6",
        paymentsEnabled:
          state.paymentsEnabled,
        killSwitchActive: false,
        changedAt:
          state.changedAt,
        signerLoaded: false,
        paymentAttempted: false
      });
    } catch (error) {
      return c.json(
        {
          ok: false,
          securityPhase: "13.6",
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


app.get(
  "/audit-status",
  async (c) => {
    try {
      const audit =
        await getAuditLog(
          c.env,
          1
        );

      return c.json({
        ok: true,
        securityPhase: "13.6",
        persistent:
          audit.persistent === true,
        appendOnly:
          audit.appendOnly === true,
        totalEvents:
          audit.totalEvents,
        signerLoaded: false,
        paymentAttempted: false
      });
    } catch (error) {
      return c.json(
        {
          ok: false,
          securityPhase: "13.6",
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

app.get(
  "/admin/audit-log",
  async (c) => {
    if (
      !isSecurityAdminAuthorized(c)
    ) {
      try {
        await logAudit(
          c.env,
          {
            eventType:
              "audit_log_access_denied",
            stage: "audit",
            outcome: "blocked",
            details: {
              endpoint:
                "/admin/audit-log"
            }
          }
        );
      } catch {
        // fail closed on access;
        // audit failure does not reveal data
      }

      return c.json(
        {
          ok: false,
          securityPhase: "13.6",
          signerLoaded: false,
          paymentAttempted: false,
          error: "Unauthorized"
        },
        401
      );
    }

    try {
      const limit =
        c.req.query("limit") ??
        "50";

      const audit =
        await getAuditLog(
          c.env,
          limit
        );

      return c.json({
        ...audit,
        securityPhase: "13.6",
        secretsIncluded: false,
        signerLoaded: false,
        paymentAttempted: false
      });
    } catch (error) {
      return c.json(
        {
          ok: false,
          securityPhase: "13.6",
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

app.post(
  "/admin/audit-self-test",
  async (c) => {
    if (
      !isSecurityAdminAuthorized(c)
    ) {
      return c.json(
        {
          ok: false,
          securityPhase: "13.6",
          signerLoaded: false,
          paymentAttempted: false,
          error: "Unauthorized"
        },
        401
      );
    }

    const testKey =
      `audit-test-${Date.now()}`;

    try {
      const first =
        await logAudit(
          c.env,
          {
            eventType:
              "audit_self_test_started",
            stage: "audit-self-test",
            outcome: "diagnostic",
            requestId: testKey,
            details: {
              paymentCapable: false,
              testKey
            }
          }
        );

      const second =
        await logAudit(
          c.env,
          {
            eventType:
              "audit_self_test_completed",
            stage: "audit-self-test",
            outcome: "diagnostic",
            requestId: testKey,
            details: {
              paymentCapable: false,
              testKey
            }
          }
        );

      const audit =
        await getAuditLog(
          c.env,
          100
        );

      const matching =
        audit.records.filter(
          (record) =>
            record?.requestId ===
            testKey
        );

      const passed =
        matching.length === 2 &&
        matching.some(
          (record) =>
            record.eventType ===
            "audit_self_test_started"
        ) &&
        matching.some(
          (record) =>
            record.eventType ===
            "audit_self_test_completed"
        ) &&
        Number(
          second?.record?.sequence
        ) >
          Number(
            first?.record?.sequence
          );

      return c.json({
        ok: passed,
        securityPhase: "13.6",
        test:
          "persistent-append-only-audit-log",
        testKey,
        persistent:
          audit.persistent === true,
        appendOnly:
          audit.appendOnly === true,
        recordsFound:
          matching.length,
        sequences:
          matching
            .map(
              (record) =>
                record.sequence
            )
            .sort(
              (a, b) =>
                a - b
            ),
        signerLoaded: false,
        paymentAttempted: false,
        realBudgetModified: false,
        paymentExecuted: false
      });
    } catch (error) {
      return c.json(
        {
          ok: false,
          securityPhase: "13.6",
          test:
            "persistent-append-only-audit-log",
          signerLoaded: false,
          paymentAttempted: false,
          realBudgetModified: false,
          paymentExecuted: false,
          error:
            error?.message ??
            String(error)
        },
        500
      );
    }
  }
);

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

        securityPhase: "13.6",

        test:
          "persistent-idempotency",

        requestId,

        signerLoaded: false,
        paymentAttempted: false,

        firstReservation: first,
        secondReservation: second,

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

        securityPhase: "13.6"
      },
      405,
      {
        Allow: "POST"
      }
    )
);

app.post(
  "/pay-vegetables",
  async (c) => {
    const requestId =
      c.req
        .header("Idempotency-Key")
        ?.trim();

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

    let securityState;

    try {
      securityState =
        await getSecurityState(
          c.env
        );
    } catch (error) {
      return c.json(
        {
          ok: false,
          requestId,
          stage:
            "emergency-kill-switch",
          signerLoaded: false,
          paymentAttempted: false,
          error:
            error?.message ??
            String(error)
        },
        500
      );
    }

    if (
      securityState.paymentsEnabled ===
      false
    ) {
      try {
        await logAudit(
          c.env,
          {
            eventType:
              "payment_blocked_kill_switch",
            stage:
              "emergency-kill-switch",
            outcome: "blocked",
            requestId,
            details: {
              paymentsEnabled: false,
              signerLoaded: false,
              paymentAttempted: false
            }
          }
        );
      } catch {
        // payment remains blocked
      }

      return c.json(
        {
          ok: false,
          requestId,
          securityPhase: "13.6",
          stage:
            "emergency-kill-switch",
          paymentsEnabled: false,
          killSwitchActive: true,
          signerLoaded: false,
          paymentAttempted: false,
          message:
            "Payments are disabled by security policy."
        },
        503
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
                SESSIONKEY.network,

              securityPhase:
                "13.6"
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

    let policyDecision;

    try {
      const {
        paymentRequired
      } =
        await fetchPaymentChallenge(
          c.env
        );

      policyDecision =
        inspectPaymentPolicy(
          paymentRequired
        );

      if (!policyDecision.allowed) {
        await callGuard(
          c.env,
          "/fail",
          "POST",
          {
            requestId,

            result: {
              stage:
                "spending-policy",

              policyAllowed: false,

              reason:
                policyDecision.reason,

              signerLoaded: false,
              paymentAttempted: false
            }
          }
        );

        return c.json(
          {
            ok: false,
            requestId,

            stage:
              "spending-policy",

            policyAllowed: false,
            signerLoaded: false,
            paymentAttempted: false,

            decision:
              policyDecision
          },
          403
        );
      }
    } catch (error) {
      try {
        await callGuard(
          c.env,
          "/fail",
          "POST",
          {
            requestId,

            result: {
              stage:
                "spending-policy",

              policyAllowed: false,
              signerLoaded: false,
              paymentAttempted: false,

              error:
                error?.message ??
                String(error)
            }
          }
        );
      } catch {
        // fail closed
      }

      return c.json(
        {
          ok: false,
          requestId,

          stage:
            "spending-policy",

          policyAllowed: false,
          signerLoaded: false,
          paymentAttempted: false,

          error:
            error?.message ??
            String(error)
        },
        500
      );
    }

    let budgetDecision;

    try {
      budgetDecision =
        await callGuard(
          c.env,
          "/authorize-budget",
          "POST",
          {
            requestId,
            amount:
              policyDecision.requirement.amount
          }
        );
    } catch (error) {
      try {
        await callGuard(
          c.env,
          "/fail",
          "POST",
          {
            requestId,

            result: {
              stage:
                "persistent-budget",

              budgetAllowed: false,
              signerLoaded: false,
              paymentAttempted: false,

              error:
                error?.message ??
                String(error)
            }
          }
        );
      } catch {
        // fail closed
      }

      return c.json(
        {
          ok: false,
          requestId,

          stage:
            "persistent-budget",

          budgetAllowed: false,
          signerLoaded: false,
          paymentAttempted: false,

          error:
            error?.message ??
            String(error)
        },
        500
      );
    }

    if (!budgetDecision.allowed) {
      await callGuard(
        c.env,
        "/fail",
        "POST",
        {
          requestId,

          result: {
            stage:
              "persistent-budget",

            budgetAllowed: false,

            reason:
              budgetDecision.reason,

            signerLoaded: false,
            paymentAttempted: false
          }
        }
      );

      return c.json(
        {
          ok: false,
          requestId,

          stage:
            "persistent-budget",

          policyAllowed: true,
          budgetAllowed: false,
          signerLoaded: false,
          paymentAttempted: false,

          decision:
            budgetDecision
        },
        429
      );
    }

    try {
      const account =
        getSessionkeyAccount(c.env);

      const directFetch =
        getVegetablesFetch(c.env);

      const client =
        new x402Client();

      client.register(
        SESSIONKEY.network,
        new ExactEvmScheme(account)
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
              stage:
                "x402-payment",

              policyAllowed: true,
              budgetAllowed: true,

              policyDecision,
              budgetDecision,

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

            policyAllowed: true,
            budgetAllowed: true,

            policyDecision,
            budgetDecision,

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
            stage:
              "x402-payment",

            policyAllowed: true,
            budgetAllowed: true,

            policyDecision,
            budgetDecision,

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

        securityPhase:
          "13.6",

        policyAllowed: true,
        budgetAllowed: true,

        policyDecision,
        budgetDecision,

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
      try {
        await callGuard(
          c.env,
          "/fail",
          "POST",
          {
            requestId,

            result: {
              stage:
                "x402-payment",

              policyAllowed: true,
              budgetAllowed: true,

              policyDecision,
              budgetDecision,

              error:
                error?.message ??
                String(error),

              failedAt:
                new Date().toISOString()
            }
          }
        );
      } catch {
        // intentionally swallowed
      }

      return c.json(
        {
          ok: false,
          requestId,

          policyAllowed: true,
          budgetAllowed: true,

          policyDecision,
          budgetDecision,

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
        "GET /policy",
        "GET /policy-check",
        "GET /budget-status",
        "GET /budget-self-test",
        "GET /security-status",
        "GET /audit-status",
        "GET /signer-check",
        "GET /binding-check",
        "GET /guard-self-test",
        "GET /pay-vegetables",
        "POST /pay-vegetables",
        "POST /admin/payments/disable",
        "POST /admin/payments/enable",
        "GET /admin/audit-log",
        "POST /admin/audit-self-test"
      ]
    },
    404
  )
);

export default app;
