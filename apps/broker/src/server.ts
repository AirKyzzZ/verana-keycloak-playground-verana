import type Provider from "oidc-provider";
import QRCode from "qrcode";

import { type InteractionStatus, renderInteractionPage } from "./html.js";
import type { LoginService } from "./login-service.js";
import type { TransactionStore } from "./transaction-store.js";
import type { LoginTransaction } from "./types.js";

type LoginServiceContract = Pick<LoginService, "start" | "poll">;

export interface InteractionRouteOptions {
  loginService: LoginServiceContract;
  transactionStore: TransactionStore;
}

type PublicStatus =
  | Pick<LoginTransaction, "status" | "errorCode">
  | {
      status: "expired";
      errorCode?: string;
    };

function publicStatus(
  status: InteractionStatus,
  errorCode?: string,
): PublicStatus {
  return errorCode ? { status, errorCode } : { status };
}

export function attachInteractionRoutes(
  provider: Provider,
  { loginService, transactionStore }: InteractionRouteOptions,
): Provider {
  const startedInteractions = new Set<string>();
  const failedStarts = new Set<string>();
  const starts = new Map<string, Promise<LoginTransaction>>();

  const resolveStatus = async (uid: string): Promise<PublicStatus> => {
    if (failedStarts.has(uid)) {
      return {
        status: "unavailable",
        errorCode: "vs_agent_unavailable",
      };
    }

    const transaction = transactionStore.get(uid);
    if (!transaction) {
      return {
        status: "expired",
        errorCode: "transaction_expired",
      };
    }

    const state = await loginService.poll(uid);
    return publicStatus(state.status, state.errorCode);
  };

  const startInteraction = async (uid: string): Promise<LoginTransaction> => {
    const activeStart = starts.get(uid);
    if (activeStart) return await activeStart;

    startedInteractions.add(uid);
    const start = loginService.start(uid);
    starts.set(uid, start);

    try {
      return await start;
    } catch {
      failedStarts.add(uid);
      throw new Error("vs_agent_unavailable");
    } finally {
      starts.delete(uid);
    }
  };

  provider.use(async (context, next) => {
    if (!context.path.startsWith("/interaction/")) {
      await next();
      return;
    }

    context.set("Cache-Control", "no-store");

    if (context.method !== "GET") {
      context.status = 405;
      context.body = "Method Not Allowed";
      return;
    }

    const match = context.path.match(
      /^\/interaction\/([^/]+)(?:\/(status|complete))?$/,
    );
    if (!match) {
      context.status = 404;
      context.body = "Not Found";
      return;
    }

    const uid = decodeURIComponent(match[1] ?? "");
    const action = match[2];

    let interaction: Awaited<ReturnType<Provider["interactionDetails"]>>;
    try {
      interaction = await provider.interactionDetails(context.req, context.res);
    } catch {
      context.status = 404;
      context.body =
        action === "status"
          ? publicStatus("expired", "interaction_not_found")
          : "Interaction not found";
      return;
    }

    if (interaction.uid !== uid) {
      context.status = 404;
      context.body =
        action === "status"
          ? publicStatus("expired", "interaction_not_found")
          : "Interaction not found";
      return;
    }

    if (action === "status") {
      context.type = "application/json";
      context.body = await resolveStatus(uid);
      return;
    }

    if (action === "complete") {
      const status = await resolveStatus(uid);
      if (status.status !== "verified") {
        context.status = 409;
        context.type = "application/json";
        context.body = status;
        return;
      }

      const transaction = transactionStore.get(uid);
      const state = await loginService.poll(uid);
      if (
        transaction?.status !== "pending" ||
        state.status !== "verified" ||
        !state.accountId
      ) {
        context.status = 409;
        context.type = "application/json";
        context.body = publicStatus(
          transaction?.status ?? "expired",
          transaction ? undefined : "transaction_expired",
        );
        return;
      }

      transactionStore.complete(uid, state.accountId);
      await provider.interactionFinished(
        context.req,
        context.res,
        { login: { accountId: state.accountId } },
        { mergeWithLastSubmission: false },
      );
      return;
    }

    let transaction = transactionStore.get(uid);
    let status: PublicStatus;

    if (!transaction && (!startedInteractions.has(uid) || starts.has(uid))) {
      try {
        transaction = await startInteraction(uid);
        status = publicStatus(transaction.status);
      } catch {
        status = publicStatus("unavailable", "vs_agent_unavailable");
      }
    } else {
      status = await resolveStatus(uid);
    }

    const qrDataUrl = transaction
      ? await QRCode.toDataURL(transaction.authorizationRequest, {
          errorCorrectionLevel: "M",
          margin: 2,
          width: 320,
        })
      : undefined;

    context.type = "text/html";
    context.body = renderInteractionPage({
      uid,
      status: status.status,
      ...(transaction
        ? { authorizationRequest: transaction.authorizationRequest }
        : {}),
      ...(qrDataUrl ? { qrDataUrl } : {}),
      ...(status.errorCode ? { errorCode: status.errorCode } : {}),
    });
  });

  return provider;
}
