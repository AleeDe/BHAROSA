import makeWASocket, {
  DisconnectReason,
  useMultiFileAuthState,
} from "@whiskeysockets/baileys";
import pino from "pino";
import qrcode from "qrcode-terminal";

import { registerMessageHandler } from "./messageHandler.js";

/** Folder at the project root where Baileys persists session credentials. */
const AUTH_FOLDER = "auth";

/** Delay after a transient drop (connection closed/lost, timeout). */
const TRANSIENT_RETRY_MS = 3000;

/** Delay after WhatsApp asks us to restart the socket. */
const RESTART_RETRY_MS = 1500;

/**
 * Delay after the session was claimed by another connection.
 *
 * Deliberately long: a tight retry here turns into two processes evicting each
 * other in a loop, which is the failure this constant exists to avoid.
 */
const REPLACED_RETRY_MS = 10_000;

/** Delay for disconnect codes we do not specifically recognize. */
const UNKNOWN_RETRY_MS = 5000;

/** Silenced so Baileys' internal protocol logs stay out of the terminal. */
const logger = pino({ level: "silent" });

/** Human-readable names for the disconnect codes Baileys reports. */
const DISCONNECT_REASONS: Record<number, string> = {
  [DisconnectReason.loggedOut]: "loggedOut",
  [DisconnectReason.forbidden]: "forbidden",
  // connectionLost shares code 408 with timedOut.
  [DisconnectReason.timedOut]: "timedOut/connectionLost",
  [DisconnectReason.multideviceMismatch]: "multideviceMismatch",
  [DisconnectReason.connectionClosed]: "connectionClosed",
  [DisconnectReason.connectionReplaced]: "connectionReplaced",
  [DisconnectReason.badSession]: "badSession",
  [DisconnectReason.unavailableService]: "unavailableService",
  [DisconnectReason.restartRequired]: "restartRequired",
};

/**
 * Reads the HTTP-style status code Baileys attaches to disconnect errors.
 *
 * Baileys reports these as Boom errors, which carry the code at
 * `error.output.statusCode`. Read structurally so we do not depend on
 * `@hapi/boom` being a direct dependency.
 */
function getDisconnectStatusCode(error: unknown): number | undefined {
  const output = (error as { output?: { statusCode?: unknown } } | undefined)
    ?.output;
  return typeof output?.statusCode === "number" ? output.statusCode : undefined;
}

/** Names a disconnect code for logging. */
function describeReason(statusCode: number | undefined): string {
  if (statusCode === undefined) {
    return "unknown";
  }
  return DISCONNECT_REASONS[statusCode] ?? "unrecognized";
}

/**
 * Opens a WhatsApp socket and keeps it alive.
 *
 * Resolves once a connection has been established. Recoverable disconnects are
 * retried in the background with a delay chosen per disconnect reason; an
 * explicit logout stops the retry loop.
 *
 * At most one socket and one pending retry exist at any moment.
 */
export async function connectWhatsApp(): Promise<void> {
  const { state, saveCreds } = await useMultiFileAuthState(AUTH_FOLDER);

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    let reconnectTimer: NodeJS.Timeout | undefined;
    /** Guards against two close events both queueing a socket. */
    let reconnecting = false;

    /** Queues exactly one reconnect attempt, discarding any later request. */
    const scheduleReconnect = (delayMs: number): void => {
      if (reconnecting) {
        return;
      }
      reconnecting = true;

      reconnectTimer = setTimeout(() => {
        reconnectTimer = undefined;
        reconnecting = false;
        start();
      }, delayMs);
    };

    const start = (): void => {
      const sock = makeWASocket({
        auth: state,
        logger,
      });

      sock.ev.on("creds.update", saveCreds);

      registerMessageHandler(sock);

      sock.ev.on("connection.update", (update) => {
        const { connection, qr, lastDisconnect } = update;

        if (qr) {
          qrcode.generate(qr, { small: true });
          console.log("Scan this QR using WhatsApp > Linked Devices");
        }

        if (connection === "open") {
          if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = undefined;
          }
          reconnecting = false;

          console.log("WhatsApp connected.");
          if (!settled) {
            settled = true;
            resolve();
          }
          return;
        }

        if (connection === "close") {
          const statusCode = getDisconnectStatusCode(lastDisconnect?.error);
          console.log(
            `WhatsApp disconnected. Code: ${statusCode ?? "unknown"}. Reason: ${describeReason(statusCode)}`,
          );

          if (statusCode === DisconnectReason.loggedOut) {
            console.log(
              "WhatsApp logged out. Delete the auth folder and pair again.",
            );
            if (!settled) {
              settled = true;
              reject(new Error("WhatsApp session logged out."));
            }
            return;
          }

          if (statusCode === DisconnectReason.connectionReplaced) {
            console.log("WhatsApp session was replaced by another connection.");
            console.log(
              "Make sure only one Digital Shield process is running.",
            );
            scheduleReconnect(REPLACED_RETRY_MS);
            return;
          }

          if (statusCode === DisconnectReason.restartRequired) {
            scheduleReconnect(RESTART_RETRY_MS);
            return;
          }

          if (
            statusCode === DisconnectReason.connectionClosed ||
            statusCode === DisconnectReason.timedOut
          ) {
            scheduleReconnect(TRANSIENT_RETRY_MS);
            return;
          }

          scheduleReconnect(UNKNOWN_RETRY_MS);
        }
      });
    };

    start();
  });
}
