import {
  getContentType,
  normalizeMessageContent,
  type WAMessage,
  type WAMessageContent,
  type WASocket,
} from "@whiskeysockets/baileys";

import { analyzeImage } from "../analyzers/imageAnalyzer.js";
import { analyzeText } from "../analyzers/textAnalyzer.js";
import {
  ANALYSIS_UNAVAILABLE_MESSAGE,
  formatImageAnalysis,
  formatTextAnalysis,
  IMAGE_ANALYSIS_UNAVAILABLE_MESSAGE,
} from "../risk/formatter.js";
import type { IncomingMessage } from "../types/message.js";
import { saveImageMessage } from "./media.js";

/** Pseudo-chat WhatsApp uses for status updates; never worth processing. */
const STATUS_BROADCAST = "status@broadcast";

/**
 * Pulls the body text out of a message.
 *
 * Covers the two shapes plain text arrives in: a bare `conversation` string and
 * the `extendedTextMessage` used when the text carries context such as a reply.
 */
function extractText(content: WAMessageContent): string | undefined {
  const conversation = content.conversation;
  if (conversation) {
    return conversation;
  }

  return content.extendedTextMessage?.text ?? undefined;
}

/**
 * Normalizes a raw Baileys message into an {@link IncomingMessage}.
 *
 * Dispatches on the presence of `imageMessage` rather than on
 * `getContentType`, which returns whichever `*Message*` key appears first and
 * so can report a sibling field such as `messageContextInfo` for a real image.
 * `getContentType` is still used to label unsupported messages.
 *
 * Images are downloaded to `./temp` as part of normalizing, so a returned
 * `image` always refers to a file that exists on disk. A download failure
 * propagates rather than degrading to `unsupported`, which would hide the
 * cause.
 */
async function normalizeMessage(
  message: WAMessage,
  sock: WASocket,
): Promise<IncomingMessage | undefined> {
  const chatId = message.key.remoteJid;
  const id = message.key.id;

  if (!chatId || !id) {
    return undefined;
  }

  // Unwraps ephemeral and view-once envelopes so the real content is reachable.
  const content = normalizeMessageContent(message.message);
  if (!content) {
    return undefined;
  }

  const imageMessage = content.imageMessage;
  if (imageMessage) {
    const saved = await saveImageMessage(
      message,
      imageMessage.mimetype ?? undefined,
      sock.updateMediaMessage,
    );

    return {
      id,
      chatId,
      type: "image",
      image: {
        filePath: saved.filePath,
        mimeType: saved.mimeType,
        caption: imageMessage.caption ?? undefined,
      },
    };
  }

  const text = extractText(content);
  if (text !== undefined) {
    return { id, chatId, type: "text", text };
  }

  return { id, chatId, type: "unsupported" };
}

/**
 * Writes a normalized message to the terminal.
 *
 * Unsupported messages report only their top-level content type; the message
 * body is never printed, since it may hold sensitive data.
 */
function logMessage(
  incoming: IncomingMessage,
  contentType: string | undefined,
): void {
  if (incoming.type === "text") {
    // The message body is deliberately not logged; it is sent to the analyzer
    // instead, and logging it here would serve no purpose.
    console.log("[TEXT]");
    console.log(`Chat: ${incoming.chatId}`);
    return;
  }

  if (incoming.type === "image" && incoming.image) {
    console.log("[IMAGE]");
    console.log(`Chat: ${incoming.chatId}`);
    console.log(`Saved: ${incoming.image.filePath}`);
    if (incoming.image.caption) {
      console.log(`Caption: ${incoming.image.caption}`);
    }
    return;
  }

  console.log("[UNSUPPORTED]");
  console.log(`Type: ${contentType ?? "unknown"}`);
}

/**
 * Analyzes a message and replies to the chat it came from.
 *
 * Exactly one analysis and one reply per message. Analyzer failures are
 * reported to the terminal in full and to the user as generic safe guidance,
 * so provider details never reach the chat.
 */
async function analyzeAndReply(
  sock: WASocket,
  chatId: string,
  text: string,
): Promise<void> {
  let reply: string;

  try {
    const result = await analyzeText(text);
    reply = formatTextAnalysis(result);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    console.error("[ANALYSIS ERROR]");
    console.error(`Chat: ${chatId}`);
    console.error(`Reason: ${reason}`);

    reply = ANALYSIS_UNAVAILABLE_MESSAGE;
  }

  await sock.sendMessage(chatId, { text: reply });
}

/**
 * Analyzes a downloaded image and replies to the chat it came from.
 *
 * Exactly one analysis and one reply per image. Analyzer failures are reported
 * to the terminal in full and to the user as generic safe guidance, so status
 * codes, file paths, and provider details never reach the chat.
 */
async function analyzeImageAndReply(
  sock: WASocket,
  chatId: string,
  filePath: string,
): Promise<void> {
  let reply: string;

  try {
    const result = await analyzeImage(filePath);
    reply = formatImageAnalysis(result);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    console.error("[IMAGE ANALYSIS ERROR]");
    console.error(`Chat: ${chatId}`);
    console.error(`Reason: ${reason}`);

    reply = IMAGE_ANALYSIS_UNAVAILABLE_MESSAGE;
  }

  await sock.sendMessage(chatId, { text: reply });
}

/**
 * Attaches incoming-message handling to a socket.
 *
 * Only freshly delivered messages are processed; history syncs and the
 * account's own outgoing messages are skipped so nothing loops back on itself.
 */
export function registerMessageHandler(sock: WASocket): void {
  sock.ev.on("messages.upsert", async ({ messages, type }) => {
    if (type !== "notify") {
      return;
    }

    for (const message of messages) {
      if (message.key.fromMe) {
        continue;
      }

      if (message.key.remoteJid === STATUS_BROADCAST) {
        continue;
      }

      if (!message.message) {
        continue;
      }

      const content = normalizeMessageContent(message.message);
      const contentType = getContentType(content);
      const isImage = Boolean(content?.imageMessage);

      try {
        const incoming = await normalizeMessage(message, sock);
        if (incoming) {
          logMessage(incoming, contentType);

          if (incoming.type === "text" && incoming.text) {
            await analyzeAndReply(sock, incoming.chatId, incoming.text);
          } else if (incoming.type === "image" && incoming.image) {
            await analyzeImageAndReply(
              sock,
              incoming.chatId,
              incoming.image.filePath,
            );
          }
        }
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);

        // A detected image that failed to download is reported as such, so the
        // real cause stays visible instead of looking like an unsupported type.
        if (isImage) {
          console.error("[IMAGE ERROR]");
          console.error(`Chat: ${message.key.remoteJid ?? "unknown"}`);
          console.error(`Reason: ${reason}`);
        } else {
          console.error(`Failed to process message: ${reason}`);
        }
      }
    }
  });
}
