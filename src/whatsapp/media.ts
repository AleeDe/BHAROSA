import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  downloadMediaMessage,
  type WAMessage,
} from "@whiskeysockets/baileys";
import pino from "pino";

/** Folder where downloaded media is held for processing. Gitignored. */
const TEMP_FOLDER = "temp";

/** Extension used when the reported MIME type is missing or unrecognized. */
const FALLBACK_EXTENSION = ".bin";

/** MIME types we can map to a known image extension. */
const MIME_EXTENSIONS: Record<string, string> = {
  "image/jpeg": ".jpg",
  "image/jpg": ".jpg",
  "image/png": ".png",
  "image/webp": ".webp",
};

/** Silenced so media retries do not print Baileys internals. */
const logger = pino({ level: "silent" });

/**
 * Re-fetches the media keys for a message whose upload has expired.
 *
 * Baileys calls this only when a direct download fails; pass the socket's own
 * `updateMediaMessage` so the retry can actually succeed.
 */
export type ReuploadRequest = (message: WAMessage) => Promise<WAMessage>;

/** Metadata describing a downloaded media file on disk. */
export interface SavedMedia {
  filePath: string;
  mimeType?: string;
}

/**
 * Picks a file extension from a MIME type.
 *
 * Falls back to a generic extension rather than trusting the sender, so an
 * unexpected type can never choose its own extension.
 */
function extensionForMimeType(mimeType: string | undefined): string {
  if (!mimeType) {
    return FALLBACK_EXTENSION;
  }

  const normalized = mimeType.split(";")[0]?.trim().toLowerCase() ?? "";
  return MIME_EXTENSIONS[normalized] ?? FALLBACK_EXTENSION;
}

/**
 * Builds a collision-resistant filename from a timestamp and random suffix.
 *
 * Nothing sender-controlled reaches the filename, which keeps the write inside
 * the temp folder regardless of what the message claimed to be called.
 */
function buildFileName(mimeType: string | undefined): string {
  const timestamp = Date.now();
  const suffix = randomBytes(4).toString("hex");
  return `${timestamp}-${suffix}${extensionForMimeType(mimeType)}`;
}

/**
 * Downloads the image attached to a message and writes it into `./temp`.
 *
 * Creates the temp folder if it does not exist yet. Returns the path written
 * and the MIME type WhatsApp reported for the image.
 */
export async function saveImageMessage(
  message: WAMessage,
  mimeType: string | undefined,
  reuploadRequest: ReuploadRequest,
): Promise<SavedMedia> {
  const buffer = await downloadMediaMessage(message, "buffer", {}, {
    logger,
    reuploadRequest,
  });

  await mkdir(TEMP_FOLDER, { recursive: true });

  const filePath = path.join(TEMP_FOLDER, buildFileName(mimeType));
  await writeFile(filePath, buffer);

  return { filePath, mimeType };
}
