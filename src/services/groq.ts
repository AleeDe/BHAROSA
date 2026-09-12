import Groq from "groq-sdk";

import { getGroqApiKey } from "../config/env.js";

/** Cached client, built on first use. */
let client: Groq | undefined;

/**
 * Returns the shared Groq client, creating it on first call.
 *
 * Construction is deferred so importing this module never requires
 * `GROQ_API_KEY`; the WhatsApp transport can run without one.
 *
 * @throws {MissingGroqApiKeyError} if no API key is configured.
 */
export function getGroqClient(): Groq {
  if (!client) {
    client = new Groq({
      apiKey: getGroqApiKey(),
    });
  }

  return client;
}

/**
 * Converts an SDK or network failure into a message safe to surface.
 *
 * Reports only the status and a short description; request bodies, image data,
 * and credentials are never included.
 */
export function describeGroqError(error: unknown): string {
  // Checked before APIError, which it extends, so network failures are not
  // reported as a status-less API error.
  if (error instanceof Groq.APIConnectionError) {
    return "Could not reach the Groq API. Check your network connection.";
  }

  if (error instanceof Groq.APIError) {
    const status = error.status;

    if (status === 401 || status === 403) {
      return "Groq rejected the API key. Check GROQ_API_KEY.";
    }

    if (status === 404) {
      return "Groq model not found. Check GROQ_VISION_MODEL.";
    }

    if (status === 413) {
      return "Image is too large for the Groq API.";
    }

    if (status === 429) {
      return "Groq rate limit reached. Retry in a moment.";
    }

    if (status !== undefined && status >= 500) {
      return `Groq service error (${status}). Retry in a moment.`;
    }

    return `Groq request failed (${status ?? "no status"}).`;
  }

  return error instanceof Error ? error.message : String(error);
}
