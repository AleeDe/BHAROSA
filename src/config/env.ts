/** Vision model used when `GROQ_VISION_MODEL` is not set. */
const DEFAULT_GROQ_VISION_MODEL = "qwen/qwen3.6-27b";

/** Text model used when `GROQ_TEXT_MODEL` is not set. */
const DEFAULT_GROQ_TEXT_MODEL = "qwen/qwen3.6-27b";

/**
 * Thrown when analysis is used without a Groq API key configured.
 *
 * Kept as a named class so callers can distinguish a configuration problem from
 * a network or API failure.
 */
export class MissingGroqApiKeyError extends Error {
  constructor() {
    super(
      "GROQ_API_KEY is not set. Add it to your .env file to use analysis.",
    );
    this.name = "MissingGroqApiKeyError";
  }
}

/**
 * Returns the Groq API key.
 *
 * Read on demand rather than at startup so the WhatsApp transport can run
 * without a key configured; only Groq-backed analysis requires one. A blank
 * value counts as missing.
 *
 * @throws {MissingGroqApiKeyError} if the key is absent or blank.
 */
export function getGroqApiKey(): string {
  const apiKey = process.env.GROQ_API_KEY?.trim();

  if (!apiKey) {
    throw new MissingGroqApiKeyError();
  }

  return apiKey;
}

/** Returns the configured Groq vision model, falling back to the default. */
export function getGroqVisionModel(): string {
  return process.env.GROQ_VISION_MODEL?.trim() || DEFAULT_GROQ_VISION_MODEL;
}

/**
 * Returns the configured Groq text model, falling back to the default.
 *
 * Kept separate from the vision model so text and image analysis can be pointed
 * at different models without affecting each other.
 */
export function getGroqTextModel(): string {
  return process.env.GROQ_TEXT_MODEL?.trim() || DEFAULT_GROQ_TEXT_MODEL;
}

/**
 * Returns the VirusTotal API key, or `undefined` when none is configured.
 *
 * URL reputation is optional: the analyzer falls back to local rules without a
 * key, so this returns `undefined` rather than throwing. `WEB_RISK_API_KEY` is
 * accepted as a compatibility fallback for the original implementation.
 */
export function getVirusTotalApiKey(): string | undefined {
  return (
    process.env.VIRUSTOTAL_API_KEY?.trim() ||
    process.env.WEB_RISK_API_KEY?.trim() ||
    undefined
  );
}
