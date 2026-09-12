import { readFile, stat } from "node:fs/promises";
import path from "node:path";

import type { ChatCompletion } from "groq-sdk/resources/chat/completions";
import { z } from "zod";

import { getGroqVisionModel } from "../config/env.js";
import { describeGroqError, getGroqClient } from "../services/groq.js";
import type { ImageAnalysisResult } from "../types/analysis.js";

/**
 * Image types accepted, mapped to the MIME type sent to the model.
 *
 * MIME is derived from the local extension rather than from anything a sender
 * supplied, so a mislabelled upload cannot influence how the file is treated.
 */
const SUPPORTED_EXTENSIONS: Record<string, string> = {
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".webp": "image/webp",
};

/** Mirrors {@link ImageAnalysisResult} for validating the model's output. */
const imageAnalysisSchema = z
  .object({
    fraud: z
      .object({
        risk: z.enum(["low", "medium", "high"]),
        score: z.number().int().min(0).max(100),
        scamType: z.enum([
          "phishing",
          "impersonation",
          "fake_prize",
          "fake_job",
          "investment",
          "credential_theft",
          "payment_fraud",
          "advance_fee",
          "other",
          "none",
        ]),
      })
      .strict(),
    authenticity: z
      .object({
        aiSuspicion: z.enum(["low", "medium", "high", "unknown"]),
        score: z.number().int().min(0).max(100).nullable(),
      })
      .strict(),
    extractedText: z.string(),
    signals: z.array(z.string()),
    explanation: z.string(),
    recommendedAction: z.string(),
  })
  .strict();

/**
 * Schema sent to the model to constrain its output.
 *
 * Derived from the Zod schema so the provider-enforced shape and the shape we
 * validate against cannot drift apart.
 */
const responseJsonSchema = z.toJSONSchema(imageAnalysisSchema);

const SYSTEM_INSTRUCTION = `You are the image analysis component of a security tool that screens images shared over WhatsApp. You perform TWO INDEPENDENT tasks on the same image and must not let either one influence the other.

TASK A - FRAUD / SCAM RISK

Judge the CONTENT of the image and the REQUEST it makes of the viewer. Read all reasonably visible text. Images are often screenshots of WhatsApp or SMS conversations, bank messages, posters, advertisements, job offers, prize notices, or payment instructions.

Look for indicators of:
- fake prize or lottery wins
- fake job offers
- advance-fee requests (pay now to receive something later)
- payment requests, including QR codes and Easypaisa or JazzCash instructions
- requests for OTPs, PINs, passwords, or CNIC details
- bank or account "verification" and "blocked account" claims
- impersonation of relatives, officials, companies, or support staff
- investment and quick-profit schemes
- manufactured urgency, fear, threats, secrecy
- social engineering and requests for sensitive personal information

Languages: handle English, Urdu, Roman Urdu, and mixed Urdu/English equally well. Understand Roman Urdu phrases such as "jaldi paisay bhejo" (send money quickly), "OTP share karo" (share the OTP), "account block ho jayega" (the account will be blocked), "aap inaam jeet gaye hain" (you have won a prize), "registration fee bhejein" (send a registration fee), "Easypaisa kar dein" and "JazzCash bhejo" (send money via those services).

Judgement rules:
- Do NOT treat an image as fraudulent merely because it mentions money, names a bank, sounds urgent, or is poorly designed.
- Ordinary content is NOT a scam. A routine meeting reminder, a normal photograph, a receipt, or a salary notification is low risk.
- Weigh the COMBINATION of signals in context.
- fraud.score runs 0-100: 0 means no meaningful fraud indicators, 100 means extremely strong fraud indicators.

TASK B - AI-GENERATED IMAGE SUSPICION

Separately, estimate whether the image LOOKS synthetic, based only on what you can see. Possible visual signals include inconsistent anatomy, malformed hands or fingers, impossible geometry, inconsistent lighting or reflections, distorted or nonsensical text, repeated textures, unnatural object boundaries, rendering artifacts, and internally inconsistent details.

This is a HEURISTIC visual impression. You are not a forensic detector, and you must never claim certainty that an image is or is not AI-generated.

When the image is a screenshot, document, poster, meme, user interface, or a text-heavy graphic - or when there is simply not enough visual evidence to judge - set aiSuspicion to "unknown" and score to null. Do not invent confidence you do not have.

authenticity.score runs 0-100 when you can assess it: 0 means strongly consistent with ordinary non-synthetic imagery, 100 means strong visual indications of synthetic generation. Use null whenever aiSuspicion is "unknown".

INDEPENDENCE - THIS IS CRITICAL

The two tasks are separate and must not contaminate each other:
- A genuine, non-synthetic screenshot can contain a blatant scam: high fraud risk, low or unknown AI suspicion.
- An AI-generated landscape or portrait can be completely harmless: low fraud risk, high AI suspicion.
- Never raise fraud.score merely because AI suspicion is high. Synthetic imagery is not evidence of fraud.
- Never lower AI suspicion merely because the content looks like an ordinary message.

EXTRACTED TEXT

Put all important readable text from the image into extractedText, preserving the original language. Do not guess at text you cannot actually read. If the image contains no readable text, return an empty string.

URL BOUNDARY

A separate component analyses links. A URL visible in the image may appear in extractedText, but you must NOT judge whether any domain, link, or website is malicious, legitimate, or fake, and must not speculate about where a link leads. You may consider the wording around a link and the request being made of the viewer.

OUTPUT

Keep "signals" short - a few words each, naming the indicator you found. Keep "explanation" to one or two plain sentences a non-technical reader understands. Keep "recommendedAction" to one short, practical instruction.`;

/**
 * Cap on generated tokens.
 *
 * The free tier enforces an output-tokens-per-minute limit, and an uncapped
 * request exceeds it before producing anything.
 */
const MAX_OUTPUT_TOKENS = 1000;

/** Short task prompt accompanying the image. */
const USER_INSTRUCTION =
  "Analyze this image for fraud risk and, separately, for signs that it may be AI-generated.";

/**
 * Analyzes a local image for fraud risk and AI-generation suspicion.
 *
 * The image is sent inline as a data URL; it is never uploaded anywhere
 * else. Each call is independent, and nothing is logged or persisted.
 *
 * @param filePath Path to a local .jpg, .jpeg, .png, or .webp file.
 * @throws If the path is empty, missing, not a regular file, of an unsupported
 * type, empty on disk, or if the model's output fails validation.
 */
export async function analyzeImage(
  filePath: string,
): Promise<ImageAnalysisResult> {
  const trimmedPath = filePath.trim();

  if (!trimmedPath) {
    throw new Error("Cannot analyze an empty image path.");
  }

  const extension = path.extname(trimmedPath).toLowerCase();
  const mimeType = SUPPORTED_EXTENSIONS[extension];

  if (!mimeType) {
    throw new Error(
      `Unsupported image type "${extension || "(none)"}". Supported types: ${Object.keys(
        SUPPORTED_EXTENSIONS,
      ).join(", ")}.`,
    );
  }

  let stats;
  try {
    stats = await stat(trimmedPath);
  } catch {
    throw new Error(`Image file not found: ${trimmedPath}`);
  }

  if (!stats.isFile()) {
    throw new Error(`Not a regular file: ${trimmedPath}`);
  }

  if (stats.size === 0) {
    throw new Error(`Image file is empty: ${trimmedPath}`);
  }

  const buffer = await readFile(trimmedPath);

  const client = getGroqClient();

  let raw: string | null | undefined;
  try {
    const response = await client.chat.completions.create({
      model: getGroqVisionModel(),
      max_tokens: MAX_OUTPUT_TOKENS,
      // The vision model emits chain-of-thought into `content` by default,
      // which would leave the JSON unparseable. Both flags are needed: one
      // stops the reasoning, the other keeps it out of the message body.
      reasoning_effort: "none",
      reasoning_format: "hidden",
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "image_analysis",
          schema: responseJsonSchema,
          strict: true,
        },
      },
      messages: [
        { role: "system", content: SYSTEM_INSTRUCTION },
        {
          role: "user",
          content: [
            { type: "text", text: USER_INSTRUCTION },
            {
              type: "image_url",
              image_url: {
                url: `data:${mimeType};base64,${buffer.toString("base64")}`,
              },
            },
          ],
        },
      ],
    } as Parameters<typeof client.chat.completions.create>[0]);

    raw = (response as ChatCompletion).choices[0]?.message?.content;
  } catch (error) {
    throw new Error(`Image analysis failed: ${describeGroqError(error)}`);
  }

  if (!raw) {
    throw new Error("Model returned no usable structured output.");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Model returned output that is not valid JSON.");
  }

  const validated = imageAnalysisSchema.safeParse(parsed);

  if (!validated.success) {
    throw new Error(
      `Model output did not match the expected schema: ${validated.error.issues
        .map((issue) => `${issue.path.join(".") || "(root)"} ${issue.message}`)
        .join("; ")}`,
    );
  }

  return validated.data;
}
