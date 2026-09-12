import type { ChatCompletion } from "groq-sdk/resources/chat/completions";
import { z } from "zod";

import { getGroqTextModel } from "../config/env.js";
import { describeGroqError, getGroqClient } from "../services/groq.js";
import type { TextAnalysisResult } from "../types/analysis.js";

/** Mirrors {@link TextAnalysisResult} for validating the model's output. */
const textAnalysisSchema = z
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
const responseJsonSchema = z.toJSONSchema(textAnalysisSchema);

const SYSTEM_INSTRUCTION = `You are the fraud-risk analysis component of a security tool that screens WhatsApp messages.

Your job is RISK ASSESSMENT, not absolute truth detection. You estimate how likely it is that a message is an attempt to defraud the reader, based on the indicators present.

Look for indicators of:
- phishing and credential theft
- requests for OTPs, PINs, passwords, or CNIC details
- bank or account "verification" and "blocked account" scams
- impersonation of relatives, officials, companies, or support staff
- fake prizes and lottery wins
- fake job offers
- investment and quick-profit schemes
- advance-fee requests (pay now to receive something later)
- payment requests, especially to Easypaisa or JazzCash
- manufactured urgency, fear, threats, secrecy
- social engineering and requests for sensitive personal information

Languages: handle English, Urdu, Roman Urdu, and mixed Urdu/English equally well. Roman Urdu phrases you must understand include "jaldi paisay bhejo" (send money quickly), "OTP share karo" (share the OTP), "account block ho jayega" (the account will be blocked), "aap inaam jeet gaye hain" (you have won a prize), "registration fee bhejein" (send a registration fee), "Easypaisa kar dein" and "JazzCash bhejo" (send money via those services).

Important judgement rules:
- Do NOT treat a message as fraudulent merely because it mentions money, names a bank, sounds urgent, or is poorly written. Ordinary life involves all of these.
- Ordinary financial messages are NOT scams. A salary deposit notice, a balance update, or a routine bank statement is low risk.
- Weigh the COMBINATION of signals in context. A single weak indicator is not fraud.
- Ordinary, safe messages must score low. A routine meeting reminder is low risk.
- Do not claim certainty unless the evidence strongly supports it.

Scoring: 0 means no meaningful fraud indicators; 100 means extremely strong fraud indicators. Map the score to risk honestly: low, medium, or high.

URL boundary: a separate component analyses links. You may consider the wording around a link and the fact that the message pushes the reader to click or log in. You must NOT claim that any domain, link, or website is malicious, suspicious, or fake, and you must not speculate about where a link leads. Judge only the language and the request being made.

Keep "signals" short — a few words each, naming the indicator you found. Keep "explanation" to one or two plain sentences a non-technical reader understands. Keep "recommendedAction" to one short, practical instruction.`;

/**
 * Cap on generated tokens.
 *
 * The structured result is compact, and the free tier enforces an
 * output-tokens-per-minute limit, so an uncapped request wastes budget.
 */
const MAX_OUTPUT_TOKENS = 500;

/**
 * Estimates the fraud risk of a message.
 *
 * Each call is independent: no conversation history is sent, and nothing is
 * logged or persisted.
 *
 * @param text Raw message text, in any of the supported languages.
 * @throws If the text is empty, the API call fails, or the model returns
 * output that is not valid JSON matching the schema.
 */
export async function analyzeText(text: string): Promise<TextAnalysisResult> {
  const trimmed = text.trim();

  if (!trimmed) {
    throw new Error("Cannot analyze empty text.");
  }

  const client = getGroqClient();

  let raw: string | null | undefined;
  try {
    const response = await client.chat.completions.create({
      model: getGroqTextModel(),
      max_tokens: MAX_OUTPUT_TOKENS,
      // This model emits chain-of-thought into `content` by default, which
      // would leave the JSON unparseable. Both flags are needed: one stops the
      // reasoning, the other keeps it out of the message body.
      reasoning_effort: "none",
      reasoning_format: "hidden",
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "text_analysis",
          schema: responseJsonSchema,
          strict: true,
        },
      },
      messages: [
        { role: "system", content: SYSTEM_INSTRUCTION },
        { role: "user", content: trimmed },
      ],
    } as Parameters<typeof client.chat.completions.create>[0]);

    raw = (response as ChatCompletion).choices[0]?.message?.content;
  } catch (error) {
    throw new Error(`Text analysis failed: ${describeGroqError(error)}`);
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

  const validated = textAnalysisSchema.safeParse(parsed);

  if (!validated.success) {
    throw new Error(
      `Model output did not match the expected schema: ${validated.error.issues
        .map((issue) => `${issue.path.join(".") || "(root)"} ${issue.message}`)
        .join("; ")}`,
    );
  }

  return validated.data;
}
