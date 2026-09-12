import type {
  AiSuspicionLevel,
  ImageAnalysisResult,
  RiskLevel,
  ScamType,
  TextAnalysisResult,
} from "../types/analysis.js";

/** Most signals to show, so replies stay short on a phone screen. */
const MAX_SIGNALS = 3;

/** Readable wording for each scam category. */
const SCAM_TYPE_LABELS: Record<ScamType, string> = {
  phishing: "Phishing",
  impersonation: "Impersonation",
  fake_prize: "Fake prize",
  fake_job: "Fake job",
  investment: "Investment scam",
  credential_theft: "Credential / OTP theft",
  payment_fraud: "Payment fraud",
  advance_fee: "Advance-fee scam",
  other: "Suspicious activity",
  none: "No obvious scam pattern",
};

/** Headline shown for each risk band. */
const RISK_HEADERS: Record<RiskLevel, string> = {
  high: "🔴 HIGH RISK",
  medium: "🟡 CAUTION",
  low: "🟢 LOW RISK",
};

/** Headline shown for each AI-suspicion band. */
const AI_SUSPICION_HEADERS: Record<AiSuspicionLevel, string> = {
  high: "🔴 HIGH SUSPICION",
  medium: "🟡 MEDIUM SUSPICION",
  low: "🟢 LOW SUSPICION",
  unknown: "⚪ UNKNOWN",
};

/** Title line on every reply. */
const TITLE = "🛡️ Digital Shield";

/**
 * Reply sent when analysis could not be completed.
 *
 * Deliberately free of technical detail: the user gets safe guidance, while the
 * real cause stays in the terminal diagnostics.
 */
export const ANALYSIS_UNAVAILABLE_MESSAGE = `${TITLE}

⚠️ I couldn't analyze this message right now.
Please avoid sharing OTPs, passwords, or sending money until you can verify the request independently.`;

/**
 * Renders an analysis result as a WhatsApp reply.
 *
 * Purely presentational: no network calls, no model involvement. Wording
 * describes risk rather than asserting that a message is definitely a scam,
 * because the analyzer estimates risk and does not verify truth.
 */
export function formatTextAnalysis(result: TextAnalysisResult): string {
  const { risk, score, scamType } = result.fraud;

  const lines: string[] = [
    TITLE,
    "",
    RISK_HEADERS[risk],
    `Risk score: ${score}/100`,
  ];

  if (risk === "low") {
    lines.push("", "No obvious scam pattern detected.");
  } else {
    lines.push("", "Possible scam:", SCAM_TYPE_LABELS[scamType]);

    const signals = result.signals.slice(0, MAX_SIGNALS);
    if (signals.length > 0) {
      lines.push("", "Why:");
      for (const signal of signals) {
        lines.push(`• ${signal}`);
      }
    }
  }

  const action = result.recommendedAction.trim();
  if (risk === "low") {
    lines.push(
      "",
      action ||
        "Still verify unexpected requests before sending money or sharing private information.",
    );
  } else if (action) {
    lines.push("", "What to do:", action);
  }

  return lines.join("\n");
}

/**
 * Reply sent when image analysis could not be completed.
 *
 * Carries no technical detail: status codes, file paths, and provider messages
 * stay in the terminal diagnostics.
 */
export const IMAGE_ANALYSIS_UNAVAILABLE_MESSAGE = `${TITLE}

⚠️ I couldn't fully analyze this image right now.
Please verify any payment request, OTP request, or urgent instruction independently before acting.`;

/**
 * Renders an image analysis result as a WhatsApp reply.
 *
 * Fraud risk and AI suspicion are shown as separate sections, mirroring the
 * analyzer: a synthetic image is not itself a scam, and a genuine screenshot
 * can carry one. Wording describes suspicion rather than asserting that an
 * image was generated, because the assessment is heuristic.
 *
 * The extracted text is deliberately not included; it would repeat back the
 * whole image and make the reply unreadable on a phone.
 */
export function formatImageAnalysis(result: ImageAnalysisResult): string {
  const { risk, score, scamType } = result.fraud;
  const { aiSuspicion, score: aiScore } = result.authenticity;

  const lines: string[] = [
    TITLE,
    "",
    "Fraud risk",
    RISK_HEADERS[risk],
  ];

  if (risk === "low") {
    lines.push("No obvious scam pattern detected.");
  } else {
    lines.push(`Risk score: ${score}/100`, "", "Possible scam:", SCAM_TYPE_LABELS[scamType]);

    const signals = result.signals.slice(0, MAX_SIGNALS);
    if (signals.length > 0) {
      lines.push("", "Why:");
      for (const signal of signals) {
        lines.push(`• ${signal}`);
      }
    }

    const action = result.recommendedAction.trim();
    if (action) {
      lines.push("", "What to do:", action);
    }
  }

  lines.push("", "AI image suspicion", AI_SUSPICION_HEADERS[aiSuspicion]);

  if (aiScore === null) {
    lines.push("Not enough visual evidence to score.");
  } else {
    lines.push(`Suspicion score: ${aiScore}/100`);
  }

  return lines.join("\n");
}
