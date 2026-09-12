/** Overall fraud-risk band for an analyzed message. */
export type RiskLevel = "low" | "medium" | "high";

/** Category of scam a message most closely resembles. */
export type ScamType =
  | "phishing"
  | "impersonation"
  | "fake_prize"
  | "fake_job"
  | "investment"
  | "credential_theft"
  | "payment_fraud"
  | "advance_fee"
  | "other"
  | "none";

/**
 * Result of a text fraud-risk analysis.
 *
 * `score` runs 0-100, where 0 means no meaningful fraud indicators and 100
 * means extremely strong fraud indicators. It is a risk estimate, not a verdict.
 */
export interface TextAnalysisResult {
  fraud: {
    risk: RiskLevel;
    score: number;
    scamType: ScamType;
  };

  signals: string[];

  explanation: string;

  recommendedAction: string;
}

/**
 * How strongly an image appears to be AI-generated.
 *
 * `unknown` means there was not enough visual evidence to judge — common for
 * screenshots, documents, and other text-heavy graphics.
 */
export type AiSuspicionLevel = "low" | "medium" | "high" | "unknown";

/**
 * Result of an image analysis.
 *
 * Fraud risk and authenticity are independent: a genuine photograph can carry a
 * scam, and a synthetic image can be entirely harmless. `authenticity.score` is
 * a heuristic visual impression, not a forensic determination, and is `null`
 * when no meaningful assessment is possible.
 */
export interface ImageAnalysisResult {
  fraud: {
    risk: RiskLevel;
    score: number;
    scamType: ScamType;
  };

  authenticity: {
    aiSuspicion: AiSuspicionLevel;
    score: number | null;
  };

  extractedText: string;

  signals: string[];

  explanation: string;

  recommendedAction: string;
}
