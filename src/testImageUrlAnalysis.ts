import "dotenv/config";

import {
  combineRisk,
  formatCombinedImageAnalysis,
  type UrlOutcome,
} from "./risk/formatter.js";
import { analyzeUrl } from "./services/url.service.js";
import type {
  AiSuspicionLevel,
  ImageAnalysisResult,
  RiskLevel,
} from "./types/analysis.js";
import { extractUrls } from "./utils/extractUrls.js";

/** Mirrors the handler's cap so the harness exercises the same path. */
const MAX_URLS_PER_MESSAGE = 3;

/**
 * Builds an image result without calling the vision model.
 *
 * The fraud and authenticity values are fixed so each scenario tests the
 * combination logic rather than the model's judgement, which varies per run.
 */
function imageResult(options: {
  risk: RiskLevel;
  score: number;
  extractedText: string;
  aiSuspicion?: AiSuspicionLevel;
  aiScore?: number | null;
}): ImageAnalysisResult {
  return {
    fraud: {
      risk: options.risk,
      score: options.score,
      scamType: options.risk === "low" ? "none" : "phishing",
    },
    authenticity: {
      aiSuspicion: options.aiSuspicion ?? "unknown",
      score: options.aiScore ?? null,
    },
    extractedText: options.extractedText,
    signals: options.risk === "low" ? [] : ["urgent request", "credential request"],
    explanation: "fixture",
    recommendedAction: "Verify independently before acting.",
  };
}

/** Runs the same steps the WhatsApp image handler uses. */
async function runScenario(image: ImageAnalysisResult): Promise<{
  fraud: RiskLevel;
  ai: AiSuspicionLevel;
  reply: string;
  linkCount: number;
}> {
  const urls = extractUrls(image.extractedText).slice(0, MAX_URLS_PER_MESSAGE);

  const settled = await Promise.allSettled(urls.map((url) => analyzeUrl(url)));

  const outcomes: UrlOutcome[] = settled.map((outcome, index) =>
    outcome.status === "fulfilled"
      ? { status: "ok", result: outcome.value }
      : { status: "failed", url: urls[index]! },
  );

  return {
    fraud: combineRisk(image.fraud.risk, outcomes),
    ai: image.authenticity.aiSuspicion,
    reply: formatCombinedImageAnalysis(image, outcomes),
    linkCount: outcomes.length,
  };
}

let failures = 0;

/** Checks one scenario and prints its outcome. */
async function check(
  label: string,
  image: ImageAnalysisResult,
  expected: {
    fraud: RiskLevel;
    ai: AiSuspicionLevel;
    links: number;
    noLinksSection?: boolean;
  },
): Promise<void> {
  console.log(`\n${"=".repeat(70)}\n${label}\n${"=".repeat(70)}`);

  const { fraud, ai, reply, linkCount } = await runScenario(image);

  const hasLinksSection = reply.includes("Links found in this image:");
  const sectionOk = expected.noLinksSection ? !hasLinksSection : true;

  const ok =
    fraud === expected.fraud &&
    ai === expected.ai &&
    linkCount === expected.links &&
    sectionOk;

  if (!ok) {
    failures++;
  }

  console.log(
    `${ok ? "PASS" : "FAIL"}  fraud=${fraud} (exp ${expected.fraud})  ` +
      `ai=${ai} (exp ${expected.ai})  links=${linkCount} (exp ${expected.links})` +
      `${expected.noLinksSection ? `  noLinksSection=${!hasLinksSection}` : ""}`,
  );
  console.log(`\n--- reply ---\n${reply}`);
}

async function main(): Promise<void> {
  await check(
    "1. low fraud, no URL",
    imageResult({ risk: "low", score: 0, extractedText: "Family photo" }),
    { fraud: "low", ai: "unknown", links: 0, noLinksSection: true },
  );

  await check(
    "2. high fraud, no URL",
    imageResult({ risk: "high", score: 95, extractedText: "Send OTP immediately" }),
    { fraud: "high", ai: "unknown", links: 0, noLinksSection: true },
  );

  await check(
    "3. low image fraud + safe URL",
    imageResult({
      risk: "low",
      score: 0,
      extractedText: "More info https://example.com",
    }),
    { fraud: "low", ai: "unknown", links: 1 },
  );

  await check(
    "4. low image fraud + impersonation URL",
    imageResult({
      risk: "low",
      score: 5,
      extractedText: "Claim here https://paypal.com.example-login.xyz",
    }),
    { fraud: "medium", ai: "unknown", links: 1 },
  );

  await check(
    "5. high image fraud + safe URL",
    imageResult({
      risk: "high",
      score: 95,
      extractedText: "Send OTP now https://example.com",
    }),
    { fraud: "high", ai: "unknown", links: 1 },
  );

  await check(
    "6. multiple image URLs",
    imageResult({
      risk: "low",
      score: 0,
      extractedText:
        "https://example.com\nhttps://paypal.com.example-login.xyz",
    }),
    { fraud: "medium", ai: "unknown", links: 2 },
  );

  // 7: a link that cannot be analyzed must not raise risk, and a reply must
  // still be produced.
  console.log(`\n${"=".repeat(70)}\n7. URL analysis failure\n${"=".repeat(70)}`);
  const failImage = imageResult({
    risk: "low",
    score: 0,
    extractedText: "See https://unreachable.invalid/path",
  });
  const failOutcomes: UrlOutcome[] = [
    { status: "failed", url: "https://unreachable.invalid/path" },
  ];
  const failFraud = combineRisk(failImage.fraud.risk, failOutcomes);
  const failReply = formatCombinedImageAnalysis(failImage, failOutcomes);
  const failOk =
    failFraud === "low" && failReply.includes("Could not fully verify");
  if (!failOk) {
    failures++;
  }
  console.log(`${failOk ? "PASS" : "FAIL"}  fraud=${failFraud} (exp low)`);
  console.log(`\n--- reply ---\n${failReply}`);

  await check(
    "8. AI independence: high AI suspicion must not raise fraud",
    imageResult({
      risk: "low",
      score: 0,
      extractedText: "Artwork https://example.com",
      aiSuspicion: "high",
      aiScore: 88,
    }),
    { fraud: "low", ai: "high", links: 1 },
  );

  await check(
    "9. AI independence: phishing URL must not change AI suspicion",
    imageResult({
      risk: "low",
      score: 0,
      extractedText: "Claim here https://paypal.com.example-login.xyz",
      aiSuspicion: "unknown",
      aiScore: null,
    }),
    { fraud: "medium", ai: "unknown", links: 1 },
  );

  console.log(`\n\n${9 - failures}/9 scenarios passed.`);

  if (failures > 0) {
    process.exitCode = 1;
  }
}

await main();
