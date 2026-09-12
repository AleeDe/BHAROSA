import "dotenv/config";

import { analyzeText } from "./analyzers/textAnalyzer.js";
import {
  combineRisk,
  formatCombinedAnalysis,
  type UrlOutcome,
} from "./risk/formatter.js";
import { analyzeUrl } from "./services/url.service.js";
import type { RiskLevel, TextAnalysisResult } from "./types/analysis.js";
import { extractUrls } from "./utils/extractUrls.js";

/** Mirrors the handler's cap so the harness exercises the same path. */
const MAX_URLS_PER_MESSAGE = 3;

const SCENARIOS: { label: string; text: string; expected: RiskLevel }[] = [
  { label: "1. benign text only", text: "Meeting at 10 tomorrow.", expected: "low" },
  {
    label: "2. scam text only",
    text: "Your bank account is blocked. Send OTP immediately.",
    expected: "high",
  },
  {
    label: "3. benign + safe URL",
    text: "Meeting notes https://example.com",
    expected: "low",
  },
  // The URL alone is suspicious (medium). The text analyzer also reads the
  // deceptive hostname in the message body and rates it high phishing, and the
  // highest component wins. Verified stable across repeated runs.
  {
    label: "4. benign + impersonation URL",
    text: "Check this https://paypal.com.example-login.xyz",
    expected: "high",
  },
  {
    label: "5. scam text + safe URL",
    text: "Send OTP now https://example.com",
    expected: "high",
  },
  // The URL components alone combine to medium (safe + suspicious). The text
  // analyzer independently rates a message whose whole content is a deceptive
  // link as high, and the highest component wins, so high is expected here.
  {
    label: "6. multiple URLs",
    text: "https://example.com https://paypal.com.example-login.xyz",
    expected: "high",
  },
];

/** Runs one message through the same steps the WhatsApp handler uses. */
async function runScenario(text: string): Promise<{
  overall: RiskLevel;
  reply: string;
  urlCount: number;
}> {
  const urls = extractUrls(text).slice(0, MAX_URLS_PER_MESSAGE);

  const settled = await Promise.allSettled(urls.map((url) => analyzeUrl(url)));

  const outcomes: UrlOutcome[] = settled.map((outcome, index) =>
    outcome.status === "fulfilled"
      ? { status: "ok", result: outcome.value }
      : { status: "failed", url: urls[index]! },
  );

  const result = await analyzeText(text);

  return {
    overall: combineRisk(result.fraud.risk, outcomes),
    reply: formatCombinedAnalysis(result, outcomes),
    urlCount: outcomes.length,
  };
}

/** Spaces out requests; the free tier rejects bursts. */
function pause(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main(): Promise<void> {
  let failures = 0;

  for (const { label, text, expected } of SCENARIOS) {
    await pause(6000);
    console.log(`\n${"=".repeat(70)}\n${label}\n${"=".repeat(70)}`);
    console.log(`INPUT: ${text}`);

    try {
      const { overall, reply, urlCount } = await runScenario(text);
      const ok = overall === expected;

      if (!ok) {
        failures++;
      }

      console.log(
        `\n${ok ? "PASS" : "FAIL"}  overall=${overall} (expected ${expected}), links analyzed=${urlCount}`,
      );
      console.log(`\n--- reply ---\n${reply}`);
    } catch (error) {
      failures++;
      const reason = error instanceof Error ? error.message : String(error);
      console.log(`\nFAIL  threw: ${reason}`);
    }
  }

  // Mapping check with a fixed low text result, so the suspicious -> medium
  // path is covered even when the live analyzer rates a link-bearing message
  // high on its own.
  console.log(`\n${"=".repeat(70)}\n8. low text + suspicious URL -> medium\n${"=".repeat(70)}`);

  const fixedLowText: TextAnalysisResult = {
    fraud: { risk: "low", score: 0, scamType: "none" },
    signals: [],
    explanation: "ordinary message",
    recommendedAction: "No action needed.",
  };
  const suspicious = await analyzeUrl("https://paypal.com.example-login.xyz");
  const mappingOutcomes: UrlOutcome[] = [{ status: "ok", result: suspicious }];
  const mapped = combineRisk(fixedLowText.fraud.risk, mappingOutcomes);

  const mappingOk = mapped === "medium";
  if (!mappingOk) {
    failures++;
  }
  console.log(`\n${mappingOk ? "PASS" : "FAIL"}  overall=${mapped} (expected medium)`);
  console.log(`\n--- reply ---\n${formatCombinedAnalysis(fixedLowText, mappingOutcomes)}`);

  // Scenario 7: a link that cannot be analyzed must still produce a reply, and
  // must not raise the overall risk on its own.
  console.log(`\n${"=".repeat(70)}\n7. URL analysis failure\n${"=".repeat(70)}`);

  const benign = await analyzeText("Meeting notes");
  const failedOutcomes: UrlOutcome[] = [
    { status: "failed", url: "https://unreachable.invalid/path" },
  ];
  const overall = combineRisk(benign.fraud.risk, failedOutcomes);
  const reply = formatCombinedAnalysis(benign, failedOutcomes);

  const ok = overall === "low" && reply.includes("Could not fully verify");
  if (!ok) {
    failures++;
  }

  console.log(`\n${ok ? "PASS" : "FAIL"}  overall=${overall} (expected low)`);
  console.log(`\n--- reply ---\n${reply}`);

  console.log(
    `\n\n${SCENARIOS.length + 2 - failures}/${SCENARIOS.length + 2} scenarios passed.`,
  );

  if (failures > 0) {
    process.exitCode = 1;
  }
}

await main();
