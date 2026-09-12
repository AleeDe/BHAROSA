import "dotenv/config";

import { analyzeText } from "./analyzers/textAnalyzer.js";

/** Sample messages covering obvious scams through to ordinary traffic. */
const SAMPLES: { label: string; text: string }[] = [
  {
    label: "TEST 1 - obvious scam",
    text: "Your HBL account will be blocked today. Send your OTP immediately to verify your account.",
  },
  {
    label: "TEST 2 - fake prize",
    text: "Congratulations! Aap 500,000 rupay jeet gaye hain. Prize receive karne ke liye 2,000 rupees registration fee JazzCash karein.",
  },
  {
    label: "TEST 3 - fake job",
    text: "Online job available. Salary 80,000 per month. Registration ke liye pehle 5,000 fee bhejein.",
  },
  {
    label: "TEST 4 - normal message",
    text: "Kal meeting 10 baje hai. Please presentation le aana.",
  },
  {
    label: "TEST 5 - normal financial message",
    text: "Your salary has been deposited into your account.",
  },
  {
    label: "TEST 6 - Roman Urdu social engineering",
    text: "Main tumhara cousin bol raha hun. Emergency hai, abhi 20,000 Easypaisa kar do, baad mein explain karta hun.",
  },
];

/**
 * Runs every sample through the analyzer and prints the result.
 *
 * Scores are printed, not asserted: model output varies between runs, so this
 * is a development aid rather than a pass/fail test.
 */
async function main(): Promise<void> {
  for (const { label, text } of SAMPLES) {
    console.log(`\n=== ${label} ===`);
    console.log(`Input: ${text}`);

    try {
      const result = await analyzeText(text);
      console.log(
        `Risk: ${result.fraud.risk} | Score: ${result.fraud.score} | Type: ${result.fraud.scamType}`,
      );
      console.log(`Signals: ${result.signals.join(", ") || "(none)"}`);
      console.log(`Explanation: ${result.explanation}`);
      console.log(`Recommended: ${result.recommendedAction}`);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      console.error(`FAILED: ${reason}`);
      process.exitCode = 1;
      return;
    }
  }
}

await main();
