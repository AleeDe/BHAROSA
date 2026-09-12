import "dotenv/config";

import { analyzeImage } from "./analyzers/imageAnalyzer.js";

/**
 * Analyzes one image given on the command line and prints the result.
 *
 * Usage: npm run test:image -- <path>
 */
async function main(): Promise<void> {
  const filePath = process.argv[2];

  if (!filePath) {
    console.error("Usage: npm run test:image -- <path-to-image>");
    process.exitCode = 1;
    return;
  }

  console.log(`Analyzing: ${filePath}`);

  try {
    const result = await analyzeImage(filePath);

    console.log(`\nFraud risk:        ${result.fraud.risk}`);
    console.log(`Fraud score:       ${result.fraud.score}/100`);
    console.log(`Scam type:         ${result.fraud.scamType}`);
    console.log(`AI suspicion:      ${result.authenticity.aiSuspicion}`);
    console.log(
      `AI score:          ${result.authenticity.score ?? "null (not assessable)"}`,
    );
    console.log(`\nExtracted text:    ${result.extractedText || "(none)"}`);
    console.log(`\nSignals:           ${result.signals.join(", ") || "(none)"}`);
    console.log(`\nExplanation:       ${result.explanation}`);
    console.log(`Recommended:       ${result.recommendedAction}`);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    console.error(`FAILED: ${reason}`);
    process.exitCode = 1;
  }
}

await main();
