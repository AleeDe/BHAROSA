import "dotenv/config";

import { analyzeUrl } from "./services/url.service.js";
import { extractUrls } from "./utils/extractUrls.js";
import { normalizeUrl } from "./utils/urlAnalyzer.js";

/** Prints a section heading. */
function heading(title: string): void {
  console.log(`\n${"=".repeat(70)}\n${title}\n${"=".repeat(70)}`);
}

const EXTRACTION_CASES: string[] = [
  "Visit https://example.com",
  "Go to www.example.com/login",
  "Check example.com",
  "Nothing to see here",
  "Use https://example.com and https://example.com again",
  "Is link ko check karo https://example.com/login",
  "Open this: https://example.com/login.",
  "(https://example.com/path)",
  "Email me at user@example.com",
];

const NORMALIZATION_CASES: string[] = [
  "example.com",
  "www.example.com",
  "https://example.com",
  "http://example.com",
  "https://example.com/login?x=1",
  "EXAMPLE.COM",
  "https://example.com:443/path",
  "https://example.com/#fragment",
  "not a url",
  "://bad",
  "https://",
  "javascript:alert(1)",
];

const ANALYSIS_CASES: string[] = [
  "https://example.com",
  "http://192.168.1.10/login",
  "https://paypal.com.example-login.xyz",
  "https://login.security.account.example.com",
  "https://xn--e1afmkfd.example/",
  "http://example.com",
  "https://example.com/account/verify/login",
  "https://example.com/search?q=hello&page=2",
  "https://example.com/blog/2026/09/a-fairly-long-but-entirely-ordinary-article-title",
];

const ADVERSARIAL_CASES: string[] = [
  "https://paypal-secure-login.example.com/verify",
  "http://10.0.0.1/account/login",
  "https://www.example.com/login",
  "https://secure.example.com/payment",
  "https://xn--e1afmkfd.example/",
  "https://example.com/?redirect=https%3A%2F%2Fother.example",
];

/** Brand cases, with the `brandImpersonation` value each one should produce. */
const BRAND_CASES: { url: string; expected: boolean; note: string }[] = [
  // Legitimate brand domains.
  { url: "https://paypal.com", expected: false, note: "official domain" },
  { url: "https://www.paypal.com/login", expected: false, note: "official subdomain" },
  { url: "https://accounts.google.com", expected: false, note: "official subdomain" },
  { url: "https://jazzcash.com.pk", expected: false, note: "official multi-part domain" },
  { url: "https://www.easypaisa.com.pk", expected: false, note: "official multi-part domain" },

  // Impersonation.
  { url: "https://paypal.com.example-login.xyz", expected: true, note: "brand as subdomain prefix" },
  { url: "https://paypal-secure-login.example.com/verify", expected: true, note: "brand in hyphen token" },
  { url: "https://secure-paypal.example.net", expected: true, note: "brand in hyphen token" },
  { url: "https://google-login.example.com", expected: true, note: "brand in hyphen token" },
  { url: "https://hbl-secure.example.com", expected: true, note: "PK bank impersonation" },
  { url: "https://jazzcash-login.example.com", expected: true, note: "PK wallet impersonation" },

  // False-positive guards.
  { url: "https://example.com/paypal", expected: false, note: "brand in path, not hostname" },
  { url: "https://mypaypalette.example.com", expected: false, note: "substring overlap only" },
  { url: "https://example.com", expected: false, note: "no brand at all" },
];

/** Runs the brand cases and prints a pass/fail table. */
async function reportBrandCases(): Promise<void> {
  let failures = 0;

  for (const { url, expected, note } of BRAND_CASES) {
    const result = await analyzeUrl(url);
    const actual = result.urlSignals.brandImpersonation;
    const ok = actual === expected;

    if (!ok) {
      failures++;
    }

    console.log(
      `  ${ok ? "PASS" : "FAIL"}  brand=${String(actual).padEnd(5)} ` +
        `${result.verdict.padEnd(11)} ${String(result.riskScore).padStart(3)}/100  ` +
        `${url}`,
    );
    console.log(`        (${note}${ok ? "" : `; expected brand=${expected}`})`);
  }

  console.log(
    `\n  ${BRAND_CASES.length - failures}/${BRAND_CASES.length} brand cases passed.`,
  );
}

/** Runs one URL through the analyzer and prints a compact summary. */
async function reportAnalysis(input: string): Promise<void> {
  try {
    const result = await analyzeUrl(input);

    console.log(`\nINPUT      : ${input}`);
    console.log(`NORMALIZED : ${result.url}`);
    console.log(`VERDICT    : ${result.verdict}  (score ${result.riskScore}/100)`);

    const active = Object.entries(result.urlSignals)
      .filter(([key, value]) => value === true && key !== "usesHttps")
      .map(([key]) => key);

    if (!result.urlSignals.usesHttps) {
      active.push("noHttps");
    }

    console.log(`SIGNALS    : ${active.join(", ") || "(none)"}`);
    console.log(
      `REPUTATION : checked=${result.reputation.checked} unsafe=${result.reputation.unsafe}${
        result.reputation.error ? ` (${result.reputation.error})` : ""
      }`,
    );

    if (result.reasons.length > 0) {
      console.log("REASONS    :");
      for (const reason of result.reasons) {
        console.log(`  - ${reason}`);
      }
    }
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    console.log(`\nINPUT      : ${input}`);
    console.log(`ERROR      : ${reason}`);
  }
}

async function main(): Promise<void> {
  heading("extractUrls");
  for (const text of EXTRACTION_CASES) {
    const found = extractUrls(text);
    console.log(`\n  IN  : ${JSON.stringify(text)}`);
    console.log(`  OUT : ${JSON.stringify(found)}`);
  }

  heading("normalizeUrl");
  for (const input of NORMALIZATION_CASES) {
    try {
      console.log(`  ${JSON.stringify(input).padEnd(34)} -> ${normalizeUrl(input)}`);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      console.log(`  ${JSON.stringify(input).padEnd(34)} -> ERROR: ${reason}`);
    }
  }

  heading("analyzeUrl");
  for (const input of ANALYSIS_CASES) {
    await reportAnalysis(input);
  }

  heading("analyzeUrl - adversarial");
  for (const input of ADVERSARIAL_CASES) {
    await reportAnalysis(input);
  }

  heading("brand impersonation");
  await reportBrandCases();

  heading("non-URL input");
  console.log(`  extractUrls("hello brother") -> ${JSON.stringify(extractUrls("hello brother"))}`);
}

await main();
