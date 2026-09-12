import {
  analyzeUrlStructure,
  generateUrlReasons,
  normalizeUrl,
} from "../utils/urlAnalyzer.js";

import { checkUrlReputation } from "./webRisk.service.js";

import { URLAnalysisResult, URLVerdict } from "../types/url.types.js";

/**
 * Analyzes a URL for phishing and fraud risk.
 *
 * Scoring is deterministic and local. The only external request is an optional
 * reputation lookup; the target URL itself is never fetched, so analyzing a
 * link never causes a visit to it.
 *
 * @throws If the URL cannot be normalized. Reputation failures do not throw —
 * they degrade to local-rule-only scoring.
 */
export async function analyzeUrl(rawUrl: string): Promise<URLAnalysisResult> {
  // --------------------------------------------------
  // 1. Normalize URL
  // --------------------------------------------------

  const url = normalizeUrl(rawUrl);

  // --------------------------------------------------
  // 2. Analyze URL structure
  // --------------------------------------------------

  const urlSignals = analyzeUrlStructure(url);

  // --------------------------------------------------
  // 3. Optional reputation lookup
  // --------------------------------------------------

  const reputation = await checkUrlReputation(url);

  // --------------------------------------------------
  // 4. Generate initial reasons
  // --------------------------------------------------

  const reasons = generateUrlReasons(urlSignals);

  // --------------------------------------------------
  // 5. Calculate risk score
  // --------------------------------------------------

  let riskScore = 0;

  // -----------------------------------------------
  // Reputation is the strongest signal.
  // -----------------------------------------------

  if (reputation.unsafe) {
    riskScore += 100;

    reasons.push("A URL reputation service flagged this link as unsafe.");
  }

  // -----------------------------------------------
  // URL structure signals
  // -----------------------------------------------

  if (urlSignals.hasIpAddress) {
    riskScore += 25;
  }

  if (urlSignals.hasPunycode) {
    riskScore += 20;
  }

  if (urlSignals.hasUsername) {
    riskScore += 20;
  }

  if (urlSignals.isShortened) {
    riskScore += 10;
  }

  if (urlSignals.suspiciousQuery) {
    riskScore += 10;
  }

  if (urlSignals.excessiveSubdomains) {
    riskScore += 10;
  }

  if (urlSignals.suspiciousKeywords) {
    riskScore += 10;
  }

  // Stronger than any single generic signal, but not decisive on its own: a
  // brand token alone reaches "suspicious", and only combines to "dangerous".
  if (urlSignals.brandImpersonation) {
    riskScore += 40;
  }

  if (!urlSignals.usesHttps) {
    riskScore += 10;
  }

  // --------------------------------------------------
  // 6. Cap score
  // --------------------------------------------------

  riskScore = Math.min(riskScore, 100);

  // --------------------------------------------------
  // 7. Determine verdict
  // --------------------------------------------------

  let verdict: URLVerdict;

  if (reputation.unsafe) {
    verdict = "dangerous";
  } else if (riskScore >= 60) {
    verdict = "dangerous";
  } else if (riskScore >= 25) {
    verdict = "suspicious";
  } else {
    verdict = "safe";
  }

  // --------------------------------------------------
  // 8. Remove duplicate reasons
  // --------------------------------------------------

  const uniqueReasons = [...new Set(reasons)];

  // --------------------------------------------------
  // 9. Return evidence object
  // --------------------------------------------------

  return {
    url,

    verdict,

    riskScore,

    reasons: uniqueReasons,

    urlSignals,

    reputation,
  };
}
