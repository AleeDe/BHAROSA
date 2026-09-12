import {
  analyzeUrlStructure,
  generateUrlReasons,
  normalizeUrl,
} from "../utils/urlAnalyzer.js";

import { checkWebRisk } from "./webRisk.service.js";

import { extractWebsite, searchWebsiteReputation } from "./tavily.service.js";

import { URLAnalysisResult, URLVerdict } from "../types/url.types.js";

const REPUTATION_KEYWORDS = [
  "scam",
  "phishing",
  "fraud",
  "fake",
  "malware",
  "warning",
  "fraudulent",
  "suspicious",
];

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
  // 3. Run external services in parallel
  // --------------------------------------------------

  const [webRisk, website, webSearch] = await Promise.all([
    checkWebRisk(url),

    extractWebsite(url),

    searchWebsiteReputation(url),
  ]);

  // --------------------------------------------------
  // 4. Generate initial reasons
  // --------------------------------------------------

  const reasons = generateUrlReasons(urlSignals);

  // --------------------------------------------------
  // 5. Calculate risk score
  // --------------------------------------------------

  let riskScore = 0;

  // -----------------------------------------------
  // Web Risk is the strongest signal.
  // -----------------------------------------------

  if (webRisk.unsafe) {
    riskScore += 100;

    for (const threat of webRisk.threats) {
      switch (threat) {
        case "SOCIAL_ENGINEERING":
          reasons.push(
            "Google Web Risk identifies this URL as associated with social engineering or phishing.",
          );
          break;

        case "SOCIAL_ENGINEERING_EXTENDED_COVERAGE":
          reasons.push(
            "Google Web Risk's extended coverage identifies this URL as potentially associated with phishing or deceptive activity.",
          );
          break;

        case "MALWARE":
          reasons.push(
            "Google Web Risk identifies this URL as associated with malware.",
          );
          break;

        case "UNWANTED_SOFTWARE":
          reasons.push(
            "Google Web Risk identifies this URL as associated with unwanted software.",
          );
          break;

        default:
          reasons.push(`Google Web Risk reported threat type: ${threat}.`);
      }
    }
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

  if (!urlSignals.usesHttps) {
    riskScore += 10;
  }

  // -----------------------------------------------
  // Tavily reputation signals
  // -----------------------------------------------

  let reputationHits = 0;

  for (const result of webSearch.results) {
    const searchableText = `${result.title} ${result.content}`.toLowerCase();

    const containsWarning = REPUTATION_KEYWORDS.some((keyword) =>
      searchableText.includes(keyword),
    );

    if (containsWarning) {
      reputationHits++;
    }
  }

  if (reputationHits >= 3) {
    riskScore += 25;

    reasons.push(
      "Multiple web search results contain warning-related information about this domain.",
    );
  } else if (reputationHits >= 1) {
    riskScore += 10;

    reasons.push(
      "Some web search results contain warning-related information about this domain.",
    );
  }

  // --------------------------------------------------
  // 6. Cap score
  // --------------------------------------------------

  riskScore = Math.min(riskScore, 100);

  // --------------------------------------------------
  // 7. Determine verdict
  // --------------------------------------------------

  let verdict: URLVerdict;

  if (webRisk.unsafe) {
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

    webRisk,

    website,

    webSearch,
  };
}
