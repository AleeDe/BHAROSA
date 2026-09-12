import { getVirusTotalApiKey } from "../config/env.js";
import type { ReputationResult } from "../types/url.types.js";

type VirusTotalAnalysisStats = {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  timeout?: number;
};

type VirusTotalEngineResult = {
  category?: string;
  result?: string;
};

const VIRUSTOTAL_URLS_ENDPOINT = "https://www.virustotal.com/api/v3/urls";

/** Cap on each request, so a hanging provider cannot stall an analysis. */
const REQUEST_TIMEOUT_MS = 10_000;

/** Pause before polling for the analysis report. */
const REPORT_DELAY_MS = 1500;

/** Result used whenever the lookup could not produce a verdict. */
function unavailable(error: string): ReputationResult {
  return { checked: false, unsafe: false, threats: [], error };
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Looks up a URL's reputation with VirusTotal.
 *
 * Entirely optional: with no API key, or on any timeout, rate limit, or
 * provider failure, this reports `checked: false` and `unsafe: false` so the
 * caller falls back to local rules. A failed lookup never raises risk, and
 * never throws.
 */
export async function checkUrlReputation(
  url: string,
): Promise<ReputationResult> {
  const apiKey = getVirusTotalApiKey();

  if (!apiKey) {
    return unavailable("No VirusTotal API key configured.");
  }

  try {
    const scanResponse = await fetch(VIRUSTOTAL_URLS_ENDPOINT, {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ url }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!scanResponse.ok) {
      return unavailable(
        `VirusTotal scan request failed (${scanResponse.status}).`,
      );
    }

    const scanJson = (await scanResponse.json()) as {
      data?: { id?: string };
    };

    const analysisId = scanJson?.data?.id;

    if (!analysisId) {
      return unavailable("VirusTotal did not return an analysis id.");
    }

    await wait(REPORT_DELAY_MS);

    const reportResponse = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`,
      {
        method: "GET",
        headers: {
          "x-apikey": apiKey,
          Accept: "application/json",
        },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      },
    );

    if (!reportResponse.ok) {
      return unavailable(
        `VirusTotal report request failed (${reportResponse.status}).`,
      );
    }

    const reportJson = (await reportResponse.json()) as {
      data?: {
        attributes?: {
          stats?: VirusTotalAnalysisStats;
          results?: Record<string, VirusTotalEngineResult>;
        };
      };
    };

    const attributes = reportJson?.data?.attributes;
    const stats = attributes?.stats ?? {};
    const results = attributes?.results ?? {};

    const malicious = Number(stats.malicious ?? 0);
    const suspicious = Number(stats.suspicious ?? 0);

    const threats = Object.entries(results)
      .filter(
        ([, item]) =>
          item?.category === "malicious" || item?.category === "suspicious",
      )
      .map(([engine, item]) => {
        const verdict = item?.result ?? item?.category ?? "suspicious";
        return `${engine}: ${verdict}`;
      });

    return {
      checked: true,
      unsafe: malicious > 0 || suspicious > 0,
      threats,
      error: null,
    };
  } catch (error) {
    // Timeouts, DNS failures, and malformed responses all land here. The
    // message is the provider's or Node's own; no key or request body is
    // included.
    const message =
      error instanceof Error ? error.message : "VirusTotal request failed.";

    return unavailable(message);
  }
}
