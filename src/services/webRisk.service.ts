import type { WebRiskResult } from "../types/url.types.js";

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

function getApiKey(): string {
  return process.env.VIRUSTOTAL_API_KEY ?? process.env.WEB_RISK_API_KEY ?? "";
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function checkWebRisk(url: string): Promise<WebRiskResult> {
  const apiKey = getApiKey();

  if (!apiKey) {
    return {
      checked: true,
      unsafe: false,
      threats: [],
      error: "Missing VirusTotal API key",
    };
  }

  try {
    const scanResponse = await fetch(VIRUSTOTAL_URLS_ENDPOINT, {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ url }),
    });

    const scanText = await scanResponse.text();
    let scanJson: any = {};

    try {
      scanJson = JSON.parse(scanText);
    } catch {
      scanJson = { raw: scanText };
    }

    if (!scanResponse.ok) {
      const message =
        scanJson?.error?.message ?? "VirusTotal URL scan request failed";

      return {
        checked: true,
        unsafe: false,
        threats: [],
        error: message,
      };
    }

    const analysisId = scanJson?.data?.id;

    if (!analysisId) {
      return {
        checked: true,
        unsafe: false,
        threats: [],
        error: "VirusTotal did not return an analysis id.",
      };
    }

    await wait(1500);

    const reportResponse = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        method: "GET",
        headers: {
          "x-apikey": apiKey,
          Accept: "application/json",
        },
      },
    );

    const reportText = await reportResponse.text();
    let reportJson: any = {};

    try {
      reportJson = JSON.parse(reportText);
    } catch {
      reportJson = { raw: reportText };
    }

    if (!reportResponse.ok) {
      const message =
        reportJson?.error?.message ??
        "VirusTotal analysis report request failed";

      return {
        checked: true,
        unsafe: false,
        threats: [],
        error: message,
      };
    }

    const stats = (reportJson?.data?.attributes?.stats ??
      {}) as VirusTotalAnalysisStats;
    const results = (reportJson?.data?.attributes?.results ?? {}) as Record<
      string,
      VirusTotalEngineResult
    >;

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
    const message =
      error instanceof Error
        ? error.message
        : "Unexpected VirusTotal request failure";

    return {
      checked: true,
      unsafe: false,
      threats: [],
      error: message,
    };
  }
}
