export type URLVerdict = "safe" | "suspicious" | "dangerous";

export interface URLAnalyzeRequest {
  url: string;
}

export interface URLSignals {
  usesHttps: boolean;
  hasIpAddress: boolean;
  hasPunycode: boolean;
  hasUsername: boolean;
  isShortened: boolean;
  suspiciousQuery: boolean;
  excessiveSubdomains: boolean;
  suspiciousKeywords: boolean;
  hostname: string;
}

export interface WebRiskResult {
  checked: boolean;
  unsafe: boolean;
  threats: string[];
  error: string | null;
}

export interface WebsiteResult {
  extracted: boolean;
  title: string | null;
  contentPreview: string | null;
  error: string | null;
}

export interface WebSearchResult {
  title: string;
  url: string;
  content: string;
  score: number | null;
}

export interface WebSearchResultData {
  performed: boolean;
  results: WebSearchResult[];
  error: string | null;
}

export interface URLAnalysisResult {
  url: string;
  verdict: URLVerdict;
  riskScore: number;
  reasons: string[];

  urlSignals: URLSignals;

  webRisk: WebRiskResult;

  website: WebsiteResult;

  webSearch: WebSearchResultData;
}
