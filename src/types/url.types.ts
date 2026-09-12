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

  /**
   * A known brand name appears in the hostname, but the registrable domain is
   * not that brand's own. True for `paypal-secure.example.com`, false for
   * `login.paypal.com`.
   */
  brandImpersonation: boolean;

  hostname: string;
}

/**
 * Outcome of the optional reputation lookup.
 *
 * `checked` is false when no API key is configured or the lookup failed, in
 * which case `unsafe` is always false: a reputation failure must never be read
 * as evidence of danger.
 */
export interface ReputationResult {
  checked: boolean;
  unsafe: boolean;
  threats: string[];
  error: string | null;
}

export interface URLAnalysisResult {
  url: string;
  verdict: URLVerdict;
  riskScore: number;
  reasons: string[];

  urlSignals: URLSignals;

  reputation: ReputationResult;
}
