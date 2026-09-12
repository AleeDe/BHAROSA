import dns from "node:dns/promises";
import net from "node:net";
import { URL } from "node:url";

import { URLSignals } from "../types/url.types.js";

const SHORTENER_DOMAINS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "is.gd",
  "ow.ly",
  "buff.ly",
  "cutt.ly",
  "rb.gy",
  "shorturl.at",
  "tiny.one",
]);

const SUSPICIOUS_KEYWORDS = [
  "login",
  "signin",
  "verify",
  "verification",
  "account",
  "secure",
  "security",
  "password",
  "passwd",
  "credential",
  "wallet",
  "payment",
  "bank",
  "confirm",
  "otp",
  "refund",
  "prize",
  "winner",
  "bonus",
  "free",
  "claim",
  "urgent",
];

/**
 * Brands commonly impersonated in phishing, mapped to their official domains.
 *
 * Deliberately small and explicit: a large brand database would add false
 * positives without helping the scams this product actually sees.
 */
const KNOWN_BRANDS: Record<string, string> = {
  paypal: "paypal.com",
  google: "google.com",
  microsoft: "microsoft.com",
  apple: "apple.com",
  facebook: "facebook.com",
  instagram: "instagram.com",
  whatsapp: "whatsapp.com",
  amazon: "amazon.com",
  hbl: "hbl.com",
  ubl: "ubldigital.com",
  meezan: "meezanbank.com",
  jazzcash: "jazzcash.com.pk",
  easypaisa: "easypaisa.com.pk",
  daraz: "daraz.pk",
};

/**
 * Reports whether a hostname sits within a domain.
 *
 * Matches only on a dot boundary, so `evilpaypal.com` does not count as
 * `paypal.com` while `login.paypal.com` does.
 */
function isWithinDomain(hostname: string, domain: string): boolean {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

/**
 * Detects a known brand name used outside that brand's official domain.
 *
 * The hostname is split on the separators that delimit words in a domain, so a
 * brand is only recognized as a whole token: `secure-paypal.example.net`
 * matches, `mypaypalette.example.com` does not. A hostname legitimately inside
 * the brand's own domain never counts.
 */
function hasBrandImpersonation(hostname: string): boolean {
  const tokens = new Set(hostname.split(/[.\-_]/).filter(Boolean));

  for (const [brand, officialDomain] of Object.entries(KNOWN_BRANDS)) {
    if (!tokens.has(brand)) {
      continue;
    }

    if (!isWithinDomain(hostname, officialDomain)) {
      return true;
    }
  }

  return false;
}

export function normalizeUrl(input: string): string {
  let value = input.trim();

  if (!value) {
    throw new Error("URL cannot be empty.");
  }

  if (!/^https?:\/\//i.test(value)) {
    value = `https://${value}`;
  }

  let parsed: URL;

  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Invalid URL.");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only HTTP and HTTPS URLs are supported.");
  }

  if (!parsed.hostname) {
    throw new Error("URL does not contain a hostname.");
  }

  return parsed.toString();
}

function isIpAddress(hostname: string): boolean {
  return net.isIP(hostname) !== 0;
}

function hasPunycode(hostname: string): boolean {
  return hostname
    .split(".")
    .some((part) => part.toLowerCase().startsWith("xn--"));
}

function hasSuspiciousQuery(parsed: URL): boolean {
  const suspiciousParameters = [
    "password",
    "passwd",
    "pass",
    "otp",
    "token",
    "verify",
    "verification",
    "login",
    "signin",
    "account",
    "payment",
    "card",
    "cvv",
  ];

  for (const key of parsed.searchParams.keys()) {
    if (suspiciousParameters.includes(key.toLowerCase())) {
      return true;
    }
  }

  return false;
}

function hasSuspiciousKeyword(parsed: URL): boolean {
  const fullUrl = parsed.toString().toLowerCase();

  return SUSPICIOUS_KEYWORDS.some((keyword) => fullUrl.includes(keyword));
}

function hasExcessiveSubdomains(hostname: string): boolean {
  const parts = hostname.split(".");

  return parts.length >= 5;
}

export function analyzeUrlStructure(normalizedUrl: string): URLSignals {
  const parsed = new URL(normalizedUrl);

  const hostname = parsed.hostname.toLowerCase();

  return {
    usesHttps: parsed.protocol === "https:",

    hasIpAddress: isIpAddress(hostname),

    hasPunycode: hasPunycode(hostname),

    hasUsername: parsed.username.length > 0,

    isShortened: SHORTENER_DOMAINS.has(hostname),

    suspiciousQuery: hasSuspiciousQuery(parsed),

    excessiveSubdomains: hasExcessiveSubdomains(hostname),

    suspiciousKeywords: hasSuspiciousKeyword(parsed),

    brandImpersonation: hasBrandImpersonation(hostname),

    hostname,
  };
}

export function generateUrlReasons(signals: URLSignals): string[] {
  const reasons: string[] = [];

  if (!signals.usesHttps) {
    reasons.push("The website does not use HTTPS.");
  }

  if (signals.hasIpAddress) {
    reasons.push(
      "The link uses an IP address instead of a normal domain name.",
    );
  }

  if (signals.hasPunycode) {
    reasons.push(
      "The domain contains encoded characters that can sometimes be used for look-alike domains.",
    );
  }

  if (signals.hasUsername) {
    reasons.push(
      "The URL contains a username before the hostname, which is unusual for many public websites.",
    );
  }

  if (signals.isShortened) {
    reasons.push(
      "The link uses a URL-shortening service, so its final destination is hidden.",
    );
  }

  if (signals.suspiciousQuery) {
    reasons.push(
      "The URL contains parameters associated with login, verification, payment, or account actions.",
    );
  }

  if (signals.excessiveSubdomains) {
    reasons.push(
      "The domain contains an unusually large number of subdomains.",
    );
  }

  if (signals.suspiciousKeywords) {
    reasons.push(
      "The URL contains words commonly associated with account verification, payments, prizes, or urgent actions.",
    );
  }

  if (signals.brandImpersonation) {
    reasons.push(
      "The hostname appears to use a known brand name outside the brand's official domain.",
    );
  }

  return reasons;
}

/**
 * Resolve the hostname.
 *
 * This is currently informational.
 * We do not use the resolved IP to decide whether a URL is malicious.
 */
export async function resolveHostname(hostname: string): Promise<string[]> {
  try {
    const records = await dns.resolve4(hostname);

    return records;
  } catch {
    return [];
  }
}
