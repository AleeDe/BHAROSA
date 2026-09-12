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
