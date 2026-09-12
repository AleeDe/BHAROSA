/**
 * Characters that commonly end a sentence rather than a URL.
 *
 * Stripped from the end of a match so "visit example.com." does not yield a
 * trailing dot, and "(example.com)" does not keep the closing bracket.
 */
const TRAILING_PUNCTUATION = /[.,!?;:)\]}'"»]+$/;

/**
 * Matches URL-like tokens: an explicit scheme, a `www.` prefix, or a bare
 * domain with a plausible TLD.
 *
 * A token must not be preceded by `@` or by a character that can appear in the
 * local part of an email address, which is what keeps "user@example.com" from
 * being read as the domain "example.com".
 */
const URL_PATTERN =
  /(?<![@\w.+-])(?:https?:\/\/[^\s<>"']+|www\.[^\s<>"']+|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?:[/?#][^\s<>"']*)?)/gi;

/**
 * Balances bracket pairs at the end of a match.
 *
 * A URL wrapped in parentheses ends up with an unmatched closing bracket, while
 * a URL whose own path contains balanced brackets should keep them.
 */
function trimUnbalancedBrackets(url: string): string {
  let result = url;

  const pairs: [string, string][] = [
    ["(", ")"],
    ["[", "]"],
    ["{", "}"],
  ];

  let changed = true;
  while (changed) {
    changed = false;

    for (const [open, close] of pairs) {
      if (!result.endsWith(close)) {
        continue;
      }

      const opens = result.split(open).length - 1;
      const closes = result.split(close).length - 1;

      if (closes > opens) {
        result = result.slice(0, -1);
        changed = true;
      }
    }
  }

  return result;
}

/**
 * Strips punctuation that belongs to the surrounding sentence.
 *
 * Runs bracket balancing and trailing-punctuation removal alternately, so a
 * token such as `example.com/path).` is reduced correctly from both ends of the
 * trailing run.
 */
function trimBoundary(url: string): string {
  let previous: string;
  let result = url;

  do {
    previous = result;
    result = trimUnbalancedBrackets(result);
    result = result.replace(TRAILING_PUNCTUATION, "");
  } while (result !== previous && result.length > 0);

  return result;
}

/**
 * Finds URLs in a block of text.
 *
 * Recognizes explicit `http`/`https` links, `www.` hosts, and bare domains,
 * preserving each URL's path and query. Email addresses are not treated as
 * URLs. Results are deduplicated, case-sensitively, in first-seen order.
 *
 * Purely textual: nothing is fetched, resolved, or normalized beyond trimming
 * the punctuation around a token. Returns an empty array for ordinary text.
 */
export function extractUrls(text: string): string[] {
  if (!text) {
    return [];
  }

  const seen = new Set<string>();
  const urls: string[] = [];

  for (const match of text.matchAll(URL_PATTERN)) {
    const candidate = trimBoundary(match[0]);

    if (!candidate) {
      continue;
    }

    // A bare token has to keep a dot to still look like a hostname after
    // trimming; "e.g." style fragments fall away here.
    if (!candidate.includes(".")) {
      continue;
    }

    if (seen.has(candidate)) {
      continue;
    }

    seen.add(candidate);
    urls.push(candidate);
  }

  return urls;
}
