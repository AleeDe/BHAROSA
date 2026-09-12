import { env } from "../config/env.js";
import { WebsiteResult, WebSearchResultData } from "../types/url.types.js";

const TAVILY_SEARCH_ENDPOINT = "https://api.tavily.com/search";

const TAVILY_EXTRACT_ENDPOINT = "https://api.tavily.com/extract";

async function tavilyRequest(endpoint: string, body: unknown): Promise<any> {
  if (!env.TAVILY_API_KEY) {
    throw new Error("TAVILY_API_KEY is not configured.");
  }

  const response = await fetch(endpoint, {
    method: "POST",

    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${env.TAVILY_API_KEY}`,
    },

    body: JSON.stringify(body),

    signal: AbortSignal.timeout(15_000),
  });

  if (!response.ok) {
    const text = await response.text();

    throw new Error(
      `Tavily returned HTTP ${response.status}: ` + text.slice(0, 500),
    );
  }

  return response.json();
}

export async function extractWebsite(url: string): Promise<WebsiteResult> {
  if (!env.TAVILY_API_KEY) {
    return {
      extracted: false,
      title: null,
      contentPreview: null,
      error: "TAVILY_API_KEY is not configured.",
    };
  }

  try {
    const data = await tavilyRequest(TAVILY_EXTRACT_ENDPOINT, {
      urls: [url],
      extract_depth: "basic",
      format: "markdown",
      include_images: false,
    });

    const results = data?.results ?? [];

    if (results.length === 0) {
      const failedResults = data?.failed_results ?? [];

      return {
        extracted: false,
        title: null,
        contentPreview: null,
        error:
          failedResults[0]?.error ?? "Tavily could not extract the webpage.",
      };
    }

    const first = results[0];

    const rawContent = first?.raw_content ?? "";

    return {
      extracted: true,
      title: extractTitle(rawContent),
      contentPreview: rawContent.slice(0, 5000),
      error: null,
    };
  } catch (error) {
    return {
      extracted: false,
      title: null,
      contentPreview: null,
      error:
        error instanceof Error ? error.message : "Tavily extraction failed.",
    };
  }
}

export async function searchWebsiteReputation(
  url: string,
): Promise<WebSearchResultData> {
  if (!env.TAVILY_API_KEY) {
    return {
      performed: false,
      results: [],
      error: "TAVILY_API_KEY is not configured.",
    };
  }

  try {
    const parsed = new URL(url);

    const hostname = parsed.hostname.toLowerCase();

    const query =
      `"${hostname}" ` +
      `(scam OR phishing OR fraud OR fake ` +
      `OR warning OR legitimate OR official)`;

    const data = await tavilyRequest(TAVILY_SEARCH_ENDPOINT, {
      query,
      search_depth: "basic",
      max_results: 5,
      include_answer: false,
      include_raw_content: false,
    });

    const results = (data?.results ?? []).map((result: any) => ({
      title: result?.title ?? "",

      url: result?.url ?? "",

      content: result?.content ?? "",

      score: typeof result?.score === "number" ? result.score : null,
    }));

    return {
      performed: true,
      results,
      error: null,
    };
  } catch (error) {
    return {
      performed: false,
      results: [],
      error: error instanceof Error ? error.message : "Tavily search failed.",
    };
  }
}

function extractTitle(markdown: string): string | null {
  const lines = markdown.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith("# ")) {
      return trimmed.substring(2).trim().slice(0, 300);
    }
  }

  return null;
}
