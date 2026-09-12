import { Request, Response } from "express";

import { analyzeUrl } from "../services/url.service.js";

export async function analyzeUrlController(
  req: Request,
  res: Response,
): Promise<void> {
  try {
    // -----------------------------------------------
    // Validate request
    // -----------------------------------------------

    // Handle missing or malformed request body
    if (typeof req.body !== 'object' || req.body === null) {
      res.status(400).json({
        success: false,
        error: {
          code: "INVALID_REQUEST",
          message: "Invalid request body. Expected JSON object.",
        },
      });
      return;
    }

    const { url } = req.body;

    if (typeof url !== "string" || url.trim().length === 0) {
      res.status(400).json({
        success: false,

        error: {
          code: "INVALID_URL",
          message: "Please provide a URL.",
        },
      });

      return;
    }

    // -----------------------------------------------
    // Analyze URL
    // -----------------------------------------------

    const result = await analyzeUrl(url);

    // -----------------------------------------------
    // Return result
    // -----------------------------------------------

    res.status(200).json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error("URL analysis error:", error);

    if (
      error instanceof Error &&
      (error.message.includes("Invalid URL") ||
        error.message.includes("Only HTTP") ||
        error.message.includes("URL cannot be empty"))
    ) {
      res.status(400).json({
        success: false,

        error: {
          code: "INVALID_URL",
          message: error.message,
        },
      });

      return;
    }

    res.status(500).json({
      success: false,

      error: {
        code: "URL_ANALYSIS_FAILED",
        message: "Unable to analyze this URL.",
      },
    });
  }
}
