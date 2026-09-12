import express from "express";
import cors from "cors";

import urlRoutes from "./routes/url.routes.js";

const app = express();

// --------------------------------------------------
// Middleware
// --------------------------------------------------

app.use(
  cors({
    origin: true,
    credentials: true,
  }),
);

app.use(
  express.json({
    limit: "1mb",
  }),
);

// --------------------------------------------------
// Health check
// --------------------------------------------------

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "digital-shield-backend",
  });
});

// --------------------------------------------------
// Routes
// --------------------------------------------------

app.use("/api/v1/url", urlRoutes);

// --------------------------------------------------
// 404
// --------------------------------------------------

app.use((_req, res) => {
  res.status(404).json({
    success: false,

    error: {
      code: "NOT_FOUND",
      message: "The requested endpoint does not exist.",
    },
  });
});

// --------------------------------------------------
// Global error handler
// --------------------------------------------------

app.use(
  (
    error: unknown,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction,
  ) => {
    console.error("Unhandled error:", error);

    res.status(500).json({
      success: false,

      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "An unexpected server error occurred.",
      },
    });
  },
);

export default app;
