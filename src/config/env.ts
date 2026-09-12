import dotenv from "dotenv";

dotenv.config();

function getEnv(name: string, required = false): string | undefined {
  const value = process.env[name];

  if (required && !value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }

  return value;
}

export const env = {
  PORT: Number(process.env.PORT || 8000),

  WEB_RISK_API_KEY: getEnv("WEB_RISK_API_KEY"),

  TAVILY_API_KEY: getEnv("TAVILY_API_KEY"),
};
