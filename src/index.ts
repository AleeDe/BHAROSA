import "dotenv/config";

import { connectWhatsApp } from "./whatsapp/client.js";

console.log("Digital Shield starting...");

try {
  await connectWhatsApp();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Digital Shield failed to start: ${message}`);
  process.exitCode = 1;
}
