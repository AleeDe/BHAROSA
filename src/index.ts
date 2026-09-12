// import "dotenv/config";

// console.log("Digital Shield starting...");
import app from "./app.js";

import { env } from "./config/env.js";

app.listen(env.PORT, () => {
  console.log(
    `🛡️ Digital Shield backend running on http://localhost:${env.PORT}`,
  );

  console.log(
    `URL analysis endpoint: http://localhost:${env.PORT}/api/v1/url/analyze`,
  );
});
