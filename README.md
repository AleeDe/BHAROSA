# Digital Shield

Digital Shield is a WhatsApp-based hackathon MVP focused on three security capabilities:

- **Text fraud detection** — identifying scam and fraud patterns in message text
- **Phishing/suspicious URL detection** — flagging risky links shared in chat
- **Image analysis** — fraud analysis of text visible inside images, URL extraction from image text, and heuristic AI-generated-image suspicion

## Status: Step 1 — scaffold only

**None of the capabilities above are implemented.** They are planned. This repository currently contains only a minimal Node.js + TypeScript project scaffold:

- no WhatsApp / Baileys integration
- no Grok / xAI (or any other model) integration
- no text, URL, or image analysis
- no API clients, database, queue, or Docker setup

`src/index.ts` loads environment variables and prints a startup line. Nothing else.

## Requirements

- Node.js 20+
- npm

## Setup

```bash
npm install
cp .env.example .env
```

## Scripts

| Command | Description |
| --- | --- |
| `npm run dev` | Run the app from TypeScript source via tsx |
| `npm run build` | Compile TypeScript to `dist/` |
| `npm start` | Run the compiled output from `dist/` |
| `npm run typecheck` | Type-check without emitting files |

## Project structure

```
src/
  index.ts      entry point
  whatsapp/     (planned) WhatsApp transport layer
  analyzers/    (planned) text, URL, and image analyzers
  services/     (planned) external service clients
  risk/         (planned) risk scoring and verdicts
  utils/        (planned) shared helpers
  types/        (planned) shared type definitions
  config/       (planned) configuration loading
```

All directories other than `index.ts` are intentionally empty placeholders for later steps.
# barosa
