# promptxecure-dashboard

React + Vite frontend for PromptXecure — real-time prompt injection monitoring and interactive playground.

## Features

- **Playground** — Test prompts live, see layer-by-layer detection results, compare raw vs sanitized
- **Dashboard** — Real-time analytics: blocked %, risk trends, OWASP LLM Top 10 coverage, auto-refresh
- **Logs** — Paginated scan history with risk filters and per-page controls

## Quick Start

```bash
npm install

# Dev server (proxies API at localhost:8000)
npm run dev

# Production build
npm run build
```

Or use the root Makefile:
```bash
make dev-dash
```

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_URL` | `""` (same-origin) | API base URL. Empty = Nginx proxy. |

For local development, set in `.env.local`:
```
VITE_API_URL=http://localhost:8000
```

## Tech Stack

| Package | Purpose |
|---------|---------|
| React 18 | UI framework |
| Vite | Build tool + dev server |
| React Router v6 | SPA routing |
| Recharts | Charts (bar, pie, line) |
| Tailwind CSS / CSS modules | Styling |

## Component Structure

```
src/
├── pages/
│   ├── PlaygroundPage.jsx    — Prompt input + result display
│   ├── DashboardPage.jsx     — Stats + charts + OWASP table
│   └── LogsPage.jsx          — Paginated log viewer
├── components/
│   ├── layout/
│   │   ├── Sidebar.jsx       — Navigation with active state
│   │   ├── Header.jsx        — Dynamic page title + API status
│   │   └── ErrorBoundary.jsx — Fallback UI on crash
│   ├── playground/
│   │   ├── PromptInput.jsx   — Textarea, model selector, attack examples
│   │   ├── ThreatCard.jsx    — Individual threat display
│   │   └── AnalysisResult.jsx — SVG arc gauge, layers, threats, LLM response
│   ├── dashboard/
│   │   ├── StatsGrid.jsx     — 4 stat cards with loading skeleton
│   │   └── ThreatChart.jsx   — Actions bar, categories pie, hourly trend
│   └── logs/
│       └── LogsTable.jsx     — Table with badges, loading + empty states
├── utils/
│   ├── api.js                — Typed API client (all endpoints)
│   └── helpers.js            — Formatting utilities
└── App.jsx                   — Router + ErrorBoundary
```

## Build

The Vite build outputs to `dist/` which is served by Nginx in production:

```bash
npm run build
# → dist/index.html + hashed assets
```

The `vite.config.js` is configured with:
- Minification enabled
- Source maps disabled (production)
- Manual chunks: `vendor` (React/router), `charts` (Recharts)
- API proxy for local dev: `/api → http://localhost:8000`
