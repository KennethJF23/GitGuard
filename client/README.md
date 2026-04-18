# GitGuard Client

Frontend for GitGuard, a repository analysis platform that provides:

- Human-readable repository health analysis
- Local-first AI metadata explanation
- Malware pipeline dashboard with deterministic verdicts

Built with Next.js App Router, TypeScript, Tailwind CSS, and Framer Motion.

## Features

- JWT-protected pages through client-side auth gate
- Three analysis dashboards sharing a unified UI shell
- Responsive layout and overflow-safe containers for desktop/mobile
- Internal navigation through Next.js routing (no full page reloads)
- Staged loading feedback during repository scans

## Environment

Create client/.env.local:

```env
NEXT_PUBLIC_API_BASE_URL=http://localhost:5000
```

For deployed frontend (for example Vercel), set:

```env
NEXT_PUBLIC_API_BASE_URL=https://gitguard.onrender.com
```

## Development

Install and run:

```bash
npm install
npm run dev
```

Build for production:

```bash
npm run build
npm run start
```

## Authentication Notes

- Client currently stores the JWT in localStorage for session continuity.
- Social login has been removed; email/password auth only.
- Planned hardening: migrate to server-issued HttpOnly cookies.

## Project Areas

- src/app: route entry points and global layout
- src/components/layout: site header and footer
- src/components/sections/analysis: shared analysis dashboard UI
- src/lib/authSession.ts: token read/write/clear helpers

## Analysis Routes

- /analyze: human repository analysis
- /ai-analyze: local-first AI explanation analysis
- /malware-detection: malware pipeline scan dashboard

Each route uses the same dashboard component with mode-specific endpoint mapping.
