# SiteCheck

A website **security configuration checker**. You enter a website address, and it reports on the site's public security hygiene: HTTPS and certificate, security headers, cookie flags, and exposed software information — with a plain-language fix for each problem and an overall grade.

- **Frontend:** React 18 + Vite
- **Backend:** Node.js + Express

> **Use responsibly.** SiteCheck is a *passive* tool: it makes one ordinary request to the address, like a browser visiting the page, and reads what the server sends back. It does **not** attack the site, send payloads, guess passwords, or probe for hidden pages. Only run it against websites you own or are explicitly authorized to test. The UI asks you to confirm this before every scan.

## What it checks

| Section | Looks at |
|---|---|
| **HTTPS & certificate** | HTTPS in use, HTTP→HTTPS redirect, certificate trust, expiry, TLS version |
| **Security headers** | HSTS, Content-Security-Policy, X-Frame-Options / frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Cookies** | Secure, HttpOnly and SameSite attributes on every cookie the site sets |
| **Information exposure** | Server / X-Powered-By and similar version banners, legacy X-XSS-Protection, cacheable pages that set cookies |

Each finding is scored, and the site gets a grade from **A** to **F**.

## Safety built in

- **SSRF protection:** the scanner refuses internal and private targets (localhost, `10.x`, `192.168.x`, `172.16–31.x`, `169.254.x` cloud-metadata, IPv6 loopback/ULA). Every redirect hop is re-checked.
- **Only http/https**, credentials stripped from URLs, body capped, request timeout, and a redirect limit.
- **Rate limiting** on the API (default 20 checks per minute per address).
- The server identifies itself honestly with a `User-Agent` of `SiteCheck/1.0`.

## Project structure

```
sitecheck/
├── server/                     Express API
│   ├── src/
│   │   ├── index.js            App + routes (/api/scan, /api/health)
│   │   ├── scan.js             Runs all checks, scores, grades
│   │   ├── fetcher.js          One passive request + redirect handling
│   │   ├── safety.js           URL validation + SSRF guards
│   │   ├── config.js           Settings from the environment
│   │   └── checks/
│   │       ├── headers.js      Security headers
│   │       ├── cookies.js      Cookie flags
│   │       ├── tls.js          HTTPS + certificate
│   │       └── exposure.js     Version banners and leaks
│   └── test/                   node:test unit + integration tests
└── web/                        React app
    └── src/
        ├── App.jsx             Search box, consent, results
        ├── components/Report.jsx
        ├── lib/api.js
        └── styles.css          Design (dark and light)
```

## Run it

You need **Node.js 18+**.

**1. Start the API**

```bash
cd server
npm install
cp .env.example .env     # optional; defaults are fine for local use
npm start                # http://localhost:8080
```

**2. Start the web app** (in a second terminal)

```bash
cd web
npm install
npm run dev              # http://localhost:5173
```

Open http://localhost:5173, enter a site you're authorized to test, tick the box, and check it.

**Tests**

```bash
cd server && npm test    # 19 tests: URL/SSRF guards, each check, full scan
```

## Put it online

- **API:** deploy the `server` folder to any Node host (Render, Railway, Fly.io, a VPS). Set `WEB_ORIGIN` to your site's address and `PORT` as the host requires.
- **Web:** run `npm run build` in `web` and host the `dist` folder (Netlify, Vercel, GitHub Pages). Set `VITE_API_URL` to your deployed API's address before building.

## Honest limits

This is a configuration and hygiene check, not a penetration test. A good grade means the basics are in place; it does not prove a site is secure, and a poor grade flags configuration worth fixing rather than a confirmed breach. For a thorough assessment, use a dedicated scanner and a professional review.
