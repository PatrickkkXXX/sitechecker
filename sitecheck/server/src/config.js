// Settings, read from the environment (see .env.example).
export const config = {
  port: Number(process.env.PORT) || 8080,
  webOrigin: process.env.WEB_ORIGIN || 'http://localhost:5173',
  requestTimeoutMs: Number(process.env.REQUEST_TIMEOUT_MS) || 10_000,
  maxRedirects: Number(process.env.MAX_REDIRECTS) || 5,
  rateLimitPerMinute: Number(process.env.RATE_LIMIT_PER_MINUTE) || 20,
  // A passive checker identifies itself honestly.
  userAgent: 'SiteCheck/1.0 (+security configuration checker; passive)',
}
