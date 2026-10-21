import cors from 'cors'
import express from 'express'
import rateLimit from 'express-rate-limit'

import { config } from './config.js'
import { TargetError } from './safety.js'
import { scan } from './scan.js'

export function createApp() {
  const app = express()
  app.disable('x-powered-by')
  app.use(express.json({ limit: '8kb' }))
  app.use(cors({ origin: config.webOrigin }))

  app.get('/api/health', (_req, res) => res.json({ ok: true }))

  const limiter = rateLimit({
    windowMs: 60_000,
    max: config.rateLimitPerMinute,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many checks from this address. Please wait a minute and try again.' },
  })

  app.post('/api/scan', limiter, async (req, res) => {
    const target = req.body?.target
    try {
      const report = await scan(target)
      res.json(report)
    } catch (err) {
      if (err instanceof TargetError) return res.status(400).json({ error: err.message })
      console.error('Scan failed:', err)
      res.status(500).json({ error: 'Something went wrong while checking that site.' })
    }
  })

  return app
}

// Start only when run directly (not when imported by tests).
if (process.argv[1] && process.argv[1].endsWith('index.js')) {
  const app = createApp()
  app.listen(config.port, () => {
    console.log(`SiteCheck API on http://localhost:${config.port}`)
  })
}
