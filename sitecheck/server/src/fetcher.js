// Makes ONE ordinary request to the target and returns the response headers,
// a small slice of the body, and the redirect chain. Passive: it reads what the
// server sends back, exactly like a browser visiting the page. It never sends
// payloads, guesses passwords, or probes paths.
import http from 'node:http'
import https from 'node:https'

import { config } from './config.js'
import { assertPublicHost, normalizeTarget, TargetError } from './safety.js'

const MAX_BODY_BYTES = 256 * 1024 // enough to sniff a page; we don't store sites

function requestOnce(url) {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === 'https:' ? https : http
    const req = lib.request(
      url,
      {
        method: 'GET',
        headers: { 'User-Agent': config.userAgent, Accept: 'text/html,*/*' },
        timeout: config.requestTimeoutMs,
        // We validate the chain ourselves and want to report on it rather
        // than throw, but we still never *send* anything sensitive.
        rejectUnauthorized: false,
        servername: url.hostname,
      },
      (res) => {
        const chunks = []
        let size = 0
        res.on('data', (c) => {
          size += c.length
          if (size <= MAX_BODY_BYTES) chunks.push(c)
          if (size > MAX_BODY_BYTES) res.destroy()
        })
        res.on('end', () => finish())
        res.on('close', () => finish())
        let done = false
        function finish() {
          if (done) return
          done = true
          const socket = res.socket
          const tls = url.protocol === 'https:' && socket?.getPeerCertificate
            ? { cert: socket.getPeerCertificate(), protocol: socket.getProtocol?.(), authorized: socket.authorized, authorizationError: socket.authorizationError }
            : null
          resolve({
            status: res.statusCode,
            headers: res.headers,
            rawHeaders: res.rawHeaders,
            body: Buffer.concat(chunks).toString('utf8'),
            location: res.headers.location,
            tls,
          })
        }
      },
    )
    req.on('timeout', () => req.destroy(new TargetError('The website took too long to respond.')))
    req.on('error', (err) => {
      if (err instanceof TargetError) return reject(err)
      reject(new TargetError(`The website could not be reached (${err.code || 'network error'}).`))
    })
    req.end()
  })
}

/**
 * Follow redirects manually, checking every hop is a public host first, and
 * collect every Set-Cookie seen along the way.
 */
export async function fetchTarget(input) {
  const start = normalizeTarget(input)
  const chain = []
  const cookies = []
  let url = start
  let final = null

  for (let i = 0; i <= config.maxRedirects; i++) {
    await assertPublicHost(url.hostname)
    const res = await requestOnce(url)

    const setCookie = res.headers['set-cookie'] || []
    for (const c of setCookie) cookies.push({ raw: c, origin: url.origin })

    chain.push({ url: url.toString(), status: res.status, protocol: url.protocol })

    if ([301, 302, 303, 307, 308].includes(res.status) && res.location) {
      let next
      try {
        next = new URL(res.location, url)
      } catch {
        throw new TargetError('The website sent an invalid redirect.')
      }
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        throw new TargetError('The website redirected somewhere that is not a web address.')
      }
      url = next
      continue
    }
    final = { ...res, url }
    break
  }
  if (!final) throw new TargetError('The website redirected too many times.')

  return { start, final, chain, cookies }
}
