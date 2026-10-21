// Guards that keep this a safe, passive tool.
//
// 1. Only http/https.
// 2. No internal or private network targets (SSRF protection): the scanner
//    must never be pointed at localhost, link-local, or RFC 1918 addresses,
//    so it can't be used to reach things behind the server.
import dns from 'node:dns/promises'
import net from 'node:net'

export class TargetError extends Error {}

/** Parse and sanity-check the target the user typed. Returns a URL object. */
export function normalizeTarget(input) {
  const raw = String(input || '').trim()
  if (!raw) throw new TargetError('Please enter a website address.')

  // Allow the user to type "example.com" without a scheme; default to https.
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`

  let url
  try {
    url = new URL(withScheme)
  } catch {
    throw new TargetError('That does not look like a valid website address.')
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new TargetError('Only http and https addresses can be checked.')
  }
  if (!url.hostname || !url.hostname.includes('.')) {
    throw new TargetError('Please enter a full domain, like example.com.')
  }
  // Credentials in the URL are a red flag; drop them.
  url.username = ''
  url.password = ''
  return url
}

const PRIVATE_V4 = [
  [/^127\./, 'loopback'],
  [/^10\./, 'private'],
  [/^192\.168\./, 'private'],
  [/^169\.254\./, 'link-local'],
  [/^0\./, 'reserved'],
]

function v4IsPrivate(ip) {
  if (PRIVATE_V4.some(([re]) => re.test(ip))) return true
  // 172.16.0.0 – 172.31.255.255
  const m = ip.match(/^172\.(\d+)\./)
  if (m) {
    const second = Number(m[1])
    if (second >= 16 && second <= 31) return true
  }
  // 100.64.0.0/10 (carrier-grade NAT)
  const c = ip.match(/^100\.(\d+)\./)
  if (c) {
    const second = Number(c[1])
    if (second >= 64 && second <= 127) return true
  }
  return false
}

function v6IsPrivate(ip) {
  const low = ip.toLowerCase()
  return (
    low === '::1' ||
    low === '::' ||
    low.startsWith('fe80') || // link-local
    low.startsWith('fc') || // unique local
    low.startsWith('fd') ||
    low.startsWith('::ffff:') // IPv4-mapped — check the mapped part separately
  )
}

function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) return v4IsPrivate(ip)
  if (net.isIPv6(ip)) {
    if (ip.toLowerCase().startsWith('::ffff:')) {
      const mapped = ip.split(':').pop()
      if (net.isIPv4(mapped)) return v4IsPrivate(mapped)
    }
    return v6IsPrivate(ip)
  }
  return false
}

/**
 * Resolve the hostname and refuse private / internal targets.
 * Returns the list of resolved IPs so the caller can pin to them.
 */
export async function assertPublicHost(hostname) {
  // Test-only escape hatch so the integration test can hit a local server.
  // Requires BOTH flags, and neither is ever set in production.
  if (process.env.NODE_ENV === 'test' && process.env.SITECHECK_ALLOW_LOCAL === '1') {
    return [hostname]
  }
  if (net.isIP(hostname)) {
    if (isPrivateAddress(hostname)) throw new TargetError('Internal and private addresses cannot be checked.')
    return [hostname]
  }
  let records
  try {
    records = await dns.lookup(hostname, { all: true })
  } catch {
    throw new TargetError("That website's address could not be found.")
  }
  if (!records.length) throw new TargetError("That website's address could not be found.")
  for (const { address } of records) {
    if (isPrivateAddress(address)) throw new TargetError('That address points to an internal network and cannot be checked.')
  }
  return records.map((r) => r.address)
}
