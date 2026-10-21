import assert from 'node:assert/strict'
import { test } from 'node:test'

import { checkCookies } from '../src/checks/cookies.js'
import { checkExposure } from '../src/checks/exposure.js'
import { checkHeaders } from '../src/checks/headers.js'
import { checkTls } from '../src/checks/tls.js'

const httpsUrl = new URL('https://example.com/')

function finding(findings, id) {
  return findings.find((f) => f.id === id)
}

test('headers: flags a bare site as missing the key headers', () => {
  const f = checkHeaders({ url: httpsUrl, headers: {} })
  assert.equal(finding(f, 'hsts').status, 'bad')
  assert.equal(finding(f, 'csp').status, 'bad')
  assert.equal(finding(f, 'xfo').status, 'bad')
})

test('headers: a well-configured site passes', () => {
  const headers = {
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'content-security-policy': "default-src 'self'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'geolocation=()',
  }
  const f = checkHeaders({ url: httpsUrl, headers })
  assert.ok(f.every((x) => x.status === 'good'))
})

test('headers: CSP with unsafe-inline is only a warning', () => {
  const f = checkHeaders({ url: httpsUrl, headers: { 'content-security-policy': "default-src 'self' 'unsafe-inline'" } })
  assert.equal(finding(f, 'csp').status, 'warn')
})

test('cookies: catches missing Secure / HttpOnly / SameSite', () => {
  const r = checkCookies([{ raw: 'sid=abc', origin: 'https://example.com' }])
  const c = r.cookies[0]
  assert.equal(c.status, 'bad') // missing Secure over https is serious
  assert.ok(c.issues.some((i) => /Secure/.test(i.text)))
  assert.ok(c.issues.some((i) => /HttpOnly/.test(i.text)))
  assert.ok(c.issues.some((i) => /SameSite/.test(i.text)))
})

test('cookies: a well-set cookie passes', () => {
  const r = checkCookies([{ raw: 'sid=abc; Secure; HttpOnly; SameSite=Lax', origin: 'https://example.com' }])
  assert.equal(r.cookies[0].status, 'good')
})

test('cookies: SameSite=None without Secure is serious', () => {
  const r = checkCookies([{ raw: 'sid=abc; HttpOnly; SameSite=None', origin: 'https://example.com' }])
  assert.equal(r.cookies[0].status, 'bad')
})

test('tls: plain HTTP is flagged as bad', () => {
  const { findings } = checkTls({ start: new URL('http://example.com'), final: { url: new URL('http://example.com'), tls: null }, chain: [] })
  assert.equal(finding(findings, 'https').status, 'bad')
})

test('tls: soon-to-expire certificate warns', () => {
  const soon = new Date(Date.now() + 10 * 86_400_000).toUTCString()
  const final = { url: httpsUrl, tls: { authorized: true, protocol: 'TLSv1.3', cert: { valid_to: soon, valid_from: new Date().toUTCString(), subject: { CN: 'example.com' }, issuer: { O: 'Test CA' } } } }
  const { findings, certificate } = checkTls({ start: httpsUrl, final, chain: [{ protocol: 'https:' }] })
  assert.equal(finding(findings, 'expiry').status, 'bad') // < 15 days
  assert.equal(certificate.subject, 'example.com')
})

test('exposure: version banners are warned about', () => {
  const f = checkExposure({ url: httpsUrl, headers: { server: 'Apache/2.4.49', 'x-powered-by': 'PHP/8.1.2' } })
  assert.equal(finding(f, 'server').status, 'warn')
  assert.equal(finding(f, 'x-powered-by').status, 'warn')
})

test('exposure: a version-less Server header is fine', () => {
  const f = checkExposure({ url: httpsUrl, headers: { server: 'cloudflare' } })
  assert.equal(finding(f, 'server').status, 'good')
})
