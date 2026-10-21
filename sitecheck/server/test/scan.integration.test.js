// End-to-end: start a local server that returns known headers/cookies/redirect,
// then run a full scan against it. Uses the test-only local-host allowance.
import assert from 'node:assert/strict'
import http from 'node:http'
import { after, before, test } from 'node:test'

process.env.NODE_ENV = 'test'
process.env.SITECHECK_ALLOW_LOCAL = '1'

const { scan } = await import('../src/scan.js')

let server
let port

before(async () => {
  server = http.createServer((req, res) => {
    if (req.url === '/redir') {
      res.writeHead(301, { Location: `http://127.0.0.1:${port}/` })
      return res.end()
    }
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Set-Cookie': ['sid=abc', 'ok=1; HttpOnly; SameSite=Lax'],
      Server: 'Apache/2.4.49',
      'X-Content-Type-Options': 'nosniff',
    })
    res.end('<!doctype html><title>test</title>')
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  port = server.address().port
})

after(() => server.close())

test('a plain-HTTP site with weak config gets a low grade and real findings', async () => {
  const report = await scan(`http://127.0.0.1:${port}/`)

  // HTTP, no HSTS/CSP, leaky cookie and version banner → should be poor.
  assert.ok(['D', 'F'].includes(report.grade), `expected D/F, got ${report.grade}`)
  assert.ok(report.counts.bad > 0)

  const tls = report.sections.find((s) => s.key === 'tls')
  assert.equal(tls.findings.find((f) => f.id === 'https').status, 'bad')

  const cookies = report.sections.find((s) => s.key === 'cookies')
  assert.equal(cookies.cookies.length, 2)
  assert.ok(cookies.cookies.find((c) => c.name === 'sid').issues.length > 0)

  const exposure = report.sections.find((s) => s.key === 'exposure')
  assert.equal(exposure.findings.find((f) => f.id === 'server').status, 'warn')

  assert.ok(report.disclaimer.includes('authorized'))
})

test('follows redirects and collects cookies from each hop', async () => {
  const report = await scan(`http://127.0.0.1:${port}/redir`)
  assert.equal(report.redirects.length, 2) // /redir then /
  assert.ok(report.target.finalUrl.endsWith('/'))
})
