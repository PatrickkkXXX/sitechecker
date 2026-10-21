// Checks the security-related HTTP response headers of the final page.
// Each finding: { id, title, status: 'good'|'warn'|'bad', detail, fix }

function get(headers, name) {
  return headers[name.toLowerCase()]
}

export function checkHeaders(final) {
  const h = final.headers
  const isHttps = final.url.protocol === 'https:'
  const findings = []
  const add = (id, title, status, detail, fix) => findings.push({ id, title, status, detail, fix })

  // Strict-Transport-Security
  const hsts = get(h, 'strict-transport-security')
  if (!isHttps) {
    add('hsts', 'HTTP Strict Transport Security (HSTS)', 'warn', 'The final page is not served over HTTPS, so HSTS does not apply yet.', 'Serve the site over HTTPS, then add HSTS.')
  } else if (!hsts) {
    add('hsts', 'HTTP Strict Transport Security (HSTS)', 'bad', 'Missing. Browsers are not told to always use HTTPS, which leaves room for downgrade attacks.', 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains')
  } else {
    const maxAge = Number((hsts.match(/max-age=(\d+)/i) || [])[1] || 0)
    if (maxAge < 15_552_000) {
      add('hsts', 'HTTP Strict Transport Security (HSTS)', 'warn', `Present but short (max-age=${maxAge}). Aim for at least 6 months.`, 'Use max-age=31536000; includeSubDomains')
    } else {
      add('hsts', 'HTTP Strict Transport Security (HSTS)', 'good', 'Present with a strong max-age.', null)
    }
  }

  // Content-Security-Policy
  const csp = get(h, 'content-security-policy')
  if (!csp) {
    add('csp', 'Content Security Policy (CSP)', 'bad', 'Missing. CSP is the strongest defence against cross-site scripting (XSS).', "Add a Content-Security-Policy header. Start with: default-src 'self'")
  } else if (/unsafe-inline|unsafe-eval|\*(?![.\w])/.test(csp)) {
    add('csp', 'Content Security Policy (CSP)', 'warn', 'Present, but it allows unsafe-inline, unsafe-eval or a wildcard source, which weakens it.', "Remove 'unsafe-inline' / 'unsafe-eval' and wildcard sources where you can.")
  } else {
    add('csp', 'Content Security Policy (CSP)', 'good', 'Present and reasonably strict.', null)
  }

  // X-Frame-Options / frame-ancestors
  const xfo = get(h, 'x-frame-options')
  const frameAncestors = csp && /frame-ancestors/i.test(csp)
  if (!xfo && !frameAncestors) {
    add('xfo', 'Clickjacking protection', 'bad', 'No X-Frame-Options and no CSP frame-ancestors. The page can be embedded in a hidden frame (clickjacking).', "Add X-Frame-Options: DENY, or CSP frame-ancestors 'none'.")
  } else {
    add('xfo', 'Clickjacking protection', 'good', xfo ? `X-Frame-Options: ${xfo}` : 'Covered by CSP frame-ancestors.', null)
  }

  // X-Content-Type-Options
  const xcto = get(h, 'x-content-type-options')
  if (!xcto || !/nosniff/i.test(xcto)) {
    add('xcto', 'MIME-sniffing protection', 'warn', 'Missing X-Content-Type-Options: nosniff. Browsers may guess content types, which can enable some attacks.', 'Add: X-Content-Type-Options: nosniff')
  } else {
    add('xcto', 'MIME-sniffing protection', 'good', 'Set to nosniff.', null)
  }

  // Referrer-Policy
  const ref = get(h, 'referrer-policy')
  if (!ref) {
    add('referrer', 'Referrer-Policy', 'warn', 'Missing. Full URLs may leak to other sites in the Referer header.', 'Add: Referrer-Policy: strict-origin-when-cross-origin')
  } else {
    add('referrer', 'Referrer-Policy', 'good', `Set to ${ref}.`, null)
  }

  // Permissions-Policy
  const pp = get(h, 'permissions-policy')
  if (!pp) {
    add('permissions', 'Permissions-Policy', 'warn', 'Missing. Powerful features (camera, microphone, geolocation) are not restricted at the header level.', 'Add a Permissions-Policy that disables features you do not use, e.g. geolocation=(), camera=(), microphone=()')
  } else {
    add('permissions', 'Permissions-Policy', 'good', 'Present.', null)
  }

  return findings
}
