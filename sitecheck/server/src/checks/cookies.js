// Checks the attributes of every cookie the site set (Secure, HttpOnly, SameSite).
// It reads the Set-Cookie headers only — it never stores or uses the values.

function parseCookie(raw) {
  const parts = raw.split(';').map((p) => p.trim())
  const [nameValue, ...attrParts] = parts
  const name = nameValue.split('=')[0]
  const attrs = {}
  for (const a of attrParts) {
    const [k, v] = a.split('=')
    attrs[k.toLowerCase()] = v === undefined ? true : v
  }
  return { name, attrs }
}

export function checkCookies(cookies) {
  if (!cookies.length) {
    return { summary: 'This site set no cookies on the page checked.', cookies: [] }
  }
  const results = cookies.map(({ raw, origin }) => {
    const { name, attrs } = parseCookie(raw)
    const https = origin.startsWith('https:')
    const issues = []

    if (https && !attrs.secure) issues.push({ status: 'bad', text: 'Missing Secure — the cookie can be sent over plain HTTP.', fix: 'Add the Secure attribute.' })
    if (!attrs.httponly) issues.push({ status: 'warn', text: 'Missing HttpOnly — JavaScript can read it, which helps attackers steal it via XSS.', fix: 'Add the HttpOnly attribute (unless the front-end genuinely needs to read this cookie).' })

    const sameSite = String(attrs.samesite || '').toLowerCase()
    if (!sameSite) issues.push({ status: 'warn', text: 'No SameSite attribute — leaves more room for cross-site request forgery (CSRF).', fix: 'Add SameSite=Lax (or Strict for sensitive cookies).' })
    else if (sameSite === 'none' && !attrs.secure) issues.push({ status: 'bad', text: 'SameSite=None without Secure is rejected by modern browsers.', fix: 'Add Secure whenever you use SameSite=None.' })

    return {
      name,
      secure: !!attrs.secure,
      httpOnly: !!attrs.httponly,
      sameSite: attrs.samesite || '(none)',
      status: issues.some((i) => i.status === 'bad') ? 'bad' : issues.length ? 'warn' : 'good',
      issues,
    }
  })

  const bad = results.filter((r) => r.status === 'bad').length
  const warn = results.filter((r) => r.status === 'warn').length
  const summary = bad || warn
    ? `${results.length} cookie(s): ${bad} with serious issues, ${warn} with warnings.`
    : `${results.length} cookie(s), all with Secure, HttpOnly and SameSite set well.`
  return { summary, cookies: results }
}
