// Flags headers that reveal software and versions (which help an attacker pick
// known exploits), and a couple of other common information leaks.

function get(headers, name) {
  return headers[name.toLowerCase()]
}

const VERSION_RE = /\d+\.\d+/

export function checkExposure(final) {
  const h = final.headers
  const findings = []
  const add = (id, title, status, detail, fix) => findings.push({ id, title, status, detail, fix })

  const banners = [
    ['server', 'Server'],
    ['x-powered-by', 'X-Powered-By'],
    ['x-aspnet-version', 'X-AspNet-Version'],
    ['x-aspnetmvc-version', 'X-AspNetMvc-Version'],
    ['x-generator', 'X-Generator'],
  ]
  let anyLeak = false
  for (const [key, label] of banners) {
    const value = get(h, key)
    if (!value) continue
    const hasVersion = VERSION_RE.test(value)
    anyLeak = anyLeak || hasVersion
    add(key, `${label} header`, hasVersion ? 'warn' : 'good',
      hasVersion
        ? `Reveals software and version: "${value}". Attackers use this to look up known vulnerabilities.`
        : `Present: "${value}". It does not leak a version number.`,
      hasVersion ? `Remove or shorten the ${label} header so it does not include a version.` : null)
  }
  if (!anyLeak && !banners.some(([k]) => get(h, k))) {
    add('banners', 'Software version banners', 'good', 'No Server or X-Powered-By version banners were exposed.', null)
  }

  // X-XSS-Protection: the old header is deprecated and can introduce bugs.
  const xss = get(h, 'x-xss-protection')
  if (xss && xss.trim().startsWith('1')) {
    add('xxss', 'Legacy X-XSS-Protection', 'warn', 'The deprecated X-XSS-Protection filter is enabled; it can cause issues and is no replacement for CSP.', 'Set X-XSS-Protection: 0 and rely on Content-Security-Policy instead.')
  }

  // Caching of HTML with cookies — a light heuristic.
  const cache = get(h, 'cache-control') || ''
  if ((h['set-cookie'] || []).length && /public/.test(cache) && !/no-store|private/.test(cache)) {
    add('cache', 'Caching of a page that sets cookies', 'warn', 'The page sets cookies but is marked publicly cacheable, which can leak personalised content.', 'Use Cache-Control: private, no-store on pages that set cookies.')
  }

  return findings
}
