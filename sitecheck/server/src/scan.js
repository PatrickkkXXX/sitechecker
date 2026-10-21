// Runs all the checks and produces one report with an overall grade.
import { checkCookies } from './checks/cookies.js'
import { checkExposure } from './checks/exposure.js'
import { checkHeaders } from './checks/headers.js'
import { checkTls } from './checks/tls.js'
import { fetchTarget } from './fetcher.js'

function scoreFindings(findings) {
  // Each bad = -15, each warn = -5, capped at 0.
  let score = 100
  for (const f of findings) {
    if (f.status === 'bad') score -= 15
    else if (f.status === 'warn') score -= 5
  }
  return Math.max(0, score)
}

function grade(score) {
  if (score >= 90) return 'A'
  if (score >= 80) return 'B'
  if (score >= 65) return 'C'
  if (score >= 50) return 'D'
  return 'F'
}

export async function scan(input) {
  const fetched = await fetchTarget(input)
  const { start, final, chain } = fetched

  const headerFindings = checkHeaders(final)
  const tlsResult = checkTls(fetched)
  const exposureFindings = checkExposure(final)
  const cookieResult = checkCookies(fetched.cookies)

  // Flatten cookie issues into findings for scoring.
  const cookieFindings = cookieResult.cookies.flatMap((c) =>
    c.issues.map((i) => ({ id: `cookie-${c.name}`, title: `Cookie "${c.name}"`, status: i.status, detail: i.text, fix: i.fix })),
  )

  const sections = [
    { key: 'tls', title: 'HTTPS & certificate', findings: tlsResult.findings },
    { key: 'headers', title: 'Security headers', findings: headerFindings },
    { key: 'cookies', title: 'Cookies', findings: cookieFindings, summary: cookieResult.summary, cookies: cookieResult.cookies },
    { key: 'exposure', title: 'Information exposure', findings: exposureFindings },
  ]

  const allFindings = sections.flatMap((s) => s.findings)
  const score = scoreFindings(allFindings)
  const counts = {
    good: allFindings.filter((f) => f.status === 'good').length,
    warn: allFindings.filter((f) => f.status === 'warn').length,
    bad: allFindings.filter((f) => f.status === 'bad').length,
  }

  return {
    target: { entered: input, finalUrl: final.url.toString(), finalStatus: final.status },
    scannedAt: new Date().toISOString(),
    redirects: chain,
    certificate: tlsResult.certificate,
    score,
    grade: grade(score),
    counts,
    sections,
    disclaimer:
      'This is a passive configuration review of information the site returns publicly. It is not a full penetration test and does not prove a site is secure or insecure. Only scan sites you own or are authorized to test.',
  }
}
