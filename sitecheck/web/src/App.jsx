import { useState } from 'react'
import Report from './components/Report'
import { scanSite } from './lib/api'

export default function App() {
  const [target, setTarget] = useState('')
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [agreed, setAgreed] = useState(false)

  async function run(e) {
    e.preventDefault()
    setError('')
    if (!agreed) { setError('Please confirm you are authorized to check this site.'); return }
    setBusy(true)
    setReport(null)
    try {
      setReport(await scanSite(target))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="wrap">
      <header className="masthead">
        <div className="logo" aria-hidden="true">
          <svg viewBox="0 0 32 32" width="40" height="40"><path d="M16 4l9 3.2v6.8c0 5.7-3.8 10.6-9 12-5.2-1.4-9-6.3-9-12V7.2z" fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinejoin="round" /><path d="M12 15.5l2.8 2.8 5-5.6" fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
        </div>
        <div>
          <h1>SiteCheck</h1>
          <p className="tagline">A quick security health check for a website's public configuration.</p>
        </div>
      </header>

      <section className="card search-card">
        <form onSubmit={run}>
          <label htmlFor="target" className="field-label">Website address</label>
          <div className="search-row">
            <input
              id="target"
              className="text"
              type="text"
              inputMode="url"
              placeholder="example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              autoComplete="off"
              autoCapitalize="off"
              spellCheck="false"
            />
            <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Checking…' : 'Check site'}</button>
          </div>
          <label className="consent" htmlFor="agree">
            <input id="agree" type="checkbox" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />
            <span>I own this website or I'm authorized to test it.</span>
          </label>
          {error && <p className="error" role="alert">{error}</p>}
        </form>
      </section>

      {!report && !busy && (
        <section className="card intro">
          <h2>What this checks</h2>
          <ul className="intro-list">
            <li><strong>HTTPS &amp; certificate</strong> — is the site encrypted, is the certificate trusted, when does it expire</li>
            <li><strong>Security headers</strong> — HSTS, Content-Security-Policy, clickjacking and MIME-sniffing protection, and more</li>
            <li><strong>Cookies</strong> — whether cookies use Secure, HttpOnly and SameSite</li>
            <li><strong>Information exposure</strong> — software and version banners that help attackers</li>
          </ul>
          <p className="muted">
            This is a <strong>passive</strong> review: it makes one ordinary request, like a browser visiting the page, and reads what comes back. It does not attack the site or try to break in. It is a hygiene check, not a full penetration test.
          </p>
        </section>
      )}

      {busy && <section className="card"><p className="muted">Checking the site…</p></section>}
      {report && <Report report={report} />}

      <footer className="foot muted">SiteCheck · passive configuration review · use only on sites you are authorized to test.</footer>
    </div>
  )
}
