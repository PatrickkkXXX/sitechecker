const STATUS_LABEL = { good: 'Pass', warn: 'Warning', bad: 'Issue' }

function Finding({ f }) {
  return (
    <li className={`finding ${f.status}`}>
      <span className="pill">{STATUS_LABEL[f.status]}</span>
      <div className="finding-body">
        <div className="finding-title">{f.title}</div>
        <p className="finding-detail">{f.detail}</p>
        {f.fix && <p className="finding-fix"><strong>Fix:</strong> {f.fix}</p>}
      </div>
    </li>
  )
}

function CookieTable({ cookies }) {
  if (!cookies?.length) return null
  return (
    <div className="cookie-wrap">
      <table className="cookie-table">
        <thead>
          <tr><th>Cookie</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr>
        </thead>
        <tbody>
          {cookies.map((c) => (
            <tr key={c.name} className={c.status}>
              <td className="mono">{c.name}</td>
              <td>{c.secure ? '✓' : '✗'}</td>
              <td>{c.httpOnly ? '✓' : '✗'}</td>
              <td className="mono">{c.sameSite}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Section({ s }) {
  const order = { bad: 0, warn: 1, good: 2 }
  const findings = [...s.findings].sort((a, b) => order[a.status] - order[b.status])
  return (
    <section className="card section">
      <div className="section-head">
        <h3>{s.title}</h3>
        <div className="mini-counts">
          {['bad', 'warn', 'good'].map((st) => {
            const n = s.findings.filter((f) => f.status === st).length
            return n ? <span key={st} className={`dot ${st}`}>{n}</span> : null
          })}
        </div>
      </div>
      {s.summary && <p className="section-summary">{s.summary}</p>}
      {s.cookies && <CookieTable cookies={s.cookies} />}
      {findings.length > 0 && <ul className="findings">{findings.map((f, i) => <Finding key={`${f.id}-${i}`} f={f} />)}</ul>}
      {!findings.length && !s.cookies?.length && <p className="muted">Nothing to report here.</p>}
    </section>
  )
}

export default function Report({ report }) {
  const { grade, score, counts, target, certificate } = report
  return (
    <div className="report">
      <section className={`card grade-card grade-${grade}`}>
        <div className="grade-badge" aria-label={`Grade ${grade}`}>{grade}</div>
        <div className="grade-info">
          <div className="score">{score}<span>/100</span></div>
          <div className="counts">
            <span className="dot bad">{counts.bad}</span> issues ·{' '}
            <span className="dot warn">{counts.warn}</span> warnings ·{' '}
            <span className="dot good">{counts.good}</span> passed
          </div>
          <div className="target mono">{target.finalUrl}</div>
          {certificate && (
            <div className="cert muted">
              Certificate by {certificate.issuer} · {certificate.daysLeft} days left
            </div>
          )}
        </div>
      </section>

      {report.sections.map((s) => <Section key={s.key} s={s} />)}

      <p className="disclaimer">{report.disclaimer}</p>
    </div>
  )
}
