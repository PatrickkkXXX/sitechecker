// Checks HTTPS: whether HTTP redirects to HTTPS, and the certificate's validity
// and expiry. Uses the certificate the server already presented during the fetch.

export function checkTls({ start, final, chain }) {
  const findings = []
  const add = (id, title, status, detail, fix) => findings.push({ id, title, status, detail, fix })

  const finalHttps = final.url.protocol === 'https:'

  // HTTPS used at all
  if (!finalHttps) {
    add('https', 'HTTPS', 'bad', 'The site served the page over plain HTTP. Traffic can be read or changed in transit.', 'Serve the whole site over HTTPS and redirect HTTP to HTTPS.')
    return { findings, certificate: null }
  }

  // HTTP → HTTPS redirect (only meaningful if the user started on http, or we can note it)
  const startedHttp = start.protocol === 'http:'
  if (startedHttp) {
    const endedHttps = chain.at(-1)?.protocol === 'https:'
    add('redirect', 'Redirect to HTTPS', endedHttps ? 'good' : 'bad',
      endedHttps ? 'An http:// address was redirected to HTTPS.' : 'An http:// address was NOT redirected to HTTPS.',
      endedHttps ? null : 'Add a 301 redirect from http:// to https:// for every page.')
  }

  const tls = final.tls
  if (!tls || !tls.cert || !tls.cert.valid_to) {
    add('cert', 'Certificate', 'warn', 'HTTPS is in use but the certificate details could not be read.', null)
    return { findings, certificate: null }
  }

  const cert = tls.cert
  // Trusted chain
  if (tls.authorized === false) {
    add('trust', 'Certificate trust', 'bad', `The certificate is not trusted (${tls.authorizationError || 'unknown reason'}). Visitors will see security warnings.`, 'Install a certificate from a trusted authority (Let’s Encrypt is free), with the full chain.')
  } else {
    add('trust', 'Certificate trust', 'good', 'The certificate chain is trusted.', null)
  }

  // Expiry
  const now = Date.now()
  const validTo = new Date(cert.valid_to).getTime()
  const daysLeft = Math.round((validTo - now) / 86_400_000)
  if (daysLeft < 0) {
    add('expiry', 'Certificate expiry', 'bad', `The certificate expired ${Math.abs(daysLeft)} day(s) ago.`, 'Renew the certificate now. Automate renewal so this does not recur.')
  } else if (daysLeft < 15) {
    add('expiry', 'Certificate expiry', 'bad', `The certificate expires in ${daysLeft} day(s).`, 'Renew it now and set up automatic renewal.')
  } else if (daysLeft < 30) {
    add('expiry', 'Certificate expiry', 'warn', `The certificate expires in ${daysLeft} day(s).`, 'Renew soon, and automate renewal.')
  } else {
    add('expiry', 'Certificate expiry', 'good', `Valid for ${daysLeft} more day(s).`, null)
  }

  // Protocol version
  const proto = tls.protocol || ''
  if (/TLSv1(\.[01])?$/.test(proto) || proto === 'TLSv1' || proto === 'TLSv1.1' || proto === 'SSLv3') {
    add('proto', 'TLS version', 'bad', `The connection used ${proto}, which is outdated.`, 'Disable TLS 1.0/1.1 and serve TLS 1.2 and 1.3 only.')
  } else if (proto) {
    add('proto', 'TLS version', 'good', `The connection used ${proto}.`, null)
  }

  const certificate = {
    subject: cert.subject?.CN || '(unknown)',
    issuer: cert.issuer?.O || cert.issuer?.CN || '(unknown)',
    validFrom: cert.valid_from || null,
    validTo: cert.valid_to || null,
    daysLeft,
  }
  return { findings, certificate }
}
