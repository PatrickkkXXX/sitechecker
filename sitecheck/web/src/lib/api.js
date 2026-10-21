const BASE = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '')

export async function scanSite(target) {
  let res
  try {
    res = await fetch(`${BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
    })
  } catch {
    throw new Error("Can't reach the checker service. Make sure the server is running.")
  }
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.error || 'The check could not be completed.')
  return data
}
