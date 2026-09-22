import { useState } from 'react'
import axios from 'axios'

const VERDICTS = {
  SAFE: { icon: '✅', label: 'SAFE', background: '#d4edda', border: '#a3d7b0', color: '#0f5132' },
  MALICIOUS: { icon: '⛔', label: 'MALICIOUS', background: '#f8d7da', border: '#f1aeb5', color: '#842029' },
  SUSPICIOUS: { icon: '⚠️', label: 'SUSPICIOUS', background: '#fff3cd', border: '#ffe69c', color: '#664d03' },
  UNKNOWN: { icon: '❔', label: 'UNABLE TO IDENTIFY', background: '#e7e9ec', border: '#ced4da', color: '#343a40' },
  SCANNING: { icon: '⏳', label: 'SCANNING', background: '#e7e9ec', border: '#ced4da', color: '#343a40' },
  ERROR: { icon: '⚠️', label: 'ERROR', background: '#f8d7da', border: '#f1aeb5', color: '#842029' },
}

const SEVERITY_ICON = { critical: '⛔', high: '⚠️', medium: '•', low: '•' }

function ResultCard({ result }) {
  const verdict = VERDICTS[result.verdict] || VERDICTS.ERROR
  const signals = (result.signals || []).slice(0, 5)

  return (
    <div
      style={{
        marginTop: '20px',
        padding: '20px',
        borderRadius: '8px',
        textAlign: 'left',
        background: verdict.background,
        border: `1px solid ${verdict.border}`,
        color: verdict.color,
      }}
    >
      <h3 style={{ margin: '0 0 6px', color: verdict.color }}>{verdict.icon} {verdict.label}</h3>
      <p style={{ fontWeight: 600 }}>{result.score}</p>
      {result.message && <p style={{ marginTop: '8px' }}>{result.message}</p>}
      {signals.length > 0 && (
        <ul style={{ margin: '10px 0 0', paddingLeft: '20px' }}>
          {signals.map((signal, index) => (
            <li key={`${signal.id}-${index}`}>{SEVERITY_ICON[signal.severity] || '•'} {signal.message}</li>
          ))}
        </ul>
      )}
      {result.warning && <p style={{ marginTop: '10px', fontStyle: 'italic' }}>Engine notice: {result.warning}</p>}
      {result.url && <small style={{ display: 'block', marginTop: '10px', wordBreak: 'break-all' }}>{result.url}</small>}
    </div>
  )
}

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const checkUrl = async () => {
    if (!url) return
    setLoading(true)
    setResult(null)

    try {
      // Candidate scan endpoints, in order of preference.
      const configured = (import.meta.env.VITE_API_URL || '').trim().replace(/\/+$/, '')
      const hosted = !['localhost', '127.0.0.1'].includes(window.location.hostname)
      const configuredIsLocal = /^https?:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/i.test(configured)

      const endpoints = []
      // The configured backend: the local Express server answers on /scan, a
      // Vercel function on /api/scan. A localhost URL is skipped when this page
      // is served from a real host, so a stale dev value cannot break production.
      if (configured && !(configuredIsLocal && hosted)) {
        endpoints.push(`${configured}/scan`)
        if (!configured.endsWith('/api')) endpoints.push(`${configured}/api/scan`)
      }
      // Same-origin fallback: on Vercel the static app and the scan function
      // share a domain, so no environment variable is needed there.
      endpoints.push(`${window.location.origin}/api/scan`, `${window.location.origin}/scan`)

      let lastError = null
      for (const endpoint of new Set(endpoints)) {
        try {
          const res = await axios.post(endpoint, { url })
          setResult(res.data)
          return
        } catch (error) {
          lastError = error
          // 404 = wrong route, no response = wrong host: try the next candidate.
          if (error?.response && error.response.status !== 404) break
        }
      }
      throw lastError || new Error('Backend unavailable. Please start the backend server.')
    } catch (error) {
      const serverMessage = error?.response?.data
      setResult({
        verdict: 'ERROR',
        score:
          serverMessage?.score ||
          serverMessage?.message ||
          serverMessage?.error ||
          error?.message ||
          'Backend unavailable. Please start the backend server.',
        url,
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: '600px', margin: '60px auto', textAlign: 'center', fontFamily: 'Arial, sans-serif' }}>
      <h2>🛡️ PhishGuard</h2>
      <p>Checks 90+ antivirus engines plus phishing patterns</p>
      <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', marginTop: '20px' }}>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') checkUrl()
          }}
          placeholder="https://example.com"
          style={{ width: '70%', padding: '12px', borderRadius: '8px', border: '1px solid #ccc' }}
        />
        <button onClick={checkUrl} disabled={loading} style={{ padding: '12px 20px', borderRadius: '8px', background: 'black', color: 'white', cursor: 'pointer' }}>
          {loading ? 'Scanning...' : 'Scan'}
        </button>
      </div>

      {result && <ResultCard result={result} />}

      {result && (result.verdict === 'UNKNOWN' || result.verdict === 'SCANNING') && (
        <p style={{ marginTop: '12px' }}>VirusTotal needs a moment for brand-new URLs - press Scan again in a minute.</p>
      )}
    </div>
  )
}

export default App
