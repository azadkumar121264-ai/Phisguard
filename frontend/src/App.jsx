import { useState } from 'react'
import axios from 'axios'

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const checkUrl = async () => {
    if (!url) return

    setLoading(true)
    setResult(null)

    try {
      const res = await axios.post('http://localhost:5000/scan', { url })
      setResult(res.data)
    } catch (error) {
      const serverMessage = error?.response?.data
      const message =
        serverMessage?.score ||
        serverMessage?.message ||
        'Backend unavailable. Please start the backend server.'

      setResult({
        verdict: 'ERROR',
        score: message,
        url
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: '600px', margin: '60px auto', textAlign: 'center', fontFamily: 'Arial, sans-serif' }}>
      <h1>🛡️ PhishGuard</h1>
      <p>Check if link is safe with 90+ engines</p>
      <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', marginTop: '20px' }}>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          style={{ width: '70%', padding: '12px', borderRadius: '8px', border: '1px solid #ccc' }}
        />
        <button
          onClick={checkUrl}
          style={{ padding: '12px 20px', borderRadius: '8px', background: 'black', color: 'white', cursor: 'pointer', border: 'none' }}
        >
          Scan
        </button>
      </div>

      {loading && <p style={{ marginTop: '20px' }}>Scanning...</p>}

      {result && (
        <div
          style={{
            marginTop: '25px',
            padding: '20px',
            background: result.verdict === 'SAFE' ? '#d4edda' : '#f8d7da',
            borderRadius: '12px',
            border: `1px solid ${result.verdict === 'SAFE' ? '#a3d9a5' : '#f5c6cb'}`
          }}
        >
          <h2 style={{ margin: '0 0 10px 0' }}>{result.verdict}</h2>
          <p style={{ margin: '0' }}>{result.score}</p>
          <small style={{ wordBreak: 'break-all' }}>{result.url}</small>
        </div>
      )}
    </div>
  )
}

export default App
