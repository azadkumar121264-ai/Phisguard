import { useState } from "react"
import axios from "axios"

function App() {
  const [url, setUrl] = useState("")
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const checkUrl = async () => {
    if (!url) return
    setLoading(true)
    setResult(null)

    try {
      const res = await axios.post(`${import.meta.env.VITE_API_URL}/scan`, { url })
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
      <h2>🛡️ PhishGuard</h2>
      <p>Check if Link is safe with 90+ engines</p>
      <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', marginTop: '20px' }}>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          style={{ width: '70%', padding: '12px', borderRadius: '8px', border: '1px solid #ccc' }}
        />
        <button onClick={checkUrl} disabled={loading} style={{ padding: '12px 20px', borderRadius: '8px', background: 'black', color: 'white', cursor: 'pointer' }}>
          {loading ? 'Scanning...' : 'Scan'}
        </button>
      </div>

      {result && (
        <div style={{ marginTop: '20px', padding: '20px', borderRadius: '8px', background: result.verdict === 'SAFE' ? '#d4edda' : result.verdict === 'MALICIOUS' ? '#f8d7da' : '#fff3cd' }}>
          <h3>{result.verdict}</h3>
          <p>{result.score}</p>
          <small>{result.url}</small>
        </div>
      )}
    </div>
  )
}

export default App