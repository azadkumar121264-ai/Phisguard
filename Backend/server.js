require('dotenv').config();

const express = require('express');
const cors = require('cors');

// Shared with the Vercel function (api/scan.js) so both entry points answer identically.
const { analyzeUrl, buildVerdict, scanWithVirusTotal } = require('../lib/urlAnalysis');

const app = express();

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.send('PhishGuard Backend is Running');
});

app.post('/scan', async (req, res) => {
  const rawUrl = typeof req.body?.url === 'string' ? req.body.url : '';
  const heuristics = analyzeUrl(rawUrl);

  if (heuristics.error) {
    return res.status(400).json({ verdict: 'ERROR', score: 'Invalid URL', url: rawUrl });
  }

  // A raw IP address is a phishing signal on its own - no API call needed.
  if (heuristics.isIp) {
    return res.json(buildVerdict({ heuristics, stats: null, status: 'skipped' }));
  }

  const apiKey = process.env.VT_API_KEY;
  if (!apiKey || apiKey === 'your_virustotal_key_here') {
    return res.status(401).json({ verdict: 'ERROR', score: 'API key missing or invalid', url: heuristics.url });
  }

  try {
    const vt = await scanWithVirusTotal({ url: heuristics.url, apiKey });

    // When VirusTotal cannot answer, report what the local heuristics found
    // instead of a bare error: an unverified URL must never look "safe".
    if (vt.error) {
      return res.json(buildVerdict({
        heuristics,
        stats: null,
        status: 'unavailable',
        warning: vt.error.message,
      }));
    }

    return res.json(buildVerdict({ heuristics, stats: vt.stats, status: vt.status }));
  } catch (err) {
    console.error('Scan error:', err.message);
    return res.json(buildVerdict({
      heuristics,
      stats: null,
      status: 'unavailable',
      warning: 'VirusTotal could not be reached.',
    }));
  }
});

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;
