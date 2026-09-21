const express = require('express');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

function normalizeUrl(input) {
  if (!input) return null;
  let url = input.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  try {
    new URL(url);
    return url;
  } catch {
    return null;
  }
}

app.get('/', (req, res) => {
  res.send('PhishGuard Backend is Running');
});

app.post('/scan', async (req, res) => {
  const rawUrl = req.body.url;
  const url = normalizeUrl(rawUrl);

  if (!url) {
    return res.status(400).json({ verdict: 'ERROR', score: 'Invalid URL' });
  }

  const apiKey = process.env.VT_API_KEY;
  if (!apiKey || apiKey === 'your_virustotal_key_here') {
    return res.status(401).json({ verdict: 'ERROR', score: 'API key missing or invalid' });
  }

  try {
    const submitPayload = new URLSearchParams({ url }).toString();

    const submit = await axios.post('https://www.virustotal.com/api/v3/urls', submitPayload, {
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      validateStatus: () => true
    });

    if (submit.status !== 200 && submit.status !== 202) {
      throw new Error(`Submit failed: ${submit.status}`);
    }

    const analysisId = submit.data?.data?.id;
    if (!analysisId) {
      throw new Error('No analysis ID returned');
    }

    // VirusTotal ko time do scan karne ka (15 sec)
    await new Promise((resolve) => setTimeout(resolve, 15000));

    const report = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': apiKey },
      validateStatus: () => true
    });

    const stats = report.data?.data?.attributes?.stats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const total = malicious + suspicious + harmless + undetected;

    let verdict = 'SAFE';
    if (malicious >= 5) {
      verdict = 'DANGEROUS';
    } else if (malicious >= 1 || suspicious >= 2) {
      verdict = 'SUSPICIOUS';
    } else {
      verdict = 'SAFE';
    }

    return res.json({
      verdict,
      score: `${malicious} / ${total} engines flagged`,
      details: stats,
      url
    });

  } catch (err) {
    console.error(err.message);
    return res.status(500).json({ verdict: 'ERROR', score: 'Scan failed, try again' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
