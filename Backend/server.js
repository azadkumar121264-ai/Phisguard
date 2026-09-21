require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

function normalizeUrl(rawUrl) {
  const url = String(rawUrl || '').trim();
  if (!url) return '';
  return /^https?:\/\//i.test(url) ? url : `https://${url}`;
}

app.post('/scan', async (req, res) => {
  const rawUrl = req.body?.url || '';
  const url = normalizeUrl(rawUrl);

  if (!url) {
    return res.status(400).json({ verdict: 'ERROR', score: 'No URL', url: '' });
  }

  const apiKey = process.env.VT_API_KEY;
  if (!apiKey || apiKey === 'your_virustotal_key_here') {
    return res.status(401).json({ verdict: 'ERROR', score: 'API key missing or invalid', url });
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

    await new Promise((resolve) => setTimeout(resolve, 4000));

    const report = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': apiKey },
      validateStatus: () => true
    });

    if (report.status !== 200) {
      throw new Error(`Report failed: ${report.status}`);
    }

    const stats = report.data?.data?.attributes?.stats || {};
    const total = Object.values(stats).reduce((sum, value) => sum + Number(value || 0), 0);
    const malicious = Number(stats.malicious || 0) + Number(stats.suspicious || 0);
    const verdict = malicious > 0 ? 'DANGEROUS' : total > 0 ? 'SAFE' : 'UNKNOWN';

    return res.json({
      verdict,
      score: `${malicious} / ${total} engines flagged`,
      url
    });
  } catch (error) {
    console.error('VT_ERROR:', error.response?.data || error.message);
    return res.status(500).json({
      verdict: 'ERROR',
      score: 'API response issue. Please check your VirusTotal key.',
      url
    });
  }
});

app.listen(PORT, () => console.log(`PhishGuard backend running on ${PORT}`));