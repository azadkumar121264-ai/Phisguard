import urlAnalysis from '../lib/urlAnalysis.js';

const { analyzeUrl, buildVerdict, scanWithVirusTotal } = urlAnalysis;

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Use POST method' });

  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      body = {};
    }
  }

  const rawUrl = typeof body?.url === 'string' ? body.url.trim() : '';
  if (!rawUrl) return res.status(400).json({ verdict: 'ERROR', score: 'URL is required' });

  const heuristics = analyzeUrl(rawUrl);
  if (heuristics.error) {
    return res.status(400).json({ verdict: 'ERROR', score: 'Invalid URL', url: rawUrl });
  }

  if (heuristics.isIp) {
    return res.status(200).json(buildVerdict({ heuristics, stats: null, status: 'skipped' }));
  }

  const apiKey = process.env.VT_API_KEY;
  if (!apiKey) {
    return res.status(500).json({
      verdict: 'ERROR',
      score: 'Server API key is not configured',
      url: heuristics.url,
    });
  }

  try {
    const scan = await scanWithVirusTotal({ url: heuristics.url, apiKey });
    if (scan.error) {
      return res.status(200).json(buildVerdict({
        heuristics,
        stats: null,
        status: 'unavailable',
        warning: scan.error.message,
      }));
    }

    return res.status(200).json(buildVerdict({
      heuristics,
      stats: scan.stats,
      status: scan.status,
    }));
  } catch (error) {
    console.error('Scan error:', error);
    return res.status(200).json(buildVerdict({
      heuristics,
      stats: null,
      status: 'unavailable',
      warning: 'VirusTotal could not be reached.',
    }));
  }
}
