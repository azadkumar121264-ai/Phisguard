export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: "Use POST method" });

  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL is required" });

  // === 1. IP-BASED PHISHING CHECK ===
  try {
    const parsedUrl = new URL(url.startsWith('http') ? url : `http://${url}`);
    const hostname = parsedUrl.hostname;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
      return res.status(200).json({
        url,
        result: "UNSAFE",
        verdict: "MALICIOUS",
        score: "Direct IP address detected",
        message: "IP-based URL detected - Very common in phishing",
        stats: { malicious: 0, suspicious: 1, harmless: 0, undetected: 0 },
        engines: 1,
        details: { reason: "Direct IP login" }
      });
    }
  } catch (e) {
    // Invalid URL ignore
  }

  // === 2. VirusTotal Scan ===
  try {
    const VT_API_KEY = process.env.VT_API_KEY;
    if (!VT_API_KEY) {
      return res.status(500).json({ error: "Server API Key missing in Vercel" });
    }

    // Submit URL
    const formData = new URLSearchParams();
    formData.append('url', url);

    const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: { "x-apikey": VT_API_KEY },
      body: formData
    });

    const submitData = await submitRes.json();
    const analysisId = submitData.data?.id;

    if (!analysisId) {
      return res.status(500).json({ error: "VirusTotal failed", raw: submitData });
    }

    // Poll for result - 16 sec wait
    let finalStats = null;
    for (let i = 0; i < 4; i++) {
      await new Promise(r => setTimeout(r, 4000));
      const analysisRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { "x-apikey": VT_API_KEY }
      });
      const analysisData = await analysisRes.json();
      if (analysisData.data?.attributes?.status === 'completed') {
        finalStats = analysisData.data.attributes.stats;
        break;
      }
    }

    if (!finalStats) {
      return res.status(200).json({
        url,
        result: "SCANNING",
        verdict: "SCANNING",
        score: "Scan queued",
        message: "Scan is queued. Wait 15 sec and scan again.",
        stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 90 },
        engines: 0
      });
    }

    const malicious = finalStats.malicious || 0;
    const suspicious = finalStats.suspicious || 0;
    const harmless = finalStats.harmless || 0;

    let result = "SAFE";
    if (malicious > 0) result = "UNSAFE";
    else if (suspicious > 0) result = "SUSPICIOUS";
    else if (harmless === 0 && malicious === 0 && suspicious === 0) {
      result = "SCANNING";
    }
    const verdict = result === "UNSAFE" ? "MALICIOUS" : result;

    return res.status(200).json({
      url,
      result,
      verdict,
      score: `${malicious} malicious, ${suspicious} suspicious, ${harmless} harmless`,
      message: result === "SAFE" ? `Safe - ${harmless} engines say clean` : `${malicious} engines flagged as malicious`,
      stats: finalStats,
      engines: malicious + suspicious
    });

  } catch (err) {
    console.error("Scan Error:", err);
    return res.status(500).json({ error: "Scan failed", details: err.message });
  }
}