export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: "Use POST" });

  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  // 1. IP based check
  try {
    const hostname = new URL(url).hostname;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
      return res.status(200).json({
        url,
        result: "SUSPICIOUS",
        verdict: "SUSPICIOUS",
        score: "IP-based URL detected",
        message: "IP-based URL detected - Highly risky (Phishing pattern)",
        stats: { malicious: 1, suspicious: 1, harmless: 0, undetected: 0 },
        engines: 2
      });
    }
  } catch {}

  try {
    const VT_API_KEY = process.env.VT_API_KEY;
    if (!VT_API_KEY) throw new Error("VT_API_KEY not set in Vercel");

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
    if (!analysisId) throw new Error("VirusTotal submit failed");

    // Poll 15 sec
    let stats = null;
    for (let i = 0; i < 4; i++) {
      await new Promise(r => setTimeout(r, 4000));
      const checkRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { "x-apikey": VT_API_KEY }
      });
      const checkData = await checkRes.json();
      if (checkData.data?.attributes?.status === 'completed') {
        stats = checkData.data.attributes.stats;
        break;
      }
    }

    if (!stats) {
      return res.status(200).json({
        url,
        result: "SCANNING",
        verdict: "SCANNING",
        score: "Scan queued",
        message: "Scan queued, wait 15 sec and try again",
        stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 90 },
        engines: 0
      });
    }

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    let result = "SAFE";
    if (malicious > 0) result = "UNSAFE";
    else if (suspicious > 0) result = "SUSPICIOUS";
    const verdict = result === "UNSAFE" ? "MALICIOUS" : result;

    return res.status(200).json({
      url,
      result,
      verdict,
      score: `${malicious} malicious, ${suspicious} suspicious`,
      message: result === "SAFE" ? "No engines flagged" : `${malicious} engines flagged as malicious`,
      stats,
      engines: malicious + suspicious
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Scan failed", details: err.message });
  }
}