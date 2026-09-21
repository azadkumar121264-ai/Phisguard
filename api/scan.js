export default async function handler(req, res) {
  const apiKey = process.env.VT_API_KEY;

  if (!apiKey) {
    return res.status(500).json({ error: "API key missing on server" });
  }

  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  const vtRes = await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: {
      "x-apikey": apiKey,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: `url=${encodeURIComponent(url)}`
  });

  const data = await vtRes.json();
  res.status(200).json(data);
}