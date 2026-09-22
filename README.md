
# 🛡️ PhishGuard - Check if Link is safe with 90+ engines

PhishGuard ek powerful phishing link detector hai jo VirusTotal ke 90+ antivirus engines se link ko scan karta hai.

[PhishGuard Preview](https://phisguard-six.vercel.app/preview.png)

### 🌐 Live Demo
**Website:** https://phisguard-six.vercel.app

### ✨ Features
- ✅ 90+ Antivirus engines se scanning (VirusTotal API)
- ✅ Real-time result - SAFE / UNSAFE
- ✅ Fast & Simple UI
- ✅ Free & Open Source

### 🚀 How it works?
1. User link daalta hai (e.g., `google.com`)
2. Backend `/api/scan` VirusTotal ko request bhejta hai
3. Result aata hai `X / 90 engines flagged`
4. Agar 2+ engines flag kare toh UNSAFE show hota hai

### 🛠️ Tech Stack
- Frontend: HTML, CSS, JavaScript
- Backend: Node.js (Vercel Serverless)
- API: VirusTotal v3 API
- Hosting: Vercel

### 📦 Installation (Local)
```bash
git clone https://github.com/azadkumar121264-ai/phisguard.git
cd phisguard
npm install
# .env file banao aur VT_API_KEY daalo
npm run dev
```

*🔑 Environment Variable*
Vercel > Settings > Environment Variables me ye add karo:
```
VT_API_KEY=your_virustotal_api_key
```

*👨‍💻 Developer*
<img src="https://github.com/azadkumar121264-ai.png" width="100" style="border-radius:50%"/>

*Azad Kumar*
- GitHub: https://github.com/azadkumar121264-ai
- Project: https://phisguard-six.vercel.app/

*📄 License*
MIT License - Free to use

---
⭐ Agar project pasand aaye toh GitHub pe star de dena!
```
```
