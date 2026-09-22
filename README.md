# 🛡️ PhishGuard - Advanced Phishing Link Detector

![PhishGuard Banner](https://img.shields.io/badge/Cybersecurity-Phishing%20Detector-red?style=for-the-badge&logo=shield)
![Live](https://img.shields.io/badge/Live-Demo-green?style=for-the-badge)
![VirusTotal](https://img.shields.io/badge/Powered%20By-VirusTotal%20API-blue?style=for-the-badge)

> **Check if any Link is safe with 90+ antivirus engines in real-time.**

**Live Demo:** [https://phisguard-six.vercel.app](https://phisguard-six.vercel.app)

---
### 🚀 Why This Project?
Phishing attacks increased by 65% in 2024-25. Users can't identify fake links like `goggle.com`. PhishGuard solves this by using enterprise-grade security.

**Uses:** Students, Banks / CA Firms to verify client links, Organizations to prevent data breaches.

### ⚙️ How It Works (Live VirusTotal API)
I have integrated the **Official Live VirusTotal API v3**.

1. User submits URL -> Frontend calls my secure backend
2. **Phishing heuristics** (offline, instant) look for typosquatting and homoglyphs
   (`g00gle`, `paypa1`), punycode look-alikes, raw IP hosts, credential keywords,
   abused TLDs, `@`-tricks, executable downloads and more
3. The backend looks the URL up in VirusTotal (`/api/v3/urls`) with the private `VT_API_KEY`
4. Both layers are merged into one honest verdict: `SAFE`, `SUSPICIOUS`, `MALICIOUS`
   or `UNKNOWN`

`API Key is stored as Secret in Vercel - Never exposed to frontend.`

### 🧠 Why "Unable To Identify" Instead Of "Safe"?
VirusTotal is **reputation based**: a freshly registered phishing domain has no
reputation yet, so every engine reports `undetected` and the URL looks clean.
"No engine flagged it" is therefore *not* proof that a link is safe. PhishGuard
never labels such a URL `SAFE` - it reports `UNABLE TO IDENTIFY` and shows the
phishing patterns it found, so a brand-new clone like `goggle.com` is still caught
by the heuristics layer.

### ⏱️ Why Does It Still Take A Few Seconds?
1. **Real-Time Scan:** A cached VirusTotal report is reused when one already exists.
2. **90+ Engines Check:** All engines check domain reputation, SSL and redirection.
3. **Polling:** The backend polls the analysis a couple of times - staying inside the
   free 4 requests/minute quota - and picks the finished analysis up on your next click.

Accuracy & Security, without false "safe" answers.

### 💻 Tech Stack
- **Languages Used:** JavaScript, CSS, HTML
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Backend:** Node.js + Express.js
- **Security API:** VirusTotal Public API v3 (Live)
- **Deployment:** Vercel

### 👨‍💻 Lead Developer
**Azad Kumar**
*B.tech Student | Aspiring Cybersecurity Analyst*

This project was conceptualized, developed, and deployed entirely by me.

| Connect With Me |
| :---: |
| <img src="https://github.com/azadkumar121264-ai.png" width="150" style="border-radius:50%"> |
| **Azad Kumar** |
| [GitHub](https://github.com/azadkumar121264-ai) |

### 📜 Use Case for CA
1.  **Fraud Prevention:** Verifying invoice links in client emails.
2.  **Client Data Security:** Avoid phishing clones of accounting portals.
3.  **Audit & Compliance:** Practical implementation of Cyber Security in Finance.

---
**⭐ Give a star if you found this helpful!**
