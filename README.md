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
2. Backend calls `virustotal.com/api/v3/urls` with private `VT_API_KEY`
3. VirusTotal scans with **90+ engines** - Google Safe Browsing, Kaspersky, McAfee, BitDefender
4. Secure result is returned

`API Key is stored as Secret in Vercel - Never exposed to frontend.`

### ⏱️ Why Does It Take 15 Seconds?
1. **Real-Time Scan:** Fresh scan, not cached data.
2. **90+ Engines Check:** All engines crawl domain reputation, SSL, redirection.
3. **Polling:** Backend waits till `status: completed` for 100% accuracy.

This delay = Accuracy & Security.

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
