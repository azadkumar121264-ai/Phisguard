'use strict';

/**
 * PhishGuard URL analysis engine (zero dependencies).
 *
 * VirusTotal is *reputation* based: a freshly registered phishing domain has no
 * reputation, so every engine reports "undetected" and the URL looks clean.
 * This module adds the missing layer:
 *
 *   analyzeUrl(url)            -> local heuristics (typosquatting, punycode, IP
 *                                 hosts, suspicious TLDs, credential keywords, ...)
 *   buildVerdict({ ... })      -> one honest verdict: SAFE | SUSPICIOUS | MALICIOUS
 *                                 | UNKNOWN  ("unable to identify" is never SAFE)
 *   scanWithVirusTotal({...})  -> VirusTotal v3 client that stays inside the free
 *                                 quota (1 report + 1 submit + 2 polls = 4 requests)
 *
 * Used by both entry points so local (Backend/server.js) and serverless
 * (api/scan.js) answers are identical. CommonJS on purpose: the Express backend
 * requires it and the ESM Vercel function imports it.
 */

const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'click', 'link', 'work', 'loan',
  'review', 'country', 'stream', 'download', 'racing', 'party', 'gdn', 'zip',
  'mov', 'rest', 'buzz', 'monster', 'quest', 'cyou', 'sbs', 'lat', 'icu',
  'cam', 'surf', 'bar', 'wiki', 'kim', 'men', 'date', 'faith', 'bid', 'trade',
  'webcam', 'win', 'cricket', 'accountant', 'science', 'lol', 'site', 'online',
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
  'rebrand.ly', 'cutt.ly', 'shorte.st', 'adf.ly', 'bl.ink', 'rb.gy', 's.id',
  'shorturl.at', 'tiny.cc', 'bit.do', 'mcaf.ee', 'lnkd.in', 't.ly', 'v.gd',
  'clck.ru', 'u.to', 'soo.gd', 'qps.ru', '3.ly',
]);

/** words phishers put in front of a login form */
const CREDENTIAL_KEYWORDS = [
  'login', 'signin', 'sign-in', 'logon', 'verify', 'verification', 'validate',
  'account', 'update', 'confirm', 'secure', 'security', 'password', 'passwd',
  'credential', 'bank', 'banking', 'netbanking', 'wallet', 'payment', 'billing',
  'invoice', 'otp', 'kyc', 'aadhaar', 'aadhar', 'refund', 'unlock', 'recover',
  'support', 'helpdesk', 'transfer', 'upi', 'debit', 'credit', 'tax', 'efiling',
  'pension', 'claim', 'customer', 'service', 'webscr', 'authorize',
];

/** bait words used by scam / giveaway pages */
const SCAM_KEYWORDS = [
  'free', 'gift', 'prize', 'lottery', 'winner', 'jackpot', 'giveaway',
  'crypto', 'airdrop', 'investment', 'urgent', 'limited', 'bonus', 'reward',
  'casino', 'betting',
];

/** executable / archive payloads */
const RISKY_EXTENSION = /\.(exe|apk|scr|bat|cmd|msi|jar|vbs|ps1|hta|iso|img|dmg|zip|rar|7z|pif|lnk)(\?|#|$)/i;


/** brands phishers impersonate */
const BRAND_NAMES = [
  'google', 'gmail', 'youtube', 'android', 'facebook', 'instagram', 'whatsapp',
  'apple', 'icloud', 'microsoft', 'outlook', 'amazon', 'netflix', 'paypal',
  'linkedin', 'twitter', 'telegram', 'binance', 'coinbase', 'metamask',
  'adobe', 'dropbox', 'github', 'dhl', 'fedex', 'usps', 'onlinesbi', 'sbi',
  'hdfcbank', 'icicibank', 'axisbank', 'kotak', 'paytm', 'phonepe', 'irctc',
  'incometax', 'gst', 'uidai', 'epfo', 'zerodha', 'groww', 'upstox',
  'flipkart', 'myntra', 'swiggy', 'zomato', 'jio', 'airtel', 'hotstar',
];

/** domains that really belong to those brands (no impersonation checks here) */
const OFFICIAL_DOMAINS = new Set([
  'google.com', 'google.co.in', 'google.co.uk', 'gmail.com', 'youtube.com',
  'youtu.be', 'googleapis.com', 'googleusercontent.com', 'gstatic.com',
  'ytimg.com', 'withgoogle.com', 'android.com', 'facebook.com', 'fb.com',
  'fbcdn.net', 'instagram.com', 'whatsapp.com', 'whatsapp.net', 'apple.com',
  'icloud.com', 'microsoft.com', 'microsoftonline.com', 'live.com',
  'outlook.com', 'office.com', 'office365.com', 'sharepoint.com',
  'amazon.com', 'amazon.in', 'amazonaws.com', 'cloudfront.net', 'netflix.com',
  'paypal.com', 'linkedin.com', 'twitter.com', 'x.com', 't.co',
  'telegram.org', 'telegram.me', 'binance.com', 'coinbase.com',
  'metamask.io', 'adobe.com', 'dropbox.com', 'github.com',
  'githubusercontent.com', 'dhl.com', 'fedex.com', 'usps.com', 'sbi.co.in',
  'onlinesbi.sbi', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
  'kotak.com', 'paytm.com', 'phonepe.com', 'irctc.co.in', 'incometax.gov.in',
  'gst.gov.in', 'uidai.gov.in', 'epfindia.gov.in', 'npci.org.in',
  'zerodha.com', 'groww.in', 'upstox.com', 'flipkart.com', 'myntra.com',
  'swiggy.com', 'zomato.com', 'jio.com', 'airtel.in', 'hotstar.com',
]);

const PRIVATE_HOST = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0)/;
const IPV4_HOST = /^\d{1,3}(\.\d{1,3}){3}$/;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** normalise user input into a URL object, or null when it cannot be scanned */
function parseUrl(input) {
  if (typeof input !== 'string') return null;
  let value = input.trim();
  if (!value) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = `https://${value}`;
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  return parsed;
}

function levenshtein(a, b) {
  const dist = [];
  for (let i = 0; i <= a.length; i += 1) {
    dist.push([i]);
    for (let j = 1; j <= b.length; j += 1) dist[i].push(i === 0 ? j : 0);
  }
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dist[i][j] = Math.min(dist[i - 1][j] + 1, dist[i][j - 1] + 1, dist[i - 1][j - 1] + cost);
    }
  }
  return dist[a.length][b.length];
}

/** fold the digit/symbol look-alikes phishers use: g00gle, paypa1, rnicrosoft */
function foldHomoglyphs(value) {
  return value
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/8/g, 'b')
    .replace(/9/g, 'g')
    .replace(/\$/g, 's')
    .replace(/vv/g, 'w')
    .replace(/rn/g, 'm');
}

function severityOf(weight) {
  if (weight >= 40) return 'critical';
  if (weight >= 25) return 'high';
  if (weight >= 10) return 'medium';
  return 'low';
}

/**
 * Local, offline heuristics - never throws. An unusable URL comes back with `error`.
 * @returns {{ error: string|null, url: string, hostname: string, risk: number, critical: boolean, isIp: boolean, signals: Array }}
 */
function analyzeUrl(input) {
  const parsed = parseUrl(input);
  if (!parsed) {
    return { error: 'Invalid URL', url: null, hostname: '', risk: 0, critical: false, isIp: false, signals: [] };
  }

  const url = parsed.href;
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  const labels = hostname.split('.');
  const tld = labels.length > 1 ? labels[labels.length - 1] : '';
  const domain = labels.length > 1 ? labels.slice(-2).join('.') : hostname;
  const domainName = labels.length > 1 ? labels[labels.length - 2] : hostname;
  const target = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const foldedHost = foldHomoglyphs(hostname);
  const tokens = foldedHost.split(/[^a-z0-9]+/).filter(Boolean);
  const isIp = IPV4_HOST.test(hostname) || hostname.includes(':');
  const privateHost = PRIVATE_HOST.test(hostname);
  const isOfficial = OFFICIAL_DOMAINS.has(domain);

  const signals = [];
  const add = (id, weight, message) => {
    signals.push({ id, weight, severity: severityOf(weight), message });
  };

  if (isIp) {
    add('ip-host', 45, 'Raw IP address instead of a domain name - a classic phishing trick');
  }
  if (hostname.endsWith('.onion')) {
    add('onion-host', 40, 'Hidden service (.onion) address - cannot be attributed to anyone');
  }
  if (hostname.includes('xn--') || /[^\x00-\x7f]/.test(hostname)) {
    add('punycode', 40, 'Punycode / international characters - often used to imitate a real domain');
  }
  if (parsed.username || parsed.password) {
    add('userinfo-trick', 40, `Text before "@" hides the real destination (${parsed.username || '...'}@${hostname})`);
  }
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    add('odd-port', 20, `Non-standard port :${parsed.port}`);
  }

  if (!isOfficial && !isIp && !privateHost) {
    const exact = BRAND_NAMES.find((name) => tokens.includes(name));
    const typo = !exact && BRAND_NAMES.find((name) => name.length >= 5
      && !tokens.includes(name)
      && tokens.some((token) => token.length >= 5 && levenshtein(token, name) === 1));
    const embedded = !exact && !typo && BRAND_NAMES.find((name) => name.length >= 5
      && !tokens.includes(name) && foldedHost.replace(/[^a-z0-9]/g, '').includes(name));
    if (exact) {
      add('brand-token', 45, `Impersonates "${exact}": the brand name sits in a domain that is not its official site`);
    } else if (typo) {
      add('brand-typo', 45, `Look-alike domain of "${typo}" (misspelled or homoglyph brand name)`);
    } else if (embedded) {
      add('brand-embedded', 20, `Brand name "${embedded}" bundled into an unrelated domain`);
    }
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    add('suspicious-tld', 18, `".${tld}" is a top level domain with a very high abuse rate`);
  }
  if (URL_SHORTENERS.has(domain) || URL_SHORTENERS.has(hostname)) {
    add('shortener', 15, `URL shortener (${domain}) hides the final destination`);
  }

  const hostWords = CREDENTIAL_KEYWORDS.filter((word) => hostname.includes(word));
  if (hostWords.length) {
    add('credential-host', Math.min(30, 12 + hostWords.length * 6), `Credential words in the domain: ${hostWords.slice(0, 3).join(', ')}`);
  }
  const pathWords = CREDENTIAL_KEYWORDS.filter((word) => target.includes(word));
  if (pathWords.length) {
    add('credential-path', Math.min(20, 8 + pathWords.length * 4), `Asks for a sensitive action: ${pathWords.slice(0, 3).join(', ')}`);
  }
  const bait = SCAM_KEYWORDS.filter((word) => hostname.includes(word) || target.includes(word));
  if (bait.length) {
    add('scam-words', Math.min(20, 8 + bait.length * 4), `Scam bait words: ${bait.slice(0, 3).join(', ')}`);
  }

  if (parsed.protocol === 'http:') {
    const weight = hostWords.length || pathWords.length ? 25 : 8;
    add('no-https', weight, 'Unencrypted http:// - anything typed here travels in clear text');
  }

  // Host *structure* signals only make sense for real domain names.
  if (!isIp) {
    if (labels.length >= 6) {
      add('deep-subdomain', 25, `${labels.length} sub-domain levels hide the real domain`);
    } else if (labels.length >= 4) {
      add('deep-subdomain', 15, `${labels.length} sub-domain levels`);
    }
    if (hostname.length > 40) add('long-host', 10, 'Unusually long hostname');
    if ((hostname.match(/-/g) || []).length >= 3) add('many-hyphens', 12, 'Hostname stuffed with hyphens');
    if (/\d/.test(domainName)) add('digits-in-domain', 8, 'Digits inside the domain name itself');
  }

  if (RISKY_EXTENSION.test(parsed.pathname)) {
    add('risky-download', 25, 'Links directly to an executable or archive file');
  }
  const encoded = (url.match(/%[0-9a-f]{2}/gi) || []).length;
  if (encoded >= 6 || /%2f|%40|%3a|%5c/i.test(url)) {
    add('obfuscated', 12, 'Heavily percent-encoded URL - hides the real target');
  }
  if (url.length > 120) add('long-url', 10, 'Very long URL');
  if (parsed.search.length > 80) add('long-query', 8, 'Very long query string');
  if (/\\|%5c/i.test(parsed.pathname)) add('backslashes', 10, 'Backslashes in the path');
  if (/\/\/+/.test(parsed.pathname)) add('double-slash', 8, 'Duplicate slashes in the path');

  const risk = Math.min(100, signals.reduce((total, signal) => total + signal.weight, 0));
  return {
    error: null,
    url,
    hostname,
    domain,
    tld,
    protocol: parsed.protocol,
    isIp,
    privateHost,
    isOfficial,
    risk,
    critical: signals.some((signal) => signal.weight >= 40),
    signals,
  };
}

/**
 * Combine heuristics with VirusTotal statistics into one honest verdict.
 *
 * The key rule: when no engine has an opinion about a URL the answer is UNKNOWN,
 * never SAFE. A brand new phishing domain simply has no reputation yet, so
 * "nobody flagged it" must not be reported as "it is safe".
 */
function buildVerdict({ heuristics, stats, status = 'unavailable', warning = null }) {
  const malicious = stats?.malicious || 0;
  const suspicious = stats?.suspicious || 0;
  const harmless = stats?.harmless || 0;
  const undetected = stats?.undetected || 0;
  const engines = malicious + suspicious + harmless + undetected;
  const reasons = (heuristics?.signals || []).map((signal) => signal.message);
  const risk = heuristics?.risk || 0;
  const strong = risk >= 60 || (Boolean(heuristics?.critical) && risk >= 40);
  const medium = risk >= 30;
  const inProgress = ['queued', 'in_progress', 'scanning'].includes(status);
  const base = {
    url: heuristics?.url || null,
    engines,
    risk,
    status,
    signals: heuristics?.signals || [],
    stats: stats || null,
    warning,
  };

  if (malicious >= 10) {
    return {
      ...base,
      result: 'UNSAFE',
      verdict: 'MALICIOUS',
      score: `${malicious} of ${engines} engines flag this URL as malicious`,
      message: reasons.length
        ? `Confirmed malicious by ${malicious} engine(s). Also: ${reasons.slice(0, 2).join(' | ')}`
        : `${malicious} security engines detect malware or phishing here. Do not open this link.`,
    };
  }
  if (malicious >= 2) {
    return {
      ...base,
      result: 'SUSPICIOUS',
      verdict: 'SUSPICIOUS',
      score: `${malicious} of ${engines} engines flag this URL as malicious`,
      message: reasons.length
        ? `${malicious} engine(s) flagged this URL, but the malicious threshold is 10. Also: ${reasons.slice(0, 2).join(' | ')}`
        : `${malicious} engine(s) flagged this URL. Treat it with caution.`,
    };
  }
  if (stats && (malicious > 0 || harmless > 0 || suspicious > 0)) {
    return {
      ...base,
      result: 'SAFE',
      verdict: 'SAFE',
      score: `${malicious} malicious flags (${engines} engines checked)`,
      message: `Fewer than 2 engines flagged this URL as malicious.`,
    };
  }
  if (suspicious > 0) {
    return {
      ...base,
      result: 'SUSPICIOUS',
      verdict: 'SUSPICIOUS',
      score: `${suspicious} engine(s) flagged this URL as suspicious`,
      message: reasons.length ? reasons.slice(0, 3).join(' | ') : 'Some engines are suspicious about this URL.',
    };
  }
  if (strong) {
    return {
      ...base,
      result: 'SUSPICIOUS',
      verdict: 'SUSPICIOUS',
      score: `Phishing patterns detected (risk ${risk}/100)`,
      message: `${harmless > 0 ? 'Antivirus engines report no detections, but' : 'No engine has identified this URL, but'} it matches known phishing patterns: ${reasons.slice(0, 3).join(' | ')}`,
    };
  }
  if (medium) {
    return {
      ...base,
      result: 'SUSPICIOUS',
      verdict: 'SUSPICIOUS',
      score: `Suspicious characteristics (risk ${risk}/100)`,
      message: `Nothing confirmed, but this URL looks risky: ${reasons.slice(0, 3).join(' | ')}`,
    };
  }
  if (harmless > 0) {
    return {
      ...base,
      result: 'SAFE',
      verdict: 'SAFE',
      score: `${harmless} of ${engines} engines report this URL as clean`,
      message: `${harmless} security engines checked this URL and reported it as clean.`,
    };
  }
  return {
    ...base,
    result: 'UNKNOWN',
    verdict: 'UNKNOWN',
    score: 'Unable to identify',
    message: inProgress
      ? 'VirusTotal is still analysing this URL. Scan it again in a minute for the engine results.'
      : 'VirusTotal has no verdict for this URL - no engine reported it clean or malicious. Scan again in a minute. "Unable to identify" is not the same as "safe".',
  };
}

const VT_BASE = 'https://www.virustotal.com/api/v3';

/** VirusTotal identifies a URL by its own base64url form (no padding) */
function virusTotalUrlId(url) {
  return Buffer.from(url, 'utf8').toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function vtErrorMessage(status, payload) {
  if (status === 401 || status === 403) return { kind: 'auth', message: 'VirusTotal rejected the API key.' };
  if (status === 429) return { kind: 'rate_limited', message: 'VirusTotal rate limit reached (free keys allow 4 requests per minute). Try again in a minute.' };
  if (status === 400 || payload?.error?.code === 'InvalidArgumentError') {
    // VirusTotal has to fetch the URL itself; reserved or unreachable domains cannot be analysed.
    return { kind: 'unanalyzable', message: 'VirusTotal cannot analyse this URL (unreachable or invalid domain) - showing the phishing pattern check instead.' };
  }
  return { kind: 'upstream', message: 'VirusTotal could not be reached.' };
}

async function vtRequest(pathname, { apiKey, method = 'GET', body }) {
  const headers = { 'x-apikey': apiKey };
  if (body !== undefined) headers['Content-Type'] = 'application/x-www-form-urlencoded';
  const response = await fetch(`${VT_BASE}${pathname}`, { method, headers, body });
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  return { status: response.status, payload };
}

/**
 * Look the URL up in VirusTotal, submitting a fresh analysis only when needed.
 * Uses at most 4 API calls (1 report + 1 submit + 2 polls) so the free tier
 * quota of 4 requests per minute is respected.
 */
async function scanWithVirusTotal({ url, apiKey, polls = 2, pollDelayMs = 3000 }) {
  if (!apiKey) return { error: { kind: 'config', message: 'VirusTotal API key is not configured.' } };

  // 1) an existing report answers instantly and costs a single request
  const report = await vtRequest(`/urls/${virusTotalUrlId(url)}`, { apiKey });
  if (report.status === 200) {
    const attributes = report.payload?.data?.attributes || {};
    const stats = attributes.last_analysis_stats;
    if (stats && (stats.malicious || stats.suspicious || stats.harmless || attributes.last_analysis_date)) {
      return {
        status: 'completed',
        stats,
        votes: attributes.total_votes || null,
        reputation: attributes.reputation ?? null,
        timesSubmitted: attributes.times_submitted || 0,
        firstSubmission: attributes.first_submission_date || null,
      };
    }
  } else if (report.status !== 404) {
    return { error: vtErrorMessage(report.status, report.payload) };
  }

  // 2) not seen before - queue a fresh analysis
  const submit = await vtRequest('/urls', {
    apiKey,
    method: 'POST',
    body: new URLSearchParams({ url }).toString(),
  });
  if (submit.status < 200 || submit.status >= 300) return { error: vtErrorMessage(submit.status, submit.payload) };
  const analysisId = submit.payload?.data?.id;
  if (!analysisId) return { error: { kind: 'upstream', message: 'VirusTotal did not return an analysis id.' } };

  // 3) two short polls: enough for most URLs and still inside the free quota
  let stats = null;
  let status = 'queued';
  for (let attempt = 0; attempt < polls; attempt += 1) {
    await delay(pollDelayMs);
    const analysis = await vtRequest(`/analyses/${analysisId}`, { apiKey });
    if (analysis.status === 429) return { error: vtErrorMessage(429) };
    if (analysis.status !== 200) continue;
    const attributes = analysis.payload?.data?.attributes;
    if (attributes?.stats) {
      stats = attributes.stats;
      status = attributes.status === 'completed' ? 'completed' : 'in_progress';
    }
    if (attributes?.status === 'completed') {
      status = 'completed';
      break;
    }
  }

  return { status, stats, analysisId };
}

module.exports = {
  analyzeUrl,
  buildVerdict,
  scanWithVirusTotal,
  virusTotalUrlId,
  foldHomoglyphs,
  levenshtein,
  parseUrl,
};
