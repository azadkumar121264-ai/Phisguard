#!/usr/bin/env node
/**
 * Regression checks for the phishing verdict engine in lib/urlAnalysis.js.
 *
 * Run with:  node scripts/check-verdicts.mjs
 *
 * The guarantee these checks protect: a URL that VirusTotal has no verdict for
 * is never reported as SAFE ("unable to identify" != "safe").
 */

import assert from 'node:assert/strict';
import urlAnalysis from '../lib/urlAnalysis.js';

const { analyzeUrl, buildVerdict } = urlAnalysis;

/** engines looked at it and reported it clean */
const CLEAN = { malicious: 0, suspicious: 0, harmless: 72, undetected: 20 };
/** freshly registered domain: engines ran but none had an opinion */
const NO_VERDICT = { malicious: 0, suspicious: 0, harmless: 0, undetected: 95 };
/** engines actually detected something */
const DETECTED = { malicious: 12, suspicious: 0, harmless: 60, undetected: 20 };
const LOW_DETECTION = { malicious: 3, suspicious: 0, harmless: 60, undetected: 20 };
const SAFE_THRESHOLD = { malicious: 1, suspicious: 0, harmless: 60, undetected: 20 };
const SINGLE_FLAG = { malicious: 1, suspicious: 0, harmless: 0, undetected: 0 };

assert.equal(analyzeUrl('').error, 'Invalid URL');
assert.equal(analyzeUrl(undefined).error, 'Invalid URL');
assert.equal(analyzeUrl('http://goggle.com/login').isIp, false);
assert.equal(analyzeUrl('http://192.168.0.1/login').isIp, true);

let checks = 0;

function expectVerdict(url, stats, status, expected) {
  const heuristics = analyzeUrl(url);
  const { verdict, message } = buildVerdict({ heuristics, stats, status });
  checks += 1;
  assert.ok(
    expected.includes(verdict),
    `${url} -> expected ${expected.join(' or ')}, got ${verdict} (risk ${heuristics.risk}): ${message}`,
  );
  console.log(`ok  ${verdict.padEnd(11)} risk=${String(heuristics.risk).padStart(3)}  ${url}`);
}

// brand-new phishing domains: no VirusTotal reputation, so heuristics must decide
expectVerdict('http://goggle.com/login', NO_VERDICT, 'completed', ['SUSPICIOUS']);
expectVerdict('https://paypa1-login.tk/verify-account', NO_VERDICT, 'completed', ['SUSPICIOUS']);
expectVerdict('http://secure-hdfcbank-kyc-update.top/wp/login.php', NO_VERDICT, 'completed', ['SUSPICIOUS']);
expectVerdict('http://user@evil.tk/paypal/verify', NO_VERDICT, 'completed', ['SUSPICIOUS']);
expectVerdict('http://free-lottery-winner.xyz/claim-now', NO_VERDICT, 'completed', ['SUSPICIOUS']);

// no engine opinion must never be reported as SAFE
expectVerdict('https://example.com', NO_VERDICT, 'completed', ['UNKNOWN']);
expectVerdict('https://example.com', { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 }, 'queued', ['UNKNOWN']);

// a raw IP host is malicious by itself, no API call needed
expectVerdict('http://192.168.0.1/login', null, 'skipped', ['SUSPICIOUS']);

// when engines do have an opinion, they win
expectVerdict('https://google.com/', CLEAN, 'completed', ['SAFE']);
expectVerdict('https://www.amazon.in/gp/cart', CLEAN, 'completed', ['SAFE']);
expectVerdict('https://malware.testing.example/payload', DETECTED, 'completed', ['MALICIOUS']);
expectVerdict('https://malware.testing.example/payload', LOW_DETECTION, 'completed', ['SUSPICIOUS']);
expectVerdict('https://malware.testing.example/payload', SAFE_THRESHOLD, 'completed', ['SAFE']);
expectVerdict('https://malware.testing.example/payload', SINGLE_FLAG, 'completed', ['SAFE']);

// ordinary URLs must not turn into false positives
expectVerdict('https://github.com/ljharb/tsconfig', CLEAN, 'completed', ['SAFE']);
expectVerdict('https://myaccount.google.com', CLEAN, 'completed', ['SAFE']);
expectVerdict('https://bit.ly/abc123', CLEAN, 'completed', ['SAFE']);
expectVerdict('https://www.google.com/search?q=login', CLEAN, 'completed', ['SAFE']);

// while VirusTotal is still scanning, strong patterns escalate to SUSPICIOUS
expectVerdict('http://goggle.com/login', null, 'in_progress', ['SUSPICIOUS']);

// VirusTotal unavailable or rate limited: heuristics still answer
expectVerdict('https://paypa1-login.tk/verify-account', null, 'unavailable', ['SUSPICIOUS']);
expectVerdict('https://example.com', null, 'unavailable', ['UNKNOWN']);

console.log(`\n${checks} verdict checks passed`);
