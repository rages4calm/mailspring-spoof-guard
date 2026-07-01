// domains.js
// Domain comparison and look-alike helpers. No network, no dependencies.

'use strict';

// A small public-suffix-ish list. A full PSL is overkill for v1; this covers the
// multi-label TLDs people actually get spoofed with so base-domain comparison
// (the heart of DMARC-style alignment) is correct for the common cases.
var MULTI_LABEL_TLDS = [
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'co.jp', 'co.nz', 'co.za',
  'com.au', 'net.au', 'org.au', 'com.br', 'com.mx', 'com.tr', 'com.sg',
  'co.zw', 'co.in', 'co.id', 'co.ke', 'co.th', 'co.il', 'co.kr',
];

// Pull the first email-ish domain out of a free-text header value
// e.g. '"Bob" <bob@mail.example.com>' -> 'mail.example.com'
function extractDomain(text) {
  if (!text) return null;
  var m = String(text).match(/@([a-z0-9.-]+\.[a-z]{2,})/i);
  return m ? m[1].toLowerCase().replace(/[.>,;]+$/, '') : null;
}

// The email address out of a header value: '"Bob" <bob@x.com>' -> 'bob@x.com'.
function extractEmail(text) {
  if (!text) return null;
  var m = String(text).match(/<([^<>@\s]+@[^<>\s]+)>/) ||
          String(text).match(/([^\s<>"']+@[^\s<>"']+)/);
  return m ? m[1].toLowerCase().replace(/[.,;>]+$/, '') : null;
}

// The display name portion of a From/To header (the part before <...>).
function extractDisplayName(text) {
  if (!text) return null;
  var m = String(text).match(/^\s*"?([^"<]*?)"?\s*</);
  var name = m ? m[1].trim() : '';
  return name || null;
}

// Registered/organizational domain (used for alignment comparisons).
function baseDomain(domain) {
  if (!domain) return null;
  var parts = domain.toLowerCase().split('.');
  if (parts.length <= 2) return domain.toLowerCase();
  var lastTwo = parts.slice(-2).join('.');
  var lastThree = parts.slice(-3).join('.');
  if (MULTI_LABEL_TLDS.indexOf(lastTwo) !== -1) return lastThree;
  return lastTwo;
}

// True when two domains share the same organizational domain (relaxed alignment).
function sameBaseDomain(a, b) {
  if (!a || !b) return false;
  return baseDomain(a) === baseDomain(b);
}

// Punycode / IDN homograph domains begin a label with "xn--".
function isPunycode(domain) {
  return !!domain && /(^|\.)xn--/i.test(domain);
}

var SUSPICIOUS_TLDS = [
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'work', 'click', 'link', 'zip',
  'mov', 'country', 'kim', 'xyz', 'rest', 'fit', 'review', 'date', 'loan',
  // currently abuse-heavy TLDs / ccTLDs (2025-2026)
  'zw', 'icu', 'sbs', 'cfd', 'cyou', 'lol', 'quest', 'mom', 'bond',
  'makeup', 'skin', 'hair', 'monster', 'beauty', 'autos', 'boats',
];

function suspiciousTld(domain) {
  if (!domain) return false;
  var tld = domain.split('.').pop();
  return SUSPICIOUS_TLDS.indexOf(tld) !== -1;
}

// Free / consumer mail providers. A "request from the boss" that actually comes
// from one of these (instead of the corporate domain) is a classic BEC tell.
var FREEMAIL = [
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com',
  'msn.com', 'yahoo.com', 'ymail.com', 'aol.com', 'icloud.com', 'me.com',
  'proton.me', 'protonmail.com', 'gmx.com', 'gmx.net', 'mail.com',
  'yandex.com', 'zoho.com', 'tutanota.com', 'fastmail.com',
];

function isFreemail(domain) {
  if (!domain) return false;
  return FREEMAIL.indexOf(baseDomain(domain)) !== -1;
}

// Normalises a person's name for comparison ("Jane  Smith" -> "jane smith").
function normalizeName(name) {
  if (!name) return '';
  return String(name).toLowerCase().replace(/[^a-z\s]/g, ' ').replace(/\s+/g, ' ').trim();
}

// True when two names refer to the same person (exact, or one fully contains
// the other and it's a meaningful length).
function namesMatch(a, b) {
  a = normalizeName(a);
  b = normalizeName(b);
  if (!a || !b || a.length < 4 || b.length < 4) return false;
  if (a === b) return true;
  return a.indexOf(b) !== -1 || b.indexOf(a) !== -1;
}

// Homoglyph / mixed-script text: Latin letters mixed with Cyrillic or Greek
// look-alikes (e.g. "Аpple" where the A is Cyrillic U+0410). A favourite trick
// for display names and brand names that bypass domain-level checks.
function looksHomoglyph(text) {
  if (!text) return false;
  var hasLatin = /[a-z]/i.test(text);
  var hasConfusable = /[Ѐ-ӿͰ-Ͽ]/.test(text); // Cyrillic / Greek
  return hasLatin && hasConfusable;
}

// Levenshtein distance, capped — used to spot look-alike domains
// (paypa1.com vs paypal.com, micros0ft.com vs microsoft.com).
function levenshtein(a, b) {
  a = a || '';
  b = b || '';
  var m = a.length, n = b.length;
  if (Math.abs(m - n) > 3) return 99;
  var prev = [], cur = [], i, j;
  for (j = 0; j <= n; j++) prev[j] = j;
  for (i = 1; i <= m; i++) {
    cur[0] = i;
    for (j = 1; j <= n; j++) {
      var cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
    }
    for (j = 0; j <= n; j++) prev[j] = cur[j];
  }
  return prev[n];
}

// Brands commonly impersonated. If a display name claims one of these but the
// sending domain isn't that brand (and isn't aligned), it's a strong signal.
var KNOWN_BRANDS = [
  'paypal', 'apple', 'microsoft', 'amazon', 'google', 'netflix', 'facebook',
  'instagram', 'docusign', 'dropbox', 'linkedin', 'fedex', 'ups', 'dhl',
  'wellsfargo', 'chase', 'bankofamerica', 'coinbase', 'binance', 'usps',
  'irs', 'norton', 'mcafee', 'geeksquad',
];

// Spelled-out forms of the squashed brand keys above.
var BRAND_VARIANTS = {
  wellsfargo: 'wells fargo',
  bankofamerica: 'bank of america',
  geeksquad: 'geek squad',
};

// Returns the brand name a piece of text claims to be (from a known list),
// or null. Whole-word matching only — substring matching would hit "ups" inside
// "Groups", "irs" inside "first", "apple" inside "pineapple", etc.
function claimedBrand(text) {
  if (!text) return null;
  var lower = String(text).toLowerCase();
  for (var i = 0; i < KNOWN_BRANDS.length; i++) {
    var b = KNOWN_BRANDS[i];
    if (new RegExp('\\b' + b + '\\b', 'i').test(lower)) return b;
    var v = BRAND_VARIANTS[b];
    if (v && new RegExp('\\b' + v + '\\b', 'i').test(lower)) return b;
  }
  return null;
}

module.exports = {
  extractDomain: extractDomain,
  extractEmail: extractEmail,
  extractDisplayName: extractDisplayName,
  baseDomain: baseDomain,
  sameBaseDomain: sameBaseDomain,
  isPunycode: isPunycode,
  suspiciousTld: suspiciousTld,
  levenshtein: levenshtein,
  claimedBrand: claimedBrand,
  isFreemail: isFreemail,
  normalizeName: normalizeName,
  namesMatch: namesMatch,
  looksHomoglyph: looksHomoglyph,
  KNOWN_BRANDS: KNOWN_BRANDS,
  FREEMAIL: FREEMAIL,
};
