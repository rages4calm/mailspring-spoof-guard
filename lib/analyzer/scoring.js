// scoring.js
// Turns the collected signals into a 0-100 risk score, a level, and
// human-readable summary + recommendation. All weights live here so the
// detection behaviour can be tuned in one spot.

'use strict';

var WEIGHTS = {
  // user lists
  blocked_sender: 80,
  // online reputation (DNS blocklists)
  ip_blocklisted: 32,
  domain_blocklisted: 38,
  link_blocklisted: 38,
  no_auth_records: 7,
  // header / auth
  internal_spoof: 55,
  dmarc_fail: 35,
  dkim_fail: 28,
  spf_fail: 28,
  spf_softfail: 12,
  from_unaligned: 25,
  auth_missing: 6,
  reply_to_mismatch: 14,
  return_path_mismatch: 12,
  return_path_null: 14,
  display_name_email_spoof: 30,
  display_name_brand: 28,
  punycode_from: 30,
  suspicious_tld: 10,
  lookalike_domain: 32,
  impersonates_you: 45,
  homoglyph_name: 30,
  reply_to_freemail: 24,
  no_received: 6,
  // content
  sextortion: 45,
  extortion_crypto: 25,
  urgency: 6,
  credential_phish: 16,
  credential_phish_link: 32,
  fake_invoice: 8,
  link_text_mismatch: 28,
  link_suspicious_tld: 14,
  qr_phishing: 16,
  ip_url: 18,
  punycode_url: 22,
  obfuscated_url: 20,
  shortener_url: 5,
  double_extension: 40,
  dangerous_attachment: 25,
  markup_attachment: 26,
};

// Signals that are common in *legitimate* bulk/list mail. When a message is
// fully authenticated AND aligned (trusted), we down-weight these to avoid
// flagging real newsletters, receipts, and mailing lists.
var DAMPENABLE = {
  reply_to_mismatch: true,
  return_path_mismatch: true,
  urgency: true,
  credential_phish: true,
  fake_invoice: true,
  shortener_url: true,
  suspicious_tld: true,
  no_received: true,
};

function dedupe(signals) {
  var seen = {};
  var out = [];
  signals.forEach(function (s) {
    if (seen[s.id]) return;
    seen[s.id] = true;
    out.push(s);
  });
  return out;
}

function levelFor(score) {
  if (score >= 70) return 'very-high';
  if (score >= 45) return 'high';
  if (score >= 20) return 'suspicious';
  return 'low';
}

var LEVEL_RANK = { 'low': 0, 'suspicious': 1, 'high': 2, 'very-high': 3 };

var SUMMARY = {
  'low': 'No significant spoofing or phishing indicators were found.',
  'suspicious': 'This message has a few weak indicators. Treat it with mild caution.',
  'high': 'This message shows multiple spoofing/phishing indicators.',
  'very-high': 'This message shows strong signs of spoofing, phishing, or a scam.',
};

var RECOMMENDATION = {
  'low': 'Looks legitimate, but always verify unexpected requests.',
  'suspicious': 'Be cautious with links and attachments; verify the sender if anything seems off.',
  'high': 'Do not click links, open attachments, or reply. Verify the sender through a known channel.',
  'very-high': 'Treat as malicious. Do not interact. Verify independently and consider reporting it.',
};

// score(signals, auth) -> result JSON
function score(signals, auth) {
  signals = dedupe(signals || []);
  // Use the softer "looksLegit" (verified+aligned OR self-signed) for dampening
  // so legit signed mail isn't over-scored on hosts that strip auth headers.
  var trusted = auth && (auth.looksLegit || auth.trusted);

  var total = 0;
  var hasCritical = false;
  var hasHigh = false;
  signals.forEach(function (s) {
    var w = WEIGHTS[s.id] || 0;
    if (trusted && DAMPENABLE[s.id]) w = Math.round(w * 0.35);
    s.points = w;
    total += w;
    if (s.severity === 'critical') hasCritical = true;
    if (s.severity === 'high') hasHigh = true;
  });

  // A trusted, well-aligned message gets a small benefit of the doubt — but only
  // when nothing serious is present. We never discount genuine high/critical
  // signals (e.g. impersonation) just because transport authentication passed.
  if (trusted && !hasHigh && !hasCritical) total = Math.max(0, total - 8);

  var clamped = Math.max(0, Math.min(100, total));

  // A critical-severity signal (sextortion, malware double-extension, spoof of
  // your own domain) is unambiguous — it floors the score into "very high" on
  // its own, so even a strict auto-move threshold catches it.
  if (hasCritical) clamped = Math.max(clamped, 70);

  var level = levelFor(clamped);

  // Sort signals by weight, strongest first, for display.
  signals.sort(function (a, b) { return (b.points || 0) - (a.points || 0); });

  return {
    score: clamped,
    level: level,
    levelRank: LEVEL_RANK[level],
    signals: signals,
    summary: SUMMARY[level],
    recommendation: RECOMMENDATION[level],
  };
}

module.exports = { score: score, WEIGHTS: WEIGHTS, levelFor: levelFor };
