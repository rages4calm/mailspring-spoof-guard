// heuristics-content.js
// Body / link / attachment signals. Operates on decoded text + raw HTML.

'use strict';

var domains = require('./domains');

var SEXTORTION = [
  'i have access to your',
  'i recorded you',
  'i recorded your',
  'your webcam',
  'i have a video of you',
  'i have video of you',
  'pleasuring yourself',
  'masturbat',
  'adult site',
  'adult website',
  'porn',
  'i have all your contacts',
  'send.{0,15}bitcoin',
  'you are a pervert',
  'i know your password',
  'i know one of your password',
];

var EXTORTION_PAY = [
  'bitcoin',
  'btc address',
  'btc wallet',
  'usdt',
  'crypto wallet',
  'wallet address',
  'pay the ransom',
  '48 hours',
  '24 hours',
  'or i will',
  'i will send',
];

var URGENCY = [
  'act now',
  'immediately',
  'urgent',
  'final notice',
  'last warning',
  'your account will be',
  'will be suspended',
  'will be terminated',
  'within 24 hours',
  'verify your account',
  'confirm your identity',
  'unusual activity',
  'limited time',
  'expire',                 // "is set to expire", "will expire", "expires"
  '\\d+\\s*hrs?\\b',        // "24Hrs", "48 hr"
  'as soon as possible',
  'avoid suspension',
];

var CREDENTIAL = [
  'verify your account',
  'verify your identity',
  'confirm your password',
  'reset your password',
  'update your password',
  'change your password',
  'password.{0,45}expire',     // "password of your email account will expire"
  'expire.{0,25}password',
  'keep the same password',
  'current password',
  'sign in below',
  'log in below',
  'login below',
  'update your payment',
  'update your billing',
  'account has been locked',
  'account is locked',
  'account suspended',
  'unusual sign-in',
  'sign in to confirm',
  'click here to verify',
  'validate your account',
  'confirm your email',
  'reactivate your account',
  're-?confirm',                  // "re-confirm ownership", "Re-confirm Password"
  'confirm.{0,15}ownership',
  'verify.{0,15}ownership',
  'account verification',
  'mail verification',
  'verify your mailbox',
];

// Fake "document to review / sign" notifications (DocuSign/Adobe-Sign style) —
// one of the top phishing lures of 2025-2026.
var DOCUMENT_PHISH = [
  'you received a document',
  'received a document',
  'document has been sent',
  'a document.{0,20}(review|sign|sent)',
  'document.{0,20}requires your',
  'requires your (review|signature|attention)',
  'sent for your review',
  'review the (attached |secure )?document',
  'view document',
  'view the document',
  'sign(ed)? document',
  'document to sign',
  'shared a document',
  'e-?sign(ature)?',
  'secure document',
  'pending document',
];

var INVOICE = [
  'invoice attached',
  'payment is due',
  'overdue invoice',
  'outstanding balance',
  'wire transfer',
  'remittance',
  'purchase order',
  'your receipt',
  'order confirmation',
  'subscription has been renewed',
  'auto-renewal',
];

// Bulk-spam tells. Each phrase is spam-specific (rare in real business mail), so
// requiring several keeps false positives low. Content-based and run regardless
// of authentication — a throwaway domain that DKIM-signs its OWN spam is still
// spam (auth proves "the domain sent it", not "it's wanted").
var SPAM_PHRASES = [
  // adult / male-enhancement
  'rock[ -]?hard', 'stay hard', 'get hard', 'harder erection', 'male enhancement',
  'male performance', 'sexual performance', 'erectile', 'libido', 'virility',
  'your manhood', 'last longer in bed', 'ignite the passion', 'bedroom performance',
  'wife or girlfriend', 'boost.{0,12}testosterone', 'bigger.{0,12}(size|inches)',
  // health-miracle / quackery / clickbait
  'big pharma', 'doctors hate', 'this simple trick', 'taken down',
  'miracle (cure|remedy)', 'ancient.{0,15}remedy', "they don.?t want you to know",
  'controversial video', 'bedtime ritual', 'reverses.{0,30}overnight',
  'pharmaceutical industry', 'fountain of youth', 'melts.{0,12}fat',
  'simple.{0,12}ritual', 'nerve (pain|damage)', 'neuropathy',
  'costs? less than a cup of coffee', 'before it.?s taken down',
  'weird trick', 'shocking discovery', 'watch (the|this).{0,15}video before',
];

// Advance-fee / unsolicited-investment ("lead-gen") lures.
var INVESTMENT_LURE = [
  'private capital', 'family office', 'single-family office', 'private family office',
  'capitalized by', 'attract.{0,12}capital', 'private investment', 'seeking investors',
  'investment of', 'venture capital', 'access to (private )?capital',
  '\\$\\s?\\d[\\d,]*\\s?m\\b', '\\$\\s?\\d[\\d,]*\\s?million',
];

// Extensions that should never arrive as a bare email attachment.
var DANGEROUS_EXT = [
  'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe',
  'wsf', 'wsh', 'hta', 'jar', 'ps1', 'msi', 'msc', 'reg', 'lnk', 'iso',
  'img', 'cpl', 'gadget',
];

function countMatches(text, phrases) {
  var lower = (text || '').toLowerCase();
  var hits = [];
  phrases.forEach(function (p) {
    var re = new RegExp(p, 'i');
    if (re.test(lower)) hits.push(p);
  });
  return hits;
}

// Extract { href, text } pairs from HTML anchors.
function extractAnchors(html) {
  var anchors = [];
  var re = /<a\b[^>]*?href\s*=\s*["']?([^"'>\s]+)["']?[^>]*>([\s\S]*?)<\/a>/gi;
  var m;
  while ((m = re.exec(html)) !== null) {
    anchors.push({ href: m[1], text: m[2].replace(/<[^>]+>/g, ' ').trim() });
  }
  return anchors;
}

function urlDomain(url) {
  if (!url) return null;
  var m = String(url).match(/^[a-z]+:\/\/([^/?#\s]+)/i);
  if (!m) return null;
  var host = m[1].replace(/^[^@]*@/, ''); // strip userinfo
  host = host.replace(/:\d+$/, '');       // strip port
  return host.toLowerCase();
}

function contentSignals(parts, ctx) {
  var signals = [];
  var text = parts.text || '';
  var html = parts.html || '';
  var subject = ctx.subject || '';
  var haystack = subject + '\n' + text;

  // --- gather links once (used by several checks below) ----------------------
  var anchors = extractAnchors(html);
  var bare = (text.match(/\bhttps?:\/\/[^\s"'<>)]+/gi) || []);
  var allUrls = anchors.map(function (a) { return a.href; }).concat(bare);
  var linkDomains = [];
  allUrls.forEach(function (u) {
    var d = urlDomain(u);
    if (d) linkDomains.push(d.replace(/^www\./, ''));
  });
  var trustedList = ctx.trustedDomains || [];
  var hasExternalLink = linkDomains.some(function (d) {
    return !trustedList.some(function (t) { return domains.sameBaseDomain(d, t); });
  });
  // Softer trust for FALSE-POSITIVE gating: authenticated, OR the sender signed
  // for its own domain (survives hosts that strip Authentication-Results).
  var trustedAuth = !!(ctx.auth && ctx.auth.looksLegit);

  // --- scam language ----------------------------------------------------------
  if (countMatches(haystack, SEXTORTION).length >= 1) {
    signals.push({
      id: 'sextortion',
      label: 'Contains sextortion / blackmail-style language',
      severity: 'critical',
    });
  }
  var payHits = countMatches(haystack, EXTORTION_PAY);
  if (payHits.length >= 1 && /bitcoin|btc|usdt|wallet|crypto/i.test(haystack)) {
    signals.push({
      id: 'extortion_crypto',
      label: 'Demands cryptocurrency payment (common in extortion scams)',
      severity: 'high',
    });
  }
  if (countMatches(haystack, URGENCY).length >= 2) {
    signals.push({
      id: 'urgency',
      label: 'Uses pressure / urgency language',
      severity: 'low',
    });
  }
  // Credential / login phishing. When it also drives you to an EXTERNAL site and
  // the message isn't authenticated+aligned, that's high-confidence phishing
  // (the classic "your password expires, sign in here" lure).
  var credHits = countMatches(haystack, CREDENTIAL);
  if (credHits.length >= 1) {
    if (hasExternalLink && !trustedAuth) {
      signals.push({
        id: 'credential_phish_link',
        label: 'Asks for your password / login and links to an external site',
        severity: 'high',
      });
    } else {
      signals.push({
        id: 'credential_phish',
        label: 'Asks you to verify/reset credentials or unlock an account',
        severity: 'medium',
      });
    }
  }
  if (countMatches(haystack, INVOICE).length >= 1) {
    signals.push({
      id: 'fake_invoice',
      label: 'Invoice / payment / billing language (possible fake billing scam)',
      severity: 'low',
    });
  }

  // Fake document/e-signature notification that drives you to an external site,
  // on mail that isn't authenticated+aligned. (Legit DocuSign etc. is signed.)
  var docHits = countMatches(haystack, DOCUMENT_PHISH);
  if (docHits.length >= 1 && hasExternalLink && !trustedAuth) {
    signals.push({
      id: 'document_phish',
      label: 'Fake "document to review/sign" notification linking to an external site',
      severity: 'high',
    });
  }

  // Body-based brand impersonation: the message presents a known brand (DocuSign,
  // PayPal, a bank…) with an action lure, but the sender ISN'T that brand and a
  // link points off to an unrelated domain. Gated on lack of authentication and
  // on the From not being the brand, so real (signed) brand mail is never hit.
  var brand = domains.claimedBrand(haystack);
  function sld(d) { var b = domains.baseDomain(d); return b ? b.split('.')[0] : null; }
  if (brand && !trustedAuth) {
    var fromIsBrand = ctx.fromDomain && sld(ctx.fromDomain) === brand;
    var lure = docHits.length >= 1 || credHits.length >= 1;
    var offBrandLink = linkDomains.some(function (d) {
      var trusted = trustedList.some(function (t) { return domains.sameBaseDomain(d, t); });
      return !trusted && sld(d) !== brand;
    });
    if (!fromIsBrand && lure && offBrandLink) {
      signals.push({
        id: 'brand_impersonation',
        label: 'Impersonates "' + brand + '" but the sender (' + (ctx.fromDomain || 'unknown') +
          ') and links are unrelated',
        severity: 'high',
      });
    }
  }

  // --- bulk spam (adult / miracle-cure / clickbait) ---------------------------
  // NOT gated on authentication: a domain that signs its own spam is still spam.
  var spamHits = countMatches(haystack, SPAM_PHRASES);
  if (spamHits.length >= 3) {
    signals.push({
      id: 'spam_content',
      label: 'Reads like bulk spam (' + spamHits.length + ' adult / miracle-cure / clickbait phrases)',
      severity: spamHits.length >= 5 ? 'critical' : 'high',
    });
  }

  // --- advance-fee / unsolicited investment, esp. with a name/address mismatch -
  var invHits = countMatches(haystack, INVESTMENT_LURE);
  if (invHits.length >= 1) {
    var fromEmail2 = domains.extractEmail(ctx.from);
    var localPart = fromEmail2 ? fromEmail2.split('@')[0] : '';
    var lpName = domains.normalizeName(localPart.replace(/[._\-]+/g, ' '));
    var dispN = domains.normalizeName(ctx.displayName);
    var nameMismatch = dispN && lpName &&
      dispN.split(' ').filter(Boolean).length >= 2 &&
      lpName.split(' ').filter(Boolean).length >= 2 &&
      !domains.namesMatch(dispN, lpName);
    if (nameMismatch) {
      signals.push({
        id: 'advance_fee_lure',
        label: 'Unsolicited investment/funding offer, and the display name ("' + ctx.displayName +
          '") doesn’t match the address',
        severity: 'medium',
      });
    } else if (invHits.length >= 2 && !trustedAuth) {
      signals.push({
        id: 'advance_fee_lure',
        label: 'Unsolicited investment / capital-raising offer from an unverified sender',
        severity: 'medium',
      });
    }
  }

  // --- quishing (QR-code phishing) --------------------------------------------
  // QR codes hit ~12% of phishing in 2025. Legit mail rarely tells you to scan
  // a code to "verify"/"unlock". Flag QR + action language, esp. with an image.
  var hasImage = /<img\b/i.test(html) ||
    (parts.attachments || []).some(function (n) { return /\.(png|jpe?g|gif|bmp|svg)$/i.test(n); });
  if (/\b(scan (the )?(qr|code|barcode)|qr[\s-]?code)\b/i.test(haystack) &&
      (hasImage || credHits.length || countMatches(haystack, URGENCY).length)) {
    signals.push({
      id: 'qr_phishing',
      label: 'Asks you to scan a QR code (common phishing / "quishing" technique)',
      severity: 'medium',
    });
  }

  // --- link analysis ----------------------------------------------------------
  var reportedMismatch = false;
  anchors.forEach(function (a) {
    var hrefDomain = urlDomain(a.href);
    var textDomain = domains.extractDomain(a.text) ||
      (a.text && /\b[a-z0-9.-]+\.[a-z]{2,}\b/i.test(a.text)
        ? (a.text.match(/\b([a-z0-9.-]+\.[a-z]{2,})\b/i) || [])[1]
        : null);
    if (!reportedMismatch && hrefDomain && textDomain &&
        !domains.sameBaseDomain(hrefDomain.replace(/^www\./, ''), textDomain.toLowerCase().replace(/^www\./, ''))) {
      signals.push({
        id: 'link_text_mismatch',
        label: 'A link shows "' + textDomain + '" but actually points to ' + hrefDomain,
        severity: 'high',
      });
      reportedMismatch = true;
    }
  });

  var sawIp = false, sawPuny = false, sawObf = false, sawShort = false, sawLinkTld = false;
  var SHORTENERS = ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rb.gy'];
  allUrls.forEach(function (u) {
    var host = urlDomain(u);
    if (!host) return;
    // The authority is everything between the scheme and the first /?# — only an
    // "@" HERE is real userinfo obfuscation (not one in a path/query/fragment).
    var authority = u.replace(/^[a-z]+:\/\//i, '').split(/[\/?#]/)[0];
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) && !sawIp) {
      signals.push({ id: 'ip_url', label: 'Link points to a raw IP address: ' + host, severity: 'high' });
      sawIp = true;
    }
    if (/(^|\.)xn--/i.test(host) && !sawPuny) {
      signals.push({ id: 'punycode_url', label: 'Link uses punycode/IDN domain: ' + host, severity: 'high' });
      sawPuny = true;
    }
    if (/@/.test(authority) && !sawObf) {
      signals.push({ id: 'obfuscated_url', label: 'Link uses an embedded "@" to disguise its real destination', severity: 'high' });
      sawObf = true;
    }
    if (SHORTENERS.indexOf(host.replace(/^www\./, '')) !== -1 && !sawShort) {
      signals.push({ id: 'shortener_url', label: 'Uses a URL shortener that hides the real destination', severity: 'low' });
      sawShort = true;
    }
    if (!sawLinkTld && domains.suspiciousTld(host.replace(/^www\./, ''))) {
      signals.push({ id: 'link_suspicious_tld', label: 'A link points to a frequently-abused top-level domain: ' + host, severity: 'medium' });
      sawLinkTld = true;
    }
  });

  // --- attachments ------------------------------------------------------------
  // Markup attachments (HTML/SVG/MHTML) are the fast-rising 2026 phishing vector:
  // the fake login page rides along as a file, so there's no link to scan. These
  // are almost never legitimate as an emailed attachment.
  var RISKY_MARKUP = ['html', 'htm', 'shtml', 'xhtml', 'mht', 'mhtml', 'svg', 'svgz'];
  function checkFile(name, isInline) {
    var lower = name.toLowerCase();
    var ext = lower.split('.').pop();
    // double extension: invoice.pdf.exe
    if (/\.[a-z0-9]{2,4}\.(exe|scr|js|vbs|bat|cmd|com|pif|jar|hta|iso)$/i.test(lower)) {
      signals.push({ id: 'double_extension', label: 'Attachment has a deceptive double extension: ' + name, severity: 'critical' });
    } else if (DANGEROUS_EXT.indexOf(ext) !== -1) {
      signals.push({ id: 'dangerous_attachment', label: 'Potentially dangerous attachment type: ' + name, severity: 'high' });
    } else if (!isInline && RISKY_MARKUP.indexOf(ext) !== -1) {
      // Only TRUE attachments — an inline cid: SVG/HTML asset is just part of
      // the message body (e.g. a newsletter logo), not a page-as-a-file lure.
      signals.push({ id: 'markup_attachment', label: 'Attachment is a web-page file often used to deliver phishing: ' + name, severity: 'high' });
    }
  }
  (parts.attachments || []).forEach(function (n) { checkFile(n, false); });
  (parts.inlineFiles || []).forEach(function (n) { checkFile(n, true); });

  return signals;
}

module.exports = {
  contentSignals: contentSignals,
  extractAnchors: extractAnchors,
  urlDomain: urlDomain,
};
