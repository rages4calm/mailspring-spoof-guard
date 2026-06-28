// test/run.js
// Plain-Node test harness for the analyzer. Run with: npm test  (or: node test/run.js)
// No test framework needed — keeps the plugin dependency-free.

'use strict';

var analyzer = require('../lib/analyzer');

var ACCOUNT = 'me@mydomain.com';
var cases = [];
function t(name, raw, expect) { cases.push({ name: name, raw: raw, expect: expect }); }

// 1) Legitimate, fully authenticated mail from a real correspondent.
t('legit authenticated', [
  'Return-Path: <newsletter@stripe.com>',
  'Authentication-Results: mx.mydomain.com; spf=pass smtp.mailfrom=stripe.com;',
  ' dkim=pass header.d=stripe.com; dmarc=pass (p=reject) header.from=stripe.com',
  'Received: from mail.stripe.com (mail.stripe.com [54.0.0.1]) by mx.mydomain.com',
  'From: "Stripe" <newsletter@stripe.com>',
  'Reply-To: support@stripe.com',
  'Subject: Your March receipt',
  'Content-Type: text/plain',
  '',
  'Thanks for your payment. View your receipt at https://dashboard.stripe.com/receipts',
].join('\r\n'), { maxLevelRank: 1 });

// 2) Spoof of the user's OWN domain (the main pain point).
t('internal domain spoof', [
  'Return-Path: <attacker@evil.tk>',
  'Authentication-Results: mx.mydomain.com; spf=fail smtp.mailfrom=evil.tk;',
  ' dkim=none; dmarc=fail (p=none) header.from=mydomain.com',
  'Received: from evil.tk (evil.tk [193.0.0.9]) by mx.mydomain.com',
  'From: "IT Department" <admin@mydomain.com>',
  'Subject: Action required: reset your password',
  'Content-Type: text/html',
  '',
  '<p>Your account has been locked. <a href="http://193.0.0.9/login">verify your account</a></p>',
].join('\r\n'), { minLevelRank: 2, mustHave: ['internal_spoof'] });

// 3) Classic sextortion scam.
t('sextortion scam', [
  'Return-Path: <x@spammy.top>',
  'Authentication-Results: mx.mydomain.com; spf=softfail; dkim=none; dmarc=none',
  'From: "You" <you@mydomain.com>',
  'Subject: I recorded you',
  'Content-Type: text/plain',
  '',
  'I have access to your webcam and I recorded you. Send 1200 in bitcoin to this wallet within 24 hours or I will send the video to all your contacts.',
].join('\r\n'), { minLevelRank: 2, mustHave: ['sextortion'] });

// 4) Brand phishing with a link whose text lies about its destination.
t('paypal phish link mismatch', [
  'Return-Path: <bounce@account-secure.click>',
  'Authentication-Results: mx.mydomain.com; spf=pass smtp.mailfrom=account-secure.click;',
  ' dkim=pass header.d=account-secure.click; dmarc=pass header.from=account-secure.click',
  'From: "PayPal Service" <service@account-secure.click>',
  'Subject: Unusual activity on your account',
  'Content-Type: text/html',
  '',
  '<p>Please <a href="http://account-secure.click/login">www.paypal.com</a> confirm your identity.</p>',
].join('\r\n'), { minLevelRank: 1, mustHave: ['display_name_brand', 'link_text_mismatch'] });

// 5) Malware attachment with deceptive double extension.
t('double extension attachment', [
  'Return-Path: <billing@invoices-online.work>',
  'Authentication-Results: mx.mydomain.com; spf=none; dkim=none; dmarc=none',
  'From: "Billing" <billing@invoices-online.work>',
  'Subject: Invoice attached',
  'Content-Type: multipart/mixed; boundary="b1"',
  '',
  '--b1',
  'Content-Type: text/plain',
  '',
  'Payment is due. See attached invoice.',
  '--b1',
  'Content-Type: application/octet-stream; name="invoice.pdf.exe"',
  'Content-Disposition: attachment; filename="invoice.pdf.exe"',
  '',
  'TVqQAAMAAAAEAAAA',
  '--b1--',
].join('\r\n'), { minLevelRank: 2, mustHave: ['double_extension'] });

// 6) The user's real case: display name is the account owner, but the address
//    is an unrelated Gmail. Host also injected a "{Definitely Spam?}" tag.
t('freemail impersonates you (+ host tag)', [
  'Return-Path: <janesmith@gmail.com>',
  'Authentication-Results: mx.yourdomain.com; spf=pass smtp.mailfrom=gmail.com;',
  ' dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com',
  'From: "Jane Smith" <janesmith@gmail.com>',
  'To: you@yourdomain.com',
  'Subject: {Definitely Spam?} test',
  'Content-Type: text/plain',
  '',
  'test',
].join('\r\n'), {
  account: 'you@yourdomain.com', accountName: 'Jane Smith',
  minLevelRank: 2, mustHave: ['impersonates_you'], noHostTagSignal: true,
});

// 7) Legit external newsletter that the host wrongly tagged "{Disarmed}".
//    Must stay LOW — we must not amplify the host's false positive.
t('host false-positive on legit mail', [
  'Return-Path: <news@github.com>',
  'Authentication-Results: mx.yourdomain.com; spf=pass smtp.mailfrom=github.com;',
  ' dkim=pass header.d=github.com; dmarc=pass (p=reject) header.from=github.com',
  'From: "GitHub" <noreply@github.com>',
  'To: "Jane Smith" <you@yourdomain.com>',
  'Subject: {Disarmed} [GitHub] Please read this important message',
  'Content-Type: text/plain',
  '',
  'A new sign-in to your account. View it at https://github.com/settings/security',
].join('\r\n'), {
  account: 'you@yourdomain.com', accountName: 'Jane Smith',
  maxLevelRank: 1,
});

// 8) Real-world: cPanel/webmail "your password expires" credential phish.
//    No From-domain spoof, no Authentication-Results (host stripped it), null
//    Return-Path, external .click link. Must land at least HIGH so it auto-moves.
t('webmail password-expiry phish', [
  'Return-Path: <>',
  'Received: from 190.16.83.34.bc.googleusercontent.com ([34.83.16.190])',
  '  by reynolds.example-host.com with esmtp',
  'From: Webmail Account <service@webmail.com>',
  'To: you@yourdomain.com',
  'Subject: yourdomain.com Service Account Update Requirment',
  'X-Spam-Status: No',
  'MIME-Version: 1.0',
  'Content-Type: text/html; charset="utf-8"',
  '',
  '<html><body>',
  '<p>This is an urgent Reminder that your email account Password is set to Expire in 24Hrs.</p>',
  '<p>Please update and keep the same password for you@yourdomain.com after you sign in below with your current password.</p>',
  '<a href="https://medicinalmente.click/Reaad.html#you@yourdomain.com">Keep Same Password</a>',
  '</body></html>',
].join('\r\n'), {
  account: 'you@yourdomain.com',
  minLevelRank: 2,
  mustHave: ['credential_phish_link', 'return_path_null', 'link_suspicious_tld'],
});

// 9) Legit transactional mail with credential-ish language that is DKIM-signed
//    by its own domain (even though the host stripped Authentication-Results).
//    Must stay LOW — self-signed by netflix.com recovers trust.
t('legit DKIM-signed account email', [
  'Return-Path: <bounce@netflix.com>',
  'DKIM-Signature: v=1; a=rsa-sha256; d=netflix.com; s=k1; h=from:subject; b=abc123',
  'From: Netflix <info@netflix.com>',
  'To: you@yourdomain.com',
  'Subject: Update your payment method',
  'Content-Type: text/html',
  '',
  '<p>Please update your payment details. <a href="https://www.netflix.com/account">Sign in</a></p>',
].join('\r\n'), { account: 'you@yourdomain.com', maxLevelRank: 1 });

// --- run ------------------------------------------------------------------

var pass = 0, fail = 0;
cases.forEach(function (c) {
  var r = analyzer.analyze(c.raw, {
    accountEmail: c.expect.account || ACCOUNT,
    accountName: c.expect.accountName,
  });
  var ids = r.signals.map(function (s) { return s.id; });
  var problems = [];

  if (c.expect.minLevelRank != null && r.levelRank < c.expect.minLevelRank)
    problems.push('levelRank ' + r.levelRank + ' < expected ' + c.expect.minLevelRank);
  if (c.expect.maxLevelRank != null && r.levelRank > c.expect.maxLevelRank)
    problems.push('levelRank ' + r.levelRank + ' > expected ' + c.expect.maxLevelRank);
  (c.expect.mustHave || []).forEach(function (id) {
    if (ids.indexOf(id) === -1) problems.push('missing signal "' + id + '"');
  });
  if (c.expect.noHostTagSignal && r.details.hostTags.length === 0)
    problems.push('expected host tag to be detected/stripped');

  var status = problems.length ? 'FAIL' : 'PASS';
  if (problems.length) fail++; else pass++;
  console.log('[' + status + '] ' + c.name +
    '  (score ' + r.score + ', ' + r.level + ')');
  console.log('        signals: ' + (ids.join(', ') || '(none)'));
  if (problems.length) console.log('        -> ' + problems.join('; '));
});

// --- phase-1 (Message object, no raw headers) checks ----------------------
console.log('\n--- analyzeMessage (instant, no raw headers) ---');

// Mirrors the user's screenshot: "Jane Smith" display name from a Gmail.
var msg = {
  id: 'm1', accountId: 'a1',
  from: [{ name: 'Jane Smith', email: 'janesmith@gmail.com' }],
  to: [{ name: 'Jane Smith', email: 'you@yourdomain.com' }],
  replyTo: [],
  subject: '{Definitely Spam?} test',
  body: '<p>test</p>',
  files: [],
};
var pr = analyzer.analyzeMessage(msg, { accountEmail: 'you@yourdomain.com', accountName: 'Jane Smith' });
var prIds = pr.signals.map(function (s) { return s.id; });
var p1ok = prIds.indexOf('impersonates_you') !== -1 &&
  prIds.indexOf('auth_missing') === -1 &&      // must NOT false-alarm pre-fetch
  pr.details.hostTags.length === 1;
console.log('[' + (p1ok ? 'PASS' : 'FAIL') + '] instant impersonation flagged, no auth false-alarm' +
  '  (score ' + pr.score + ', ' + pr.level + ')');
console.log('        signals: ' + (prIds.join(', ') || '(none)'));
if (!p1ok) fail++; else pass++;

// Same message, but the sender is on the always-trusted allow-list -> clean.
var pr2 = analyzer.analyzeMessage(msg, {
  accountEmail: 'you@yourdomain.com', accountName: 'Jane Smith',
  trustedSenders: ['janesmith@gmail.com'],
});
var p2ok = pr2.level === 'low' && pr2.signals.length === 0 && pr2.details.allowListed === true;
console.log('[' + (p2ok ? 'PASS' : 'FAIL') + '] allow-listed sender scores clean' +
  '  (score ' + pr2.score + ', ' + pr2.level + ', allowListed=' + pr2.details.allowListed + ')');
if (!p2ok) fail++; else pass++;

// Allow-list by bare domain should also work.
var pr3 = analyzer.analyzeMessage(msg, {
  accountEmail: 'you@yourdomain.com', accountName: 'Jane Smith',
  trustedSenders: ['gmail.com'],
});
var p3ok = pr3.level === 'low' && pr3.details.allowListed === true;
console.log('[' + (p3ok ? 'PASS' : 'FAIL') + '] allow-list by domain scores clean' +
  '  (score ' + pr3.score + ', ' + pr3.level + ')');
if (!p3ok) fail++; else pass++;

// Block-list forces very-high, overriding even an otherwise-clean message.
var prBlock = analyzer.analyzeMessage(msg, {
  accountEmail: 'you@yourdomain.com', accountName: 'Jane Smith',
  trustedSenders: ['janesmith@gmail.com'],     // also allow-listed...
  blockSenders: ['janesmith@gmail.com'],       // ...but block wins
});
var pBlockOk = prBlock.level === 'very-high' &&
  prBlock.signals.some(function (s) { return s.id === 'blocked_sender'; }) &&
  prBlock.details.blocked === true;
console.log('[' + (pBlockOk ? 'PASS' : 'FAIL') + '] block-list overrides allow-list -> very-high' +
  '  (score ' + prBlock.score + ', ' + prBlock.level + ')');
if (!pBlockOk) fail++; else pass++;

// Extra signals (e.g. from online reputation) merge into scoring.
var prExtra = analyzer.analyze([
  'Authentication-Results: mx; spf=pass dkim=pass dmarc=pass header.from=shop.example',
  'From: Shop <news@shop.example>',
  'Subject: sale',
  '', 'hi',
].join('\r\n'), {
  extraSignals: [{ id: 'domain_blocklisted', label: 'blocklisted', severity: 'high' }],
  reputationFacts: { ipListed: false, domainListed: true, spf: true, dmarc: true, listedLinks: [] },
});
var pExtraOk = prExtra.signals.some(function (s) { return s.id === 'domain_blocklisted'; }) &&
  prExtra.details.reputation && prExtra.details.reputation.domainListed === true;
console.log('[' + (pExtraOk ? 'PASS' : 'FAIL') + '] reputation signals merge into result' +
  '  (score ' + prExtra.score + ', ' + prExtra.level + ')');
if (!pExtraOk) fail++; else pass++;

// --- reputation module (mock DNS resolver) --------------------------------
console.log('\n--- reputation (mock resolver) ---');
var reputation = require('../lib/reputation');
var mock = reputation.create({
  resolvers: {
    // Pretend 6.6.6.6 and bad.tld are listed; example.com publishes SPF+DMARC.
    resolve4: function (host) {
      if (host === '6.6.6.6.zen.spamhaus.org') return Promise.resolve(['127.0.0.2']); // listed IP
      if (host === 'bad.tld.dbl.spamhaus.org') return Promise.resolve(['127.0.1.2']); // listed domain
      return Promise.resolve(null);
    },
    resolveTxt: function (host) {
      if (host === 'example.com') return Promise.resolve([['v=spf1 include:_spf.example.com ~all']]);
      if (host === '_dmarc.example.com') return Promise.resolve([['v=DMARC1; p=reject']]);
      return Promise.resolve(null);
    },
  },
  timeoutMs: 1000,
});
mock.analyze({ fromDomain: 'bad.tld', senderIp: '6.6.6.6', linkDomains: [] }).then(function (r) {
  var ids = r.signals.map(function (s) { return s.id; });
  var repOk = ids.indexOf('ip_blocklisted') !== -1 && ids.indexOf('domain_blocklisted') !== -1;
  console.log('[' + (repOk ? 'PASS' : 'FAIL') + '] mock: IP + domain blocklist hits  -> ' + (ids.join(', ') || 'none'));
  if (!repOk) fail++; else pass++;

  return mock.analyze({ fromDomain: 'example.com', senderIp: '8.8.8.8', linkDomains: [] });
}).then(function (r2) {
  var ids2 = r2.signals.map(function (s) { return s.id; });
  var cleanOk = ids2.length === 0 && r2.facts.spf === true && r2.facts.dmarc === true;
  console.log('[' + (cleanOk ? 'PASS' : 'FAIL') + '] mock: clean domain w/ SPF+DMARC -> no signals');
  if (!cleanOk) fail++; else pass++;

  console.log('\n' + pass + ' passed, ' + fail + ' failed.');
  process.exit(fail ? 1 : 0);
});
