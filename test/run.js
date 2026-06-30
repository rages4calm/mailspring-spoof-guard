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

// 10) 2026 trend: phishing page delivered as an .html attachment.
t('html-attachment phishing', [
  'Return-Path: <noreply@delivery-update.top>',
  'Authentication-Results: mx; spf=none; dkim=none; dmarc=none',
  'From: Delivery <noreply@delivery-update.top>',
  'To: you@yourdomain.com',
  'Subject: Your parcel could not be delivered',
  'Content-Type: multipart/mixed; boundary="b9"',
  '',
  '--b9',
  'Content-Type: text/plain',
  '',
  'See the attached document to reschedule.',
  '--b9',
  'Content-Type: text/html; name="Delivery_Details.html"',
  'Content-Disposition: attachment; filename="Delivery_Details.html"',
  '',
  '<html>fake login</html>',
  '--b9--',
].join('\r\n'), { account: 'you@yourdomain.com', minLevelRank: 2, mustHave: ['markup_attachment'] });

// 11) Real-world: DocuSign-impersonation document phish. Brand faked in the
//     BODY (not From), real docusign.com decoy links + a real payload link on a
//     .zw domain, no auth. Must land High/Very-high (was a false negative at 13).
t('docusign-impersonation document phish', [
  'Return-Path: <info@robrix.ca>',
  'Received: from [66.175.235.26] by reynolds.example-host.com with esmtp',
  'From: eDocSign Signature <info@robrix.ca>',
  'To: you@yourdomain.com',
  'Subject: Processed: You received a document that requires your review',
  'MIME-Version: 1.0',
  'Content-Type: text/html; charset="utf-8"',
  '',
  '<div class="hero"><div>A document has been sent for your review</div>',
  '<a href="https://foresight.co.zw/vb.php">View Document</a></div>',
  '<p>Please review the attached document at your convenience.</p>',
  '<div class="footer">Access documents on <a href="https://app.docusign.com/documents">DocuSign</a>.',
  ' About Docusign: Sign securely. Sent by Ashley Allen via Docusign.</div>',
].join('\r\n'), {
  account: 'you@yourdomain.com',
  minLevelRank: 2,
  mustHave: ['document_phish', 'brand_impersonation'],
});

// 12) Legit DocuSign (from docusign.net, DKIM-signed) must stay LOW even with
//     all the same brand/document language — sender IS the brand + signed.
t('legit docusign signed', [
  'Return-Path: <dse@docusign.net>',
  'DKIM-Signature: v=1; a=rsa-sha256; d=docusign.net; s=k1; h=from; b=zz',
  'From: DocuSign <dse@docusign.net>',
  'To: you@yourdomain.com',
  'Subject: You received a document to review and sign',
  'Content-Type: text/html',
  '',
  '<p>A document has been sent for your review. <a href="https://app.docusign.com/d">View Document</a></p>',
].join('\r\n'), { account: 'you@yourdomain.com', maxLevelRank: 1 });

// 13) Adult/male-enhancement spam, DKIM-signed by its own throwaway domain.
//     Self-signing must NOT excuse it (auth proves the domain sent it, not that
//     it's wanted). Was 0/100.
t('adult/male-enhancement spam (self-signed)', [
  'Return-Path: <6519-295-carl=yourdomain.com@mail.grness.shop>',
  'DKIM-Signature: v=1; a=rsa-sha1; c=relaxed/relaxed; s=k1; d=grness.shop; i=hardnaturally@grness.shop; b=zz',
  'From: "hardaturally" <hardnaturally@grness.shop>',
  'To: <you@yourdomain.com>',
  'Subject: Chew for 7 seconds = rock hard wood    heads up',
  'Content-Type: text/html',
  '',
  '<p>I look at men’s vitality differently now. A male performance solution — an ancient virility remedy.',
  ' <a href="http://grness.shop/x">Do this at home to IGNITE the passion</a>. Don’t tell your wife or girlfriend.</p>',
].join('\r\n'), { account: 'you@yourdomain.com', minLevelRank: 2, mustHave: ['spam_content'] });

// 14) Health "miracle cure" clickbait spam, self-signed throwaway domain.
t('miracle-cure health spam (self-signed)', [
  'Return-Path: <6523-carl=yourdomain.com@mail.nronais.shop>',
  'DKIM-Signature: v=1; a=rsa-sha1; s=k1; d=nronais.shop; i=x@nronais.shop; b=zz',
  'From: "expensivemedications" <expensivemedications@nronais.shop>',
  'To: <you@yourdomain.com>',
  'Subject: Stanford scientists reveal: This bedtime ritual reverses nerve damage overnight',
  'Content-Type: text/html',
  '',
  '<p>Big Pharma doesn’t want you to know this simple bedtime ritual that reverses nerve damage overnight.',
  ' The pharmaceutical industry tried to ban it. <a href="http://nronais.shop/v">Click here to watch the controversial video before it’s taken down</a>. Costs less than a cup of coffee.</p>',
].join('\r\n'), { account: 'you@yourdomain.com', minLevelRank: 2, mustHave: ['spam_content'] });

// 15) Spoof of the user's OWN domain with NO Authentication-Results (host strips
//     it), null Return-Path, AWS-hosted phishing page. Was only 20/100.
t('own-domain spoof, no auth header', [
  'Return-Path: <>',
  'Received: from 223.66.62.34.bc.googleusercontent.com ([34.62.66.223]) by reynolds.example-host.com',
  'From: Server Security Notification <HelpDesk@yourdomain.com>',
  'To: you@yourdomain.com',
  'Subject: Email Account Verification',
  'Content-Type: text/html',
  '',
  '<p>Mail Verification. The password of your email account will expire soon. To continue using your',
  ' you@yourdomain.com kindly re-confirm ownership below.',
  ' <a href="https://verificationnn-711613.s3.amazonaws.com/x.html?c=you@yourdomain.com">Re-confirm Password</a></p>',
].join('\r\n'), {
  account: 'you@yourdomain.com', accountName: 'You',
  minLevelRank: 3, mustHave: ['internal_spoof'],
});

// 16) Authenticated advance-fee/BEC lure: real DMARC pass, but display name
//     ("Maria Guerra") != address (avery.barnes@...). Was 0/100.
t('authenticated investment lure, name != address', [
  'Authentication-Results: mx; spf=pass smtp.mailfrom=nassaucreditx.info;',
  ' dkim=pass header.d=nassaucreditx.info; dmarc=pass header.from=nassaucreditx.info',
  'DKIM-Signature: v=1; a=rsa-sha256; d=nassaucreditx.info; s=s1; b=zz',
  'From: Maria Guerra <avery.barnes@nassaucreditx.info>',
  'To: you@yourdomain.com',
  'Subject: Lining up resources for a possible private family office investment',
  'Content-Type: text/plain',
  '',
  'Hi, We work with businesses looking to attract private capital of $2-$35M from single-family offices.',
  ' Are you open to a conversation? Maria Guerra',
].join('\r\n'), { account: 'you@yourdomain.com', minLevelRank: 1, mustHave: ['advance_fee_lure'] });

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
