// heuristics-headers.js
// Header-based spoof signals. Each check pushes a signal {id, label, severity}.
// Weights live in scoring.js so all tuning is in one place.

'use strict';

var mime = require('./mime');
var domains = require('./domains');

function headerSignals(headers, ctx) {
  var signals = [];
  var auth = ctx.auth;

  var fromDomain = ctx.fromDomain;
  var replyDomain = ctx.replyDomain;
  var returnDomain = ctx.returnDomain;

  // The set of domains we consider "ours" (account domain + any user-trusted).
  var ours = ctx.trustedDomains || [];
  var claimsOurs = fromDomain && ours.some(function (d) {
    return domains.sameBaseDomain(fromDomain, d);
  });

  // --- the big one: someone claiming to be your own domain --------------------
  // From: looks like one of your domains, but the message did NOT authenticate
  // as it (DMARC/aligned pass) AND did NOT carry an aligned DKIM-Signature for
  // it. Real mail from your domain is always one or the other — so if it's
  // neither, it's a spoof. This deliberately works even when the receiving host
  // stripped the Authentication-Results header (as the user's host does).
  if (claimsOurs && !auth.trusted && !auth.selfSigned) {
    signals.push({
      id: 'internal_spoof',
      label: 'Claims to be from your own domain but is not authenticated or signed as it',
      severity: 'critical',
    });
  }

  // --- authentication verdicts ------------------------------------------------
  if (!auth.present) {
    // Don't warn about "no auth results" while we're still in the instant phase
    // before the raw headers have been fetched — that would be a false alarm.
    if (!ctx.authPending) {
      signals.push({
        id: 'auth_missing',
        label: 'No authentication results present — sender could not be verified',
        severity: 'info',
      });
    }
  } else {
    if (auth.dmarc === 'fail') {
      signals.push({ id: 'dmarc_fail', label: 'DMARC failed', severity: 'high' });
    }
    if (auth.dkim === 'fail' || auth.dkim === 'invalid' || auth.dkim === 'permerror') {
      signals.push({ id: 'dkim_fail', label: 'DKIM signature invalid or failed', severity: 'high' });
    }
    if (auth.spf === 'fail') {
      signals.push({ id: 'spf_fail', label: 'SPF failed (sender not authorized)', severity: 'high' });
    } else if (auth.spf === 'softfail') {
      signals.push({ id: 'spf_softfail', label: 'SPF soft-failed', severity: 'medium' });
    }
    // From: domain is not the domain that authenticated, and DMARC didn't pass.
    if (!auth.dmarcPass && !auth.aligned && fromDomain && (auth.dkimDomain || auth.spfDomain)) {
      signals.push({
        id: 'from_unaligned',
        label: 'Visible sender domain does not match the authenticated sending domain',
        severity: 'high',
      });
    }
  }

  // --- Reply-To / Return-Path mismatches -------------------------------------
  if (replyDomain && fromDomain && !domains.sameBaseDomain(replyDomain, fromDomain)) {
    signals.push({
      id: 'reply_to_mismatch',
      label: 'Reply-To uses a different domain (' + replyDomain + ') than From',
      severity: 'medium',
    });
  }
  if (returnDomain && fromDomain && !domains.sameBaseDomain(returnDomain, fromDomain)) {
    signals.push({
      id: 'return_path_mismatch',
      label: 'Return-Path domain (' + returnDomain + ') differs from From',
      severity: 'medium',
    });
  }
  // A null Return-Path (<>) on a normal, content-bearing message is a spam/phish
  // tell. Legit null-senders (bounces, some no-reply) are usually authenticated,
  // so we only flag it when the message isn't authenticated+aligned.
  if (ctx.returnPathNull && !auth.looksLegit) {
    signals.push({
      id: 'return_path_null',
      label: 'Empty Return-Path (<>) — typical of bulk spam, not a real reply address',
      severity: 'medium',
    });
  }

  // --- impersonating YOU / the recipient from an unrelated free-mail address --
  // e.g. display name "Jane Smith" but the real sender is randomguy@gmail.com.
  // The visible name matches the account owner (or the recipient) yet the mail
  // comes from a consumer mailbox that isn't one of our domains.
  var displayName = ctx.displayName;
  if (displayName && fromDomain && !claimsOurs) {
    var matchesYou = domains.namesMatch(displayName, ctx.accountName) ||
      domains.namesMatch(displayName, ctx.recipientName);
    if (matchesYou && domains.isFreemail(fromDomain)) {
      signals.push({
        id: 'impersonates_you',
        label: 'Uses your name but was sent from an unrelated free-mail address (' + fromDomain + ')',
        severity: 'high',
      });
    }
  }

  // --- homoglyph / mixed-script display name ---------------------------------
  if (domains.looksHomoglyph(displayName) || domains.looksHomoglyph(ctx.subject)) {
    signals.push({
      id: 'homoglyph_name',
      label: 'Sender name or subject mixes look-alike Unicode characters (homoglyph spoof)',
      severity: 'high',
    });
  }

  // --- BEC: corporate-looking From, but replies go to a free-mail account -----
  if (fromDomain && replyDomain && !domains.isFreemail(fromDomain) &&
      domains.isFreemail(replyDomain) && !domains.sameBaseDomain(replyDomain, fromDomain)) {
    signals.push({
      id: 'reply_to_freemail',
      label: 'Replies would go to a personal free-mail address (' + replyDomain + '), not the sender domain',
      severity: 'high',
    });
  }

  // --- display-name impersonation --------------------------------------------
  if (displayName) {
    // A display name that literally embeds an email address whose domain differs.
    var nameDomain = domains.extractDomain(displayName);
    if (nameDomain && fromDomain && !domains.sameBaseDomain(nameDomain, fromDomain)) {
      signals.push({
        id: 'display_name_email_spoof',
        label: 'Display name shows "' + nameDomain + '" but the real sender is ' + fromDomain,
        severity: 'high',
      });
    }
    // A display name claiming a well-known brand the sending domain isn't.
    var brand = domains.claimedBrand(displayName);
    if (brand && fromDomain && domains.baseDomain(fromDomain).indexOf(brand) === -1) {
      signals.push({
        id: 'display_name_brand',
        label: 'Display name impersonates "' + brand + '" but sender domain is ' + fromDomain,
        severity: 'high',
      });
    }
  }

  // Deprecated rsa-sha1 DKIM — weak corroborating signal (throwaway spam infra).
  if (auth.dkimWeak) {
    signals.push({
      id: 'weak_dkim',
      label: 'Message signed with deprecated rsa-sha1 DKIM (common in spam infrastructure)',
      severity: 'low',
    });
  }

  // --- look-alike / suspicious sending domain --------------------------------
  if (domains.isPunycode(fromDomain)) {
    signals.push({
      id: 'punycode_from',
      label: 'Sender domain uses punycode/IDN (possible homograph spoof): ' + fromDomain,
      severity: 'high',
    });
  }
  if (domains.suspiciousTld(fromDomain)) {
    signals.push({
      id: 'suspicious_tld',
      label: 'Sender uses a frequently-abused top-level domain: ' + fromDomain,
      severity: 'medium',
    });
  }
  // Look-alike of one of our trusted domains (paypa1 vs paypal, etc.)
  if (fromDomain && !claimsOurs) {
    var fb = domains.baseDomain(fromDomain);
    ours.forEach(function (d) {
      var ob = domains.baseDomain(d);
      var dist = domains.levenshtein(fb, ob);
      if (dist > 0 && dist <= 2 && ob.length >= 5) {
        signals.push({
          id: 'lookalike_domain',
          label: 'Sender domain "' + fb + '" closely resembles your domain "' + ob + '"',
          severity: 'high',
        });
      }
    });
  }

  // --- routing sanity ---------------------------------------------------------
  var received = mime.getHeaderValues(headers, 'Received');
  if (received.length === 0 && auth.present === false && !ctx.authPending) {
    signals.push({
      id: 'no_received',
      label: 'Message has no Received headers (unusual routing)',
      severity: 'low',
    });
  }

  return signals;
}

module.exports = { headerSignals: headerSignals };
