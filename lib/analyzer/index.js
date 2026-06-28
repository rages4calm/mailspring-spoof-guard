// index.js
// Top-level analyzer. Pure JavaScript with no Mailspring dependency so it can
// be unit-tested in plain Node (see test/run.js).
//
// Two entry points:
//   analyze(rawSource, options)        -> full analysis incl. SPF/DKIM/DMARC
//   analyzeMessage(messageLike, options) -> analysis from a Mailspring Message
//                                           object alone (no raw headers yet)
//
// The plugin uses analyzeMessage() for an INSTANT badge (so it always shows,
// even if fetching the raw source fails on this server), then upgrades to
// analyze() once the raw .eml is available.
//
// Result shape:
//   { score, level, signals:[{id,label,severity,points}], summary,
//     recommendation, details:{...} }

'use strict';

var mime = require('./mime');
var domains = require('./domains');
var authMod = require('./auth');
var headerH = require('./heuristics-headers');
var contentH = require('./heuristics-content');
var scoring = require('./scoring');

function firstValue(headers, name) {
  var vals = mime.getHeaderValues(headers, name);
  return vals.length ? vals[0] : '';
}

// Best-effort "where did this really come from" for display only.
function mailRoute(headers) {
  var received = mime.getHeaderValues(headers, 'Received');
  if (!received.length) return { origin: null, via: null };
  function common(host) {
    if (!host) return host;
    if (/google\.com|gmail\.com/.test(host)) return 'Google Workspace';
    if (/outlook\.com|protection\.outlook\.com/.test(host)) return 'Microsoft 365';
    if (/amazonses\.com/.test(host)) return 'Amazon SES';
    if (/sendgrid\.net/.test(host)) return 'SendGrid';
    if (/mailgun\.org/.test(host)) return 'Mailgun';
    return host;
  }
  var via = (received[0].match(/from\s+([a-z0-9.-]+)/i) || [])[1];
  var origin = null;
  for (var i = received.length - 1; i >= 0; i--) {
    var m = received[i].match(/helo=([a-z0-9.-]+)/i) || received[i].match(/from\s+([a-z0-9.-]+)/i);
    if (m) { origin = m[1].toLowerCase(); break; }
  }
  return { origin: common(origin), via: common(via && via.toLowerCase()) };
}

// Strips host/gateway-injected tags from the start of a subject, e.g.
// "{Disarmed} {Definitely Spam?} Real subject". The user's host (MailScanner)
// adds these and they are frequently wrong, so we remove them before analysis
// and surface them as zero-weight informational context instead.
function stripHostTags(subject) {
  var tags = [];
  var s = String(subject || '');
  var re = /^\s*(?:\{([^}]*)\}|\[((?:SPAM|DISARMED|SUSPECTED SPAM|EXTERNAL)[^\]]*)\])\s*/i;
  var m;
  while ((m = s.match(re))) {
    tags.push((m[1] || m[2]).trim());
    s = s.slice(m[0].length);
  }
  return { hostTags: tags, cleanSubject: s.trim() };
}

// First public sending IP from the Received chain (for reputation lookups).
function extractSenderIp(headers) {
  var received = mime.getHeaderValues(headers, 'Received');
  for (var i = 0; i < received.length; i++) {
    var ms = received[i].match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g);
    if (!ms) continue;
    for (var j = 0; j < ms.length; j++) {
      var ip = ms[j];
      var p = ip.split('.').map(Number);
      var priv = p[0] === 10 || p[0] === 127 ||
        (p[0] === 192 && p[1] === 168) ||
        (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
        (p[0] === 169 && p[1] === 254) || p[0] === 0 || p[0] >= 224;
      if (!priv) return ip;
    }
  }
  return null;
}

// Distinct link domains from the body (for blocklist lookups).
function extractLinkDomains(parts) {
  var set = {};
  var anchors = contentH.extractAnchors(parts.html || '');
  anchors.forEach(function (a) {
    var d = contentH.urlDomain(a.href);
    if (d) set[d] = true;
  });
  var bare = (parts.text || '').match(/\bhttps?:\/\/[^\s"'<>)]+/gi) || [];
  bare.forEach(function (u) {
    var d = contentH.urlDomain(u);
    if (d) set[d] = true;
  });
  return Object.keys(set);
}

function matchSenderList(list, fromEmail, fromDomain) {
  return (list || []).some(function (a) {
    if (!a) return false;
    if (a.indexOf('@') !== -1) return a === fromEmail;
    return fromDomain && (fromDomain === a || domains.baseDomain(fromDomain) === domains.baseDomain(a));
  });
}

function buildTrustedDomains(options) {
  var set = {};
  function add(d) {
    var dom = domains.extractDomain('@' + String(d).replace(/^.*@/, '')) || String(d).toLowerCase();
    if (dom) set[dom] = true;
  }
  if (options.accountEmail) add(options.accountEmail);
  (options.trustedDomains || []).forEach(add);
  return Object.keys(set);
}

// Core pipeline shared by both entry points.
// `headers` is a header map, `parts` is { text, html, attachments }.
// options.authPending=true means "we haven't fetched raw headers yet" — so we
// suppress the "no authentication results" / "no Received" signals (they'd be
// false alarms during the brief instant before enrichment).
function analyzeCore(headers, parts, options) {
  options = options || {};

  var from = firstValue(headers, 'From');
  var fromDomain = domains.extractDomain(from);
  var displayName = domains.extractDisplayName(from);
  var rawSubject = firstValue(headers, 'Subject');
  var tagInfo = stripHostTags(rawSubject);
  var subject = tagInfo.cleanSubject;
  var to = firstValue(headers, 'To');
  var recipientName = domains.extractDisplayName(to);
  var replyDomain = domains.extractDomain(firstValue(headers, 'Reply-To'));
  var returnVals = mime.getHeaderValues(headers, 'Return-Path');
  var returnDomain = domains.extractDomain(returnVals[0] || '');
  var returnPathNull = returnVals.length > 0 && returnVals.some(function (v) {
    return v.replace(/[<>\s]/g, '') === '';
  });

  var trustedDomains = buildTrustedDomains(options);
  var auth = authMod.analyzeAuth(headers, fromDomain);

  // Block-list wins over everything: mail from these senders is always treated
  // as spam. Allow-list ("always trusted") applies only when not blocked.
  var fromEmail = domains.extractEmail(from);
  var blocked = matchSenderList(options.blockSenders, fromEmail, fromDomain);
  var allowListed = !blocked && matchSenderList(options.trustedSenders, fromEmail, fromDomain);

  var ctx = {
    auth: auth,
    from: from,
    fromDomain: fromDomain,
    displayName: displayName,
    subject: subject,
    accountName: options.accountName || null,
    recipientName: recipientName,
    replyDomain: replyDomain,
    returnDomain: returnDomain,
    returnPathNull: returnPathNull,
    trustedDomains: trustedDomains,
    authPending: !!options.authPending,
  };

  // Allow-listed senders skip all heuristics and score clean. Otherwise combine
  // header + content signals, any externally-supplied signals (e.g. online
  // reputation), and a block-list override.
  var signals;
  if (allowListed) {
    signals = [];
  } else {
    signals = []
      .concat(headerH.headerSignals(headers, ctx))
      .concat(contentH.contentSignals(parts, ctx))
      .concat(options.extraSignals || []);
    if (blocked) {
      signals.unshift({
        id: 'blocked_sender',
        label: 'Sender is on your block list',
        severity: 'critical',
      });
    }
  }

  var result = scoring.score(signals, auth);

  var authStatus = options.authPending ? 'pending' : (auth.present ? 'ok' : 'unavailable');

  result.details = {
    from: from,
    fromDomain: fromDomain,
    displayName: displayName,
    subject: subject,
    hostTags: tagInfo.hostTags,
    replyDomain: replyDomain,
    returnDomain: returnDomain,
    accountDomain: trustedDomains[0] || null,
    allowListed: allowListed,
    blocked: blocked,
    senderIp: extractSenderIp(headers),
    linkDomains: extractLinkDomains(parts),
    reputation: options.reputationFacts || null,
    authStatus: authStatus,
    auth: {
      present: auth.present,
      spf: auth.spf,
      dkim: auth.dkim,
      dmarc: auth.dmarc,
      dmarcPolicy: auth.dmarcPolicy,
      aligned: auth.aligned,
      dmarcPass: auth.dmarcPass,
      arcPass: auth.arcPass,
      trusted: auth.trusted,
    },
    route: mailRoute(headers),
    attachments: parts.attachments,
  };

  return result;
}

// Full analysis from the raw RFC822 source.
function analyze(rawSource, options) {
  var parts = mime.parseMessage(rawSource);
  return analyzeCore(parts.headers, parts, options || {});
}

// Instant analysis from a Mailspring Message model (no raw headers available).
// Expects an object shaped like:
//   { from:[{name,email}], to:[...], replyTo:[...], subject, body(html), files:[{filename}] }
function analyzeMessage(message, options) {
  options = Object.assign({ authPending: true }, options || {});
  message = message || {};

  function contactStr(list) {
    var c = (list && list[0]) || null;
    if (!c) return '';
    var name = c.name || c.displayName || '';
    var email = c.email || '';
    return name ? '"' + name + '" <' + email + '>' : email;
  }

  var headers = {
    From: [contactStr(message.from)],
    To: [contactStr(message.to)],
    'Reply-To': [contactStr(message.replyTo)],
    Subject: [message.subject || ''],
  };

  var html = message.body || '';
  var parts = {
    headers: headers,
    html: html,
    text: html ? mime.htmlToText(html) : (message.snippet || ''),
    attachments: (message.files || []).map(function (f) {
      return f.filename || f.fileName || f.name || '';
    }).filter(Boolean),
  };

  return analyzeCore(headers, parts, options);
}

module.exports = {
  analyze: analyze,
  analyzeMessage: analyzeMessage,
};
