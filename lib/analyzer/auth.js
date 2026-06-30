// auth.js
// Parses the Authentication-Results / ARC-Authentication-Results headers that
// the *receiving* server (your cPanel/Exim, Gmail, Outlook, etc.) stamps onto
// inbound mail. These already contain the verdict of SPF, DKIM and DMARC checks,
// so for v1 we trust them rather than re-doing DNS lookups in the client.
//
// We also compute "alignment": does the domain that actually passed DKIM/SPF
// match the visible From: domain? Misalignment is the core of real spoofing.

'use strict';

var mime = require('./mime');
var domains = require('./domains');

// Reads the *last* token for a mechanism across all auth blocks, but treats any
// "pass" anywhere as a pass (multiple Authentication-Results lines can appear).
function readMechanism(blocks, mech) {
  var re = new RegExp('(?:^|[\\s;])' + mech + '=([a-z0-9_-]+)', 'gi');
  var sawPass = false;
  var last = 'none';
  blocks.forEach(function (block) {
    var m;
    re.lastIndex = 0;
    while ((m = re.exec(block)) !== null) {
      var v = m[1].toLowerCase();
      last = v;
      if (v === 'pass') sawPass = true;
    }
  });
  return sawPass ? 'pass' : last;
}

function firstMatch(blocks, re) {
  for (var i = 0; i < blocks.length; i++) {
    var m = blocks[i].match(re);
    if (m) return m[1].toLowerCase();
  }
  return null;
}

// analyzeAuth(headers, fromDomain) -> structured auth verdict + alignment
function analyzeAuth(headers, fromDomain) {
  var blocks = []
    .concat(mime.getHeaderValues(headers, 'Authentication-Results'))
    .concat(mime.getHeaderValues(headers, 'ARC-Authentication-Results'));

  var present = blocks.length > 0;

  var spf = present ? readMechanism(blocks, 'spf') : 'none';
  var dkim = present ? readMechanism(blocks, 'dkim') : 'none';
  var dmarc = present ? readMechanism(blocks, 'dmarc') : 'none';

  // Domains that actually authenticated.
  var dkimDomain = firstMatch(blocks, /header\.d=([a-z0-9.-]+)/i);
  var spfMailFrom = firstMatch(blocks, /smtp\.mailfrom=([^\s;]+)/i);
  var spfDomain = spfMailFrom ? domains.extractDomain('@' + spfMailFrom.replace(/^.*@/, '')) || spfMailFrom : null;
  var dmarcPolicy = firstMatch(blocks, /p=([a-z]+)/i);

  // Alignment: the DKIM/SPF domain shares the From: organizational domain.
  var dkimAligned = dkimDomain && fromDomain ? domains.sameBaseDomain(dkimDomain, fromDomain) : false;
  var spfAligned = spfDomain && fromDomain ? domains.sameBaseDomain(spfDomain, fromDomain) : false;

  // DMARC effectively passes when a pass verdict is present, OR when we can see
  // an aligned DKIM/SPF pass ourselves.
  var dmarcPass = dmarc === 'pass' || (dkim === 'pass' && dkimAligned) || (spf === 'pass' && spfAligned);

  // ARC seal (trusted forwarding chain) — softens SPF/DKIM breakage from lists.
  var arcSeal = mime.getHeaderValues(headers, 'ARC-Seal')[0] || '';
  var arcPass = /cv=pass/i.test(arcSeal);

  // Does the message carry its OWN DKIM-Signature aligned to the From domain?
  // We don't verify the crypto, but legit brand/transactional mail is signed by
  // its own domain while most phishing isn't signed at all. This lets us recover
  // a trust signal on mail servers that STRIP the Authentication-Results header.
  // NOTE: used only to relax content/false-positive checks (e.g. credential
  // language) — never to relax spoof detection, which keeps using `trusted`.
  var dkimSigs = mime.getHeaderValues(headers, 'DKIM-Signature');
  var sigDomains = dkimSigs.map(function (s) {
    var m = s.match(/(?:^|[;\s])d=([a-z0-9.-]+)/i);
    return m ? m[1].toLowerCase() : null;
  }).filter(Boolean);
  var selfSigned = !!fromDomain && sigDomains.some(function (d) {
    return domains.sameBaseDomain(d, fromDomain);
  });
  // Deprecated rsa-sha1 DKIM is now rare in legit mail but common in throwaway
  // spam infrastructure — a weak corroborating signal.
  var dkimWeak = dkimSigs.some(function (s) { return /a=\s*rsa-sha1\b/i.test(s); });

  return {
    present: present,
    spf: spf,
    dkim: dkim,
    dmarc: dmarc,
    dmarcPolicy: dmarcPolicy || 'none',
    dkimDomain: dkimDomain,
    spfDomain: spfDomain,
    dkimAligned: dkimAligned,
    spfAligned: spfAligned,
    aligned: dkimAligned || spfAligned,
    dmarcPass: dmarcPass,
    arcPass: arcPass,
    selfSigned: selfSigned,
    dkimWeak: dkimWeak,
    // "authenticated and aligned" — the strongest trust signal we can derive.
    trusted: dmarcPass && (dkimAligned || spfAligned),
    // A softer trust signal that survives a stripped Authentication-Results
    // header: verified-and-aligned OR the sender signed for its own domain.
    looksLegit: (dmarcPass && (dkimAligned || spfAligned)) || selfSigned,
  };
}

module.exports = { analyzeAuth: analyzeAuth };
