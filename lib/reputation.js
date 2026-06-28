// reputation.js
// Opt-in online reputation checks over plain DNS — no API keys, and only the
// sending IP / domains are ever sent to the blocklist (never your email body).
//
// Checks:
//   - Spamhaus ZEN on the sending IP            (ip.zen.spamhaus.org)
//   - Spamhaus DBL on the From + link domains   (domain.dbl.spamhaus.org)
//   - Whether the From domain publishes SPF / DMARC records at all
//
// The resolver is injectable so the parsing/logic is unit-testable offline.
// Results are cached per value for the session, and lookups are time-limited so
// a slow DNS server can never hang the UI.

'use strict';

var domainsUtil = require('./analyzer/domains');

function defaultResolvers() {
  var dns = require('dns');
  return {
    resolve4: function (host) {
      return new Promise(function (resolve) {
        dns.resolve4(host, function (err, addrs) { resolve(err ? null : addrs); });
      });
    },
    resolveTxt: function (host) {
      return new Promise(function (resolve) {
        dns.resolveTxt(host, function (err, recs) { resolve(err ? null : recs); });
      });
    },
  };
}

function withTimeout(promise, ms) {
  return new Promise(function (resolve) {
    var done = false;
    var t = setTimeout(function () { if (!done) { done = true; resolve(null); } }, ms);
    promise.then(function (v) { if (!done) { done = true; clearTimeout(t); resolve(v); } },
      function () { if (!done) { done = true; clearTimeout(t); resolve(null); } });
  });
}

function isPublicIPv4(ip) {
  if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
  var p = ip.split('.').map(Number);
  if (p[0] === 10) return false;
  if (p[0] === 127) return false;
  if (p[0] === 192 && p[1] === 168) return false;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return false;
  if (p[0] === 169 && p[1] === 254) return false;
  if (p[0] === 0 || p[0] >= 224) return false;
  return true;
}

function reverseIp(ip) {
  return ip.split('.').reverse().join('.');
}

// A DBL/ZEN "listed" answer is in 127.0.0.x / 127.0.1.x. Codes 127.255.255.x
// mean the query itself was rejected (open resolver / rate limit) — NOT a hit.
function isListedAnswer(addrs) {
  if (!addrs || !addrs.length) return false;
  return addrs.some(function (a) {
    var p = a.split('.').map(Number);
    return p[0] === 127 && p[1] === 0 && (p[2] === 0 || p[2] === 1) && p[3] < 255;
  });
}

function txtHas(records, prefix) {
  if (!records) return false;
  return records.some(function (chunks) {
    var joined = Array.isArray(chunks) ? chunks.join('') : String(chunks);
    return joined.toLowerCase().indexOf(prefix) === 0;
  });
}

// Factory so tests can inject resolvers. Pass nothing for real DNS.
function create(opts) {
  opts = opts || {};
  var R = opts.resolvers || defaultResolvers();
  var timeout = opts.timeoutMs || 4000;
  var cache = {}; // key -> Promise

  function once(key, fn) {
    if (!cache[key]) cache[key] = fn();
    return cache[key];
  }

  function ipListed(ip) {
    if (!isPublicIPv4(ip)) return Promise.resolve(false);
    return once('zen:' + ip, function () {
      return withTimeout(R.resolve4(reverseIp(ip) + '.zen.spamhaus.org'), timeout)
        .then(isListedAnswer);
    });
  }

  function domainListed(domain) {
    if (!domain) return Promise.resolve(false);
    return once('dbl:' + domain, function () {
      return withTimeout(R.resolve4(domain + '.dbl.spamhaus.org'), timeout)
        .then(isListedAnswer);
    });
  }

  function hasSpf(domain) {
    if (!domain) return Promise.resolve(false);
    return once('spf:' + domain, function () {
      return withTimeout(R.resolveTxt(domain), timeout)
        .then(function (recs) { return txtHas(recs, 'v=spf1'); });
    });
  }

  function hasDmarc(domain) {
    if (!domain) return Promise.resolve(false);
    return once('dmarc:' + domain, function () {
      return withTimeout(R.resolveTxt('_dmarc.' + domain), timeout)
        .then(function (recs) { return txtHas(recs, 'v=dmarc1'); });
    });
  }

  // Main entry: takes facts pulled from a parsed message, returns
  // { signals: [...], facts: {...} }. `linkDomains` is de-duplicated/capped.
  function analyze(input) {
    input = input || {};
    var fromDomain = input.fromDomain || null;
    var ip = input.senderIp || null;
    var links = {};
    (input.linkDomains || []).forEach(function (d) {
      if (d) links[domainsUtil.baseDomain(d.replace(/^www\./, ''))] = true;
    });
    var linkDomains = Object.keys(links).slice(0, 8);

    var jobs = [
      ipListed(ip).then(function (v) { return { k: 'ipListed', v: v }; }),
      domainListed(fromDomain).then(function (v) { return { k: 'domainListed', v: v }; }),
      hasSpf(fromDomain).then(function (v) { return { k: 'spf', v: v }; }),
      hasDmarc(fromDomain).then(function (v) { return { k: 'dmarc', v: v }; }),
    ];
    linkDomains.forEach(function (d) {
      jobs.push(domainListed(d).then(function (v) { return { k: 'link', d: d, v: v }; }));
    });

    return Promise.all(jobs).then(function (results) {
      var facts = { ipListed: false, domainListed: false, spf: null, dmarc: null, listedLinks: [] };
      results.forEach(function (r) {
        if (r.k === 'ipListed') facts.ipListed = r.v;
        else if (r.k === 'domainListed') facts.domainListed = r.v;
        else if (r.k === 'spf') facts.spf = r.v;
        else if (r.k === 'dmarc') facts.dmarc = r.v;
        else if (r.k === 'link' && r.v) facts.listedLinks.push(r.d);
      });

      var signals = [];
      if (facts.ipListed) {
        signals.push({ id: 'ip_blocklisted', label: 'Sending server IP is on the Spamhaus blocklist (' + ip + ')', severity: 'high' });
      }
      if (facts.domainListed) {
        signals.push({ id: 'domain_blocklisted', label: 'Sender domain is on the Spamhaus domain blocklist (' + fromDomain + ')', severity: 'high' });
      }
      if (facts.listedLinks.length) {
        signals.push({ id: 'link_blocklisted', label: 'A linked domain is blocklisted: ' + facts.listedLinks.join(', '), severity: 'high' });
      }
      // "No SPF/DMARC published" is a weak signal — many small legit domains lack
      // it — so it's low severity and only noted when we got a definitive answer.
      if (fromDomain && facts.spf === false && facts.dmarc === false) {
        signals.push({ id: 'no_auth_records', label: 'Sender domain publishes neither SPF nor DMARC records', severity: 'low' });
      }

      return { signals: signals, facts: facts };
    });
  }

  return { analyze: analyze, ipListed: ipListed, domainListed: domainListed, hasSpf: hasSpf, hasDmarc: hasDmarc };
}

module.exports = {
  create: create,
  isPublicIPv4: isPublicIPv4,
  reverseIp: reverseIp,
  isListedAnswer: isListedAnswer,
  txtHas: txtHas,
};
