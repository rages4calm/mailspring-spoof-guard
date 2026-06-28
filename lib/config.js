// config.js
// Thin wrapper over Mailspring's AppEnv.config for the plugin's settings.
// Keys live under the "spoofGuard.*" namespace. Only required by Mailspring-side
// code (not the analyzer), so it's safe to reference the global AppEnv here.

'use strict';

function cfg() {
  // AppEnv is a renderer global in Mailspring.
  return (typeof AppEnv !== 'undefined') ? AppEnv.config : null;
}

function getRaw(key, def) {
  try {
    var c = cfg();
    if (!c) return def;
    var v = c.get('spoofGuard.' + key);
    return (v === undefined || v === null) ? def : v;
  } catch (e) {
    return def;
  }
}

function set(key, val) {
  try {
    var c = cfg();
    if (c) c.set('spoofGuard.' + key, val);
  } catch (e) { /* ignore */ }
}

function observe(cb) {
  try {
    var c = cfg();
    if (c) return c.observe('spoofGuard', cb);
  } catch (e) { /* ignore */ }
  return { dispose: function () {} };
}

// Splits a textarea value into a clean, lower-cased list.
function parseList(text) {
  return String(text || '')
    .split(/[\s,;]+/)
    .map(function (s) { return s.trim().toLowerCase(); })
    .filter(Boolean);
}

// Normalised settings object used by the rest of the plugin.
function get() {
  return {
    enabled: getRaw('enabled', true) !== false,
    trustedSenders: parseList(getRaw('trustedSendersText', '')),
    blockSenders: parseList(getRaw('blockSendersText', '')),
    myDomains: parseList(getRaw('myDomainsText', '')),
    autoSpam: getRaw('autoSpam', false) === true,
    autoSpamLevel: getRaw('autoSpamLevel', 'very-high'),
    deepScan: getRaw('deepScan', true) !== false,
    onlineChecks: getRaw('onlineChecks', false) === true,
  };
}

var LEVEL_SCORE = { 'suspicious': 20, 'high': 45, 'very-high': 70 };
function thresholdScore(level) {
  return LEVEL_SCORE[level] || 70;
}

module.exports = {
  get: get,
  getRaw: getRaw,
  set: set,
  observe: observe,
  parseList: parseList,
  thresholdScore: thresholdScore,
};
