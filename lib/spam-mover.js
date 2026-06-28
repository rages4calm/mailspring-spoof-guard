// spam-mover.js
// Optional, opt-in auto-move of high-risk mail to the Spam folder, plus a
// manual "scan inbox now" sweep.
//
// Triggers (all gated by settings):
//   - maybeMove(): called by the badge after it analyzes a message you open.
//   - background DatabaseStore listener: scans NEW inbox mail as it arrives,
//     including an optional deep pass that fetches full headers (SPF/DKIM/DMARC).
//   - scanInboxNow(): a manual, user-initiated sweep of existing inbox mail.
//
// Safety: only acts when enabled; never touches allow-listed senders; only mail
// currently in the Inbox (never Sent/Spam/Trash); a per-message guard prevents
// repeats. If anything is uncertain, it does nothing.

'use strict';

var mailspring = require('mailspring-exports');
var Actions = mailspring.Actions;
var TaskFactory = mailspring.TaskFactory;
var TaskQueue = mailspring.TaskQueue;
var DatabaseStore = mailspring.DatabaseStore;
var CategoryStore = mailspring.CategoryStore;
var AccountStore = mailspring.AccountStore;
var Thread = mailspring.Thread;
var Message = mailspring.Message;
var GetMessageRFC2822Task = mailspring.GetMessageRFC2822Task;

var analyzer = require('./analyzer');
var config = require('./config');
var reputation = require('./reputation').create(); // shared session cache

var LEVEL_RANK = { 'low': 0, 'suspicious': 1, 'high': 2, 'very-high': 3 };
var START = Date.now();
var processed = {};       // message.id -> true (already decided)
var unsubscribe = null;

// --- helpers ---------------------------------------------------------------

function threadHasRole(thread, role) {
  try {
    return (thread.categories || []).some(function (c) { return c && c.role === role; });
  } catch (e) {
    return false;
  }
}

function optionsForAccount(accountId) {
  var c = config.get();
  var acct = null;
  try { acct = AccountStore.accountForId(accountId); } catch (e) { /* ignore */ }
  return {
    accountEmail: acct ? acct.emailAddress : null,
    accountName: acct ? acct.name : null,
    trustedSenders: c.trustedSenders,
    blockSenders: c.blockSenders,
    trustedDomains: c.myDomains,
  };
}

function moveToSpam(thread, message, result) {
  try {
    if (!CategoryStore.getSpamCategory(message.accountId)) return false; // no Spam folder
    var tasks = TaskFactory.tasksForMarkingAsSpam({ threads: [thread], source: 'SpoofGuard' });
    if (tasks && tasks.length) {
      Actions.queueTasks(tasks);
      console.log('[SpoofGuard] moved to Spam (risk ' + result.score + '):', message.id);
      return true;
    }
  } catch (e) {
    console.error('[SpoofGuard] moveToSpam', e);
  }
  return false;
}

// Shared decision core. requireAutoSpam=false lets the manual sweep run even
// when the background auto-move toggle is off.
function decideAndMove(message, thread, result, requireAutoSpam) {
  try {
    var c = config.get();
    if (!c.enabled) return false;
    if (requireAutoSpam && !c.autoSpam) return false;
    if (!message || !thread || !result) return false;
    if (processed[message.id]) return false;
    if (result.details && result.details.allowListed) return false;
    var rank = (result.levelRank != null) ? result.levelRank : (LEVEL_RANK[result.level] || 0);
    if (rank < LEVEL_RANK[c.autoSpamLevel]) return false;
    if (!threadHasRole(thread, 'inbox')) return false;
    if (threadHasRole(thread, 'spam') || threadHasRole(thread, 'trash')) return false;
    processed[message.id] = true;
    return moveToSpam(thread, message, result);
  } catch (e) {
    console.error('[SpoofGuard] decideAndMove', e);
    return false;
  }
}

// Called by the badge (on-view). Requires the auto-move toggle.
function maybeMove(message, thread, result) {
  decideAndMove(message, thread, result, true);
}

// --- raw-header fetch (shared) ---------------------------------------------

function fetchRawSource(message) {
  return new Promise(function (resolve, reject) {
    try {
      var fs = require('fs');
      var os = require('os');
      var path = require('path');
      var filepath = path.join(os.tmpdir(), 'spoofguard_bg_' + message.id + '.eml');
      var task = new GetMessageRFC2822Task({
        messageId: message.id, accountId: message.accountId, filepath: filepath,
      });
      Actions.queueTask(task);
      TaskQueue.waitForPerformRemote(task).then(function () {
        try {
          var raw = fs.readFileSync(filepath, 'utf8');
          try { fs.unlinkSync(filepath); } catch (e) { /* best effort */ }
          resolve(raw);
        } catch (e) { reject(e); }
      }).catch(reject);
    } catch (e) { reject(e); }
  });
}

// --- background deep-scan queue (throttled, one at a time) ------------------

var deepQueue = [];
var deepQueued = {};
var deepBusy = false;

function enqueueDeep(message) {
  if (!GetMessageRFC2822Task || deepQueued[message.id] || processed[message.id]) return;
  deepQueued[message.id] = true;
  deepQueue.push(message);
  processDeep();
}

function processDeep() {
  if (deepBusy) return;
  var message = deepQueue.shift();
  if (!message) return;
  deepBusy = true;

  DatabaseStore.find(Thread, message.threadId).then(function (thread) {
    if (!thread) return null;
    if (!threadHasRole(thread, 'inbox')) return null;
    if (threadHasRole(thread, 'spam') || threadHasRole(thread, 'trash')) return null;
    if (processed[message.id]) return null;
    return fetchRawSource(message).then(function (raw) {
      var opts = optionsForAccount(message.accountId);
      var result = analyzer.analyze(raw, opts);
      if (config.get().onlineChecks && !result.details.allowListed) {
        var d = result.details;
        return reputation.analyze({ fromDomain: d.fromDomain, senderIp: d.senderIp, linkDomains: d.linkDomains })
          .then(function (rep) {
            if (rep && rep.signals.length) {
              result = analyzer.analyze(raw, Object.assign({}, opts, { extraSignals: rep.signals, reputationFacts: rep.facts }));
            }
            decideAndMove(message, thread, result, true);
          });
      }
      decideAndMove(message, thread, result, true);
    });
  }).catch(function (e) {
    console.error('[SpoofGuard] deep-scan', e);
  }).then(function () {
    deepBusy = false;
    delete deepQueued[message.id];
    if (deepQueue.length) setTimeout(processDeep, 1500); // be gentle on the server
  });
}

// --- background listener ----------------------------------------------------

function analyzeAndMaybeMove(message) {
  if (!message || processed[message.id]) return;
  if (!message.unread) return;
  var when = message.date ? new Date(message.date).getTime() : 0;
  if (when && when < START - 60 * 1000) return; // only mail that arrived around/after launch

  // Phase 1 (instant) — catches content scams (sextortion, malware names, etc.)
  // right away. Then, if enabled, queue a deep pass for auth-based spoofs.
  DatabaseStore.find(Thread, message.threadId).then(function (thread) {
    if (!thread || !threadHasRole(thread, 'inbox')) return;
    if (threadHasRole(thread, 'spam') || threadHasRole(thread, 'trash')) return;
    var result = analyzer.analyzeMessage(message, optionsForAccount(message.accountId));
    decideAndMove(message, thread, result, true);
    if (!processed[message.id] && config.get().deepScan) enqueueDeep(message);
  }).catch(function (e) { console.error('[SpoofGuard] scan', e); });
}

function onDataChanged(change) {
  try {
    var c = config.get();
    if (!c.enabled || !c.autoSpam) return;
    if (!change || change.objectClass !== Message) return;
    (change.objects || []).forEach(analyzeAndMaybeMove);
  } catch (e) {
    console.error('[SpoofGuard] onDataChanged', e);
  }
}

function start() {
  try {
    if (unsubscribe || !DatabaseStore) return;
    unsubscribe = DatabaseStore.listen(onDataChanged);
  } catch (e) {
    console.error('[SpoofGuard] scanner start', e);
  }
}

function stop() {
  try { if (unsubscribe) unsubscribe(); } catch (e) { /* ignore */ }
  unsubscribe = null;
}

// --- manual "scan inbox now" ------------------------------------------------

function latestMessage(messages) {
  if (!messages || !messages.length) return null;
  var best = messages[0];
  messages.forEach(function (m) {
    if (m && m.date && best.date && new Date(m.date) > new Date(best.date)) best = m;
  });
  return best;
}

function scanThread(account, thread, total) {
  if (threadHasRole(thread, 'spam') || threadHasRole(thread, 'trash')) return Promise.resolve();
  return DatabaseStore.findAll(Message)
    .where(Message.attributes.threadId.equal(thread.id))
    .then(function (messages) {
      var message = latestMessage(messages);
      if (!message) return;
      total.scanned++;
      var result = analyzer.analyzeMessage(message, optionsForAccount(account.id));
      // Manual sweep doesn't require the auto-move toggle (user clicked Scan).
      if (decideAndMove(message, thread, result, false)) total.moved++;
    });
}

function scanAccountInbox(account, total) {
  var inbox = CategoryStore.getInboxCategory(account.id);
  if (!inbox || !CategoryStore.getSpamCategory(account.id)) return Promise.resolve();
  return DatabaseStore.findAll(Thread)
    .where(Thread.attributes.categories.contains(inbox.id))
    .limit(2000)
    .then(function (threads) {
      return threads.reduce(function (p, thread) {
        return p.then(function () { return scanThread(account, thread, total); });
      }, Promise.resolve());
    });
}

// Returns a Promise<{ scanned, moved }>.
function scanInboxNow() {
  var total = { scanned: 0, moved: 0 };
  var accounts;
  try { accounts = AccountStore.accounts() || []; } catch (e) { accounts = []; }
  return accounts.reduce(function (p, account) {
    return p.then(function () {
      return scanAccountInbox(account, total).catch(function (e) {
        console.error('[SpoofGuard] scanInbox account', e);
      });
    });
  }, Promise.resolve()).then(function () { return total; });
}

module.exports = {
  maybeMove: maybeMove,
  start: start,
  stop: stop,
  scanInboxNow: scanInboxNow,
};
