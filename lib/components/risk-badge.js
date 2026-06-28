// risk-badge.js
// The in-message UI. Registered for the 'MessageHeaderStatus' role, so
// Mailspring renders one instance per message (in the header, by the sender)
// and passes { message, thread, detailedHeaders }.
// (Note: no `account` prop is provided, so we look it up via AccountStore.)
//
// Two-phase analysis so the badge ALWAYS appears, even if this server can't
// return the raw message source:
//   Phase 1 (instant): analyze the Message object we already have
//                       (sender, reply-to, subject, body, attachments).
//   Phase 2 (async):    fetch the raw .eml and upgrade with SPF/DKIM/DMARC.
//
// Written with React.createElement (no JSX) so the plugin runs with no build.

'use strict';

var mailspring = require('mailspring-exports');
var React = mailspring.React;
var Actions = mailspring.Actions;
var TaskQueue = mailspring.TaskQueue;
var AccountStore = mailspring.AccountStore;
var GetMessageRFC2822Task = mailspring.GetMessageRFC2822Task;

var analyzer = require('../analyzer');
var config = require('../config');
var spamMover = require('../spam-mover');
var reputation = require('../reputation').create(); // shared session cache

var h = React.createElement;

var LEVEL_META = {
  'low':       { color: '#2e9e5b', bg: 'rgba(46,158,91,0.12)',  icon: '✓', text: 'Looks legitimate' },
  'suspicious':{ color: '#b9810a', bg: 'rgba(240,173,78,0.16)', icon: '!', text: 'Suspicious' },
  'high':      { color: '#e8590c', bg: 'rgba(232,89,12,0.16)',  icon: '!', text: 'High risk' },
  'very-high': { color: '#d92d20', bg: 'rgba(217,45,32,0.16)',  icon: '✕', text: 'Very high risk' },
};

// Brightened so they stay legible on the solid dark detail card.
var SEVERITY_COLOR = {
  critical: '#ff6b6b', high: '#ff9d5c', medium: '#f0c54e', low: '#aeb6c2', info: '#aeb6c2',
};

class SpoofGuardBadge extends React.Component {
  constructor(props) {
    super(props);
    this.state = { result: null, expanded: false, fetchFailed: false };
    this._mounted = false;
    this._toggle = this._toggle.bind(this);
  }

  componentDidMount() {
    this._mounted = true;
    this._run();
  }

  componentWillUnmount() {
    this._mounted = false;
  }

  componentDidUpdate(prevProps) {
    var a = prevProps.message ? prevProps.message.id : null;
    var b = this.props.message ? this.props.message.id : null;
    if (a !== b) {
      this.setState({ result: null, expanded: false, fetchFailed: false }, () => this._run());
    }
  }

  _account() {
    var msg = this.props.message;
    try {
      if (msg && AccountStore && AccountStore.accountForId) {
        return AccountStore.accountForId(msg.accountId);
      }
    } catch (e) { /* ignore */ }
    return null;
  }

  _options() {
    var acct = this._account();
    var cfg = config.get();
    return {
      accountEmail: acct ? acct.emailAddress : null,
      accountName: acct ? acct.name : null,
      trustedSenders: cfg.trustedSenders,
      blockSenders: cfg.blockSenders,
      trustedDomains: cfg.myDomains,
    };
  }

  _afterResult(result) {
    // Optional, opt-in auto-move (no-op unless the user enabled it in settings).
    try { spamMover.maybeMove(this.props.message, this.props.thread, result); }
    catch (e) { console.error('[SpoofGuard] auto-move', e); }
  }

  _run() {
    var msg = this.props.message;
    if (!msg) return;

    // Respect the master on/off switch.
    if (!config.get().enabled) {
      this.setState({ result: null });
      return;
    }

    // Phase 1: instant, from the message object. Never throws fatally.
    try {
      var opts = this._options();
      var quick = analyzer.analyzeMessage(msg, opts);
      this.setState({ result: quick });
      this._afterResult(quick);
    } catch (e) {
      console.error('[SpoofGuard] phase1', e);
    }

    // Phase 2: best-effort raw-header enrichment.
    this._enrich();
  }

  async _enrich() {
    var msg = this.props.message;
    if (!msg || !GetMessageRFC2822Task) {
      if (this._mounted) this.setState({ fetchFailed: true });
      return;
    }
    try {
      var fs = require('fs');
      var os = require('os');
      var path = require('path');
      var filepath = path.join(os.tmpdir(), 'spoofguard_' + msg.id + '.eml');

      var task = new GetMessageRFC2822Task({ messageId: msg.id, accountId: msg.accountId, filepath: filepath });
      Actions.queueTask(task);
      await TaskQueue.waitForPerformRemote(task);

      var raw = fs.readFileSync(filepath, 'utf8');
      try { fs.unlinkSync(filepath); } catch (e) { /* best effort */ }

      var opts = this._options();
      var full = analyzer.analyze(raw, opts);
      if (this._mounted) {
        this.setState({ result: full, fetchFailed: false });
        this._afterResult(full);
      }
      // Phase 3 (optional): online reputation via DNS blocklists.
      if (config.get().onlineChecks && !full.details.allowListed) {
        this._reputationEnrich(raw, full, opts);
      }
    } catch (err) {
      // Keep the phase-1 result; just note that full headers weren't available.
      console.error('[SpoofGuard] enrich', err);
      if (this._mounted) this.setState({ fetchFailed: true });
    }
  }

  async _reputationEnrich(raw, full, opts) {
    try {
      var d = full.details;
      var rep = await reputation.analyze({
        fromDomain: d.fromDomain,
        senderIp: d.senderIp,
        linkDomains: d.linkDomains,
      });
      if (!rep || (!rep.signals.length && !rep.facts)) return;
      var enriched = analyzer.analyze(raw, Object.assign({}, opts, {
        extraSignals: rep.signals,
        reputationFacts: rep.facts,
      }));
      if (this._mounted) {
        this.setState({ result: enriched });
        this._afterResult(enriched);
      }
    } catch (e) {
      console.error('[SpoofGuard] reputation', e);
    }
  }

  _toggle(e) {
    if (e && e.stopPropagation) e.stopPropagation(); // don't toggle Mailspring's header
    this.setState({ expanded: !this.state.expanded });
  }

  _authChip(label, value) {
    var ok = value === 'pass';
    var color = ok ? '#3ddc97' : (value === 'fail' ? '#ff6b6b' : '#aeb6c2');
    return h('span', { className: 'sg-auth-chip', style: { color: color }, key: label },
      h('b', null, label), ' ', ok ? '✓' : (value || 'none'));
  }

  _renderAuthLine(d) {
    if (this.state.fetchFailed || d.authStatus === 'unavailable') {
      return h('div', { className: 'sg-note', key: 'authna' },
        'ℹ Full headers weren’t available from this server, so SPF/DKIM/DMARC couldn’t be verified. ' +
        'This score is based on the sender, links, and content only.');
    }
    if (d.authStatus === 'pending') {
      return h('div', { className: 'sg-note', key: 'authpending' }, 'Checking SPF/DKIM/DMARC…');
    }
    return h('div', { className: 'sg-auth-row', key: 'auth' },
      this._authChip('SPF', d.auth.spf),
      this._authChip('DKIM', d.auth.dkim),
      this._authChip('DMARC', d.auth.dmarc),
      d.auth.arcPass ? h('span', { className: 'sg-auth-chip', style: { color: '#5ab0e8' } }, 'ARC ✓') : null,
      d.auth.trusted ? h('span', { className: 'sg-auth-chip', style: { color: '#3ddc97' } }, 'aligned ✓') : null
    );
  }

  _renderDetails() {
    var r = this.state.result;
    var d = r.details;
    var rows = [];

    if (d.allowListed) {
      rows.push(h('div', { className: 'sg-note', key: 'allow' },
        '✓ This sender is on your always-trusted list, so it is never flagged.'));
    }

    if (d.blocked) {
      rows.push(h('div', { className: 'sg-note', key: 'blocked', style: { color: '#ff6b6b' } },
        '⛔ This sender is on your block list.'));
    }

    if (d.reputation) {
      var rep = d.reputation;
      var bits = [];
      if (rep.ipListed) bits.push('IP blocklisted');
      if (rep.domainListed) bits.push('domain blocklisted');
      if (rep.listedLinks && rep.listedLinks.length) bits.push('bad link: ' + rep.listedLinks.join(', '));
      if (rep.spf === false && rep.dmarc === false) bits.push('no SPF/DMARC published');
      if (!bits.length) bits.push('no blocklist hits');
      rows.push(h('div', { className: 'sg-note', key: 'rep' }, '🌐 Reputation: ' + bits.join(' • ')));
    }

    if (d.hostTags && d.hostTags.length) {
      rows.push(h('div', { className: 'sg-note', key: 'hosttags' },
        'ℹ Your mail host tagged this "' + d.hostTags.join(' ') +
        '". Host tags like these are frequently wrong, so they are ignored in this score.'));
    }

    rows.push(this._renderAuthLine(d));

    var facts = [];
    if (d.fromDomain) facts.push('From: ' + d.fromDomain);
    if (d.replyDomain && d.replyDomain !== d.fromDomain) facts.push('Reply-To: ' + d.replyDomain);
    if (d.returnDomain && d.returnDomain !== d.fromDomain) facts.push('Return-Path: ' + d.returnDomain);
    if (d.route && d.route.origin) facts.push('Origin: ' + d.route.origin);
    if (facts.length) rows.push(h('div', { className: 'sg-facts', key: 'facts' }, facts.join('   •   ')));

    if (r.signals.length) {
      rows.push(h('div', { className: 'sg-reasons', key: 'reasons' },
        r.signals.map(function (s, i) {
          return h('div', { className: 'sg-reason', key: i },
            h('span', { className: 'sg-dot', style: { background: SEVERITY_COLOR[s.severity] || '#aeb6c2' } }),
            h('span', { className: 'sg-reason-label' }, s.label),
            h('span', { className: 'sg-reason-sev', style: { color: SEVERITY_COLOR[s.severity] } }, s.severity)
          );
        })
      ));
    } else {
      rows.push(h('div', { className: 'sg-reasons', key: 'noreason' },
        h('div', { className: 'sg-reason' }, 'No suspicious indicators were found.')));
    }

    rows.push(h('div', { className: 'sg-reco', key: 'reco' }, r.recommendation));
    return h('div', { className: 'sg-details' }, rows);
  }

  render() {
    var r = this.state.result;
    if (!r) return null; // phase 1 sets this synchronously, so this is momentary

    var meta = LEVEL_META[r.level] || LEVEL_META.low;
    var count = r.signals.filter(function (x) { return x.severity !== 'info'; }).length;

    var badge = h('div', {
      className: 'sg-badge sg-level-' + r.level,
      style: { color: meta.color, background: meta.bg, borderColor: meta.color },
      onClick: this._toggle,
      title: 'Spoof Guard — click for details',
    },
      h('span', { className: 'sg-icon' }, meta.icon),
      h('span', { className: 'sg-label' }, meta.text),
      h('span', { className: 'sg-score' }, 'risk ' + r.score + '/100'),
      count ? h('span', { className: 'sg-count' }, count + (count === 1 ? ' reason' : ' reasons')) : null,
      h('span', { className: 'sg-caret' }, this.state.expanded ? '▲' : '▼')
    );

    return h('div', { className: 'spoof-guard' }, badge, this.state.expanded ? this._renderDetails() : null);
  }
}

SpoofGuardBadge.displayName = 'SpoofGuardBadge';

module.exports = SpoofGuardBadge;
module.exports.default = SpoofGuardBadge;
