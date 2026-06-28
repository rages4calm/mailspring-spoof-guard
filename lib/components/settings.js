// settings.js
// The "Spoof Guard" tab in Mailspring Preferences. Plain React.createElement so
// no build step is needed. Reads/writes AppEnv.config via lib/config.js.

'use strict';

var mailspring = require('mailspring-exports');
var React = mailspring.React;
var config = require('../config');
var spamMover = require('../spam-mover');

var h = React.createElement;

class SpoofGuardSettings extends React.Component {
  constructor(props) {
    super(props);
    this.state = this._read();
    this.state.confirmScan = false;
    this.state.scanning = false;
    this.state.scanStatus = null;
  }

  _read() {
    return {
      enabled: config.getRaw('enabled', true) !== false,
      trustedSendersText: config.getRaw('trustedSendersText', ''),
      myDomainsText: config.getRaw('myDomainsText', ''),
      autoSpam: config.getRaw('autoSpam', false) === true,
      autoSpamLevel: config.getRaw('autoSpamLevel', 'very-high'),
      deepScan: config.getRaw('deepScan', true) !== false,
    };
  }

  _runScan() {
    var self = this;
    this.setState({ confirmScan: false, scanning: true, scanStatus: 'Scanning your inbox…' });
    Promise.resolve()
      .then(function () { return spamMover.scanInboxNow(); })
      .then(function (r) {
        self.setState({
          scanning: false,
          scanStatus: 'Done — scanned ' + r.scanned + ' message' + (r.scanned === 1 ? '' : 's') +
            ', moved ' + r.moved + ' to Spam.',
        });
      })
      .catch(function (e) {
        self.setState({ scanning: false, scanStatus: 'Scan failed: ' + (e && e.message ? e.message : e) });
      });
  }

  _update(key, value) {
    config.set(key, value);
    var s = {};
    s[key] = value;
    this.setState(s);
  }

  _section(title, children) {
    return h('section', { className: 'sg-pref-section' },
      h('h2', null, title), children);
  }

  _check(key, label, help) {
    var self = this;
    return h('div', { className: 'sg-pref-row' },
      h('label', { className: 'sg-pref-check' },
        h('input', {
          type: 'checkbox',
          checked: !!this.state[key],
          onChange: function (e) { self._update(key, e.target.checked); },
        }),
        ' ', label
      ),
      help ? h('div', { className: 'sg-pref-help' }, help) : null
    );
  }

  _textarea(key, label, help, placeholder) {
    var self = this;
    return h('div', { className: 'sg-pref-row' },
      h('label', { className: 'sg-pref-label' }, label),
      h('textarea', {
        className: 'sg-pref-textarea',
        rows: 4,
        value: this.state[key],
        placeholder: placeholder || '',
        onChange: function (e) { self._update(key, e.target.value); },
      }),
      help ? h('div', { className: 'sg-pref-help' }, help) : null
    );
  }

  render() {
    var self = this;
    return h('div', { className: 'container-spoofguard sg-prefs' },

      this._section('Spoof Guard', [
        this._check('enabled', 'Enable Spoof Guard',
          'Shows a risk badge on each message and powers everything below.'),
      ]),

      this._section('Always-trusted senders (allow-list)',
        this._textarea('trustedSendersText', 'Never flag mail from these',
          'One per line. Use a full address (you@gmail.com) or a whole domain (example.com). ' +
          'Useful for your own other mailboxes and people you know — they’ll always score clean.',
          'you@gmail.com\nexample.com')
      ),

      this._section('Block-list (always Spam)',
        this._textarea('blockSendersText', 'Always treat mail from these as spam',
          'One per line — a full address or a whole domain. These are forced to maximum risk ' +
          '(and auto-moved if auto-move is on), no matter what else the message looks like.',
          'spammer@example.com\nbad-domain.tk')
      ),

      this._section('Your domains',
        this._textarea('myDomainsText', 'Domains you own',
          'One per line. Your signed-in account domains are detected automatically; add any ' +
          'extras here so look-alike and "spoofed as you" detection covers them too.',
          'mydomain.com\nmy-other-domain.com')
      ),

      this._section('Online reputation checks', [
        this._check('onlineChecks', 'Check sender IP and domains against DNS blocklists',
          'Off by default. When on, the plugin asks public DNS blocklists (Spamhaus) whether ' +
          'the sending IP or domains are known-bad, and whether the sender domain publishes ' +
          'SPF/DMARC. Only the IP/domain is sent to the blocklist — never your email content. ' +
          'Especially useful here, since your mail host strips the SPF/DKIM/DMARC results.'),
      ]),

      this._section('Auto-move to Spam', [
        this._check('autoSpam', 'Automatically move risky mail to the Spam folder',
          'Off by default. When on, new inbox mail at or above the level below is moved to ' +
          'Spam automatically. Allow-listed senders are never moved. Only affects mail that ' +
          'arrives while Mailspring is running and is currently in your Inbox.'),
        h('div', { className: 'sg-pref-row' },
          h('label', { className: 'sg-pref-label' }, 'Move when risk is at least'),
          h('select', {
            className: 'sg-pref-select',
            value: this.state.autoSpamLevel,
            disabled: !this.state.autoSpam,
            onChange: function (e) { self._update('autoSpamLevel', e.target.value); },
          },
            h('option', { value: 'very-high' }, 'Very high risk (safest — fewest false moves)'),
            h('option', { value: 'high' }, 'High risk (catches more spam, slightly riskier)')
          ),
          h('div', { className: 'sg-pref-help' },
            'Tip: start with “Very high”, watch your Spam folder for a few days, then lower it ' +
            'to “High” if you’re comfortable. You can always rescue anything from Spam.')
        ),
        h('div', { className: 'sg-pref-row', style: { opacity: this.state.autoSpam ? 1 : 0.5 } },
          h('label', { className: 'sg-pref-check' },
            h('input', {
              type: 'checkbox',
              checked: !!this.state.deepScan,
              disabled: !this.state.autoSpam,
              onChange: function (e) { self._update('deepScan', e.target.checked); },
            }),
            ' Fetch full headers for incoming mail (better spoof detection)'
          ),
          h('div', { className: 'sg-pref-help' },
            'Lets the background scan check SPF/DKIM/DMARC on new mail without you opening it, ' +
            'so messages spoofing your own domain can be caught automatically. Slightly more ' +
            'network use; throttled to be gentle on your server.')
        ),
      ]),

      this._section('Clean up the current inbox', [
        h('div', { className: 'sg-pref-help', style: { marginTop: 0 } },
          'Auto-move only affects new mail. Run this once to scan messages already sitting in ' +
          'your Inbox and move risky ones to Spam (uses the same risk level and allow-list above). ' +
          'Anything moved can be rescued from Spam.'),
        this.state.confirmScan
          ? h('div', { className: 'sg-pref-row' },
              h('span', { style: { marginRight: 8 } }, 'Scan the inbox and move risky mail to Spam?'),
              h('button', {
                className: 'btn btn-emphasis', style: { marginRight: 6 },
                onClick: function () { self._runScan(); },
              }, 'Yes, scan now'),
              h('button', { className: 'btn', onClick: function () { self.setState({ confirmScan: false }); } }, 'Cancel')
            )
          : h('div', { className: 'sg-pref-row' },
              h('button', {
                className: 'btn',
                disabled: this.state.scanning || !this.state.enabled,
                onClick: function () { self.setState({ confirmScan: true, scanStatus: null }); },
              }, this.state.scanning ? 'Scanning…' : 'Scan inbox now')
            ),
        this.state.scanStatus
          ? h('div', { className: 'sg-pref-help', style: { marginTop: 4 } }, this.state.scanStatus)
          : null,
      ])
    );
  }
}

SpoofGuardSettings.displayName = 'SpoofGuardSettings';

module.exports = SpoofGuardSettings;
module.exports.default = SpoofGuardSettings;
