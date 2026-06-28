// main.js — plugin entry point.
// Registers the Spoof Guard badge, a Preferences tab, and the optional
// auto-move-to-Spam scanner.

'use strict';

var mailspring = require('mailspring-exports');
var ComponentRegistry = mailspring.ComponentRegistry;
var PreferencesUIStore = mailspring.PreferencesUIStore;

var SpoofGuardBadge = require('./components/risk-badge');
var SpoofGuardSettings = require('./components/settings');
var spamMover = require('./spam-mover');

// We register for 'MessageHeaderStatus' rather than 'MessageHeader' on purpose:
// 'MessageHeader' is a SINGULAR injection point (only one plugin can occupy it),
// so another header plugin can block ours entirely. 'MessageHeaderStatus' is an
// InjectedComponentSet — every registered component renders, right next to the
// sender line — so the badge always shows and never conflicts.
function activate() {
  ComponentRegistry.register(SpoofGuardBadge, {
    role: 'MessageHeaderStatus',
  });

  if (PreferencesUIStore && PreferencesUIStore.registerPreferencesTab) {
    PreferencesUIStore.registerPreferencesTab(
      new PreferencesUIStore.TabItem({
        tabId: 'SpoofGuard',
        displayName: 'Spoof Guard',
        componentClassFn: function () { return SpoofGuardSettings; },
      })
    );
  }

  spamMover.start();
}

function serialize() {}

function deactivate() {
  ComponentRegistry.unregister(SpoofGuardBadge);
  if (PreferencesUIStore && PreferencesUIStore.unregisterPreferencesTab) {
    PreferencesUIStore.unregisterPreferencesTab('SpoofGuard');
  }
  spamMover.stop();
}

module.exports = {
  activate: activate,
  serialize: serialize,
  deactivate: deactivate,
};
