# Mailspring Spoof Guard

A Mailspring plugin that inspects each message's **raw headers and content** and shows a
clear **risk score (0–100)** with the **exact reasons** it was flagged — built to catch
spoofed, phishing, scam, and extortion mail across multiple domain accounts, while
**not** turning legitimate mail into a hunt.

It is **advisory only**: it never deletes, moves, blocks, or rewrites mail.

## What it checks

**Authentication (from the receiving server's `Authentication-Results`):**
- SPF / DKIM / DMARC pass / fail / softfail
- **Alignment** — does the domain that actually authenticated match the visible `From:`?
- ARC seal (trusted forwarding, so legit mailing-list mail isn't punished)

**Spoofing / impersonation:**
- **Your own domain spoofed** (`From:` looks like your domain but didn't authenticate as it)
- **Someone using *your* name from an unrelated free-mail address** (e.g. `"Jane Smith" <random@gmail.com>`)
- Display-name impersonation of known brands (PayPal, Microsoft, banks…)
- Look-alike / typosquatted domains (`paypa1.com`), punycode / **homoglyph** Unicode tricks
- `Reply-To` / `Return-Path` mismatches, and **BEC** (corporate-looking sender, replies go to Gmail)

**Content / links / attachments:**
- Sextortion / blackmail and crypto-ransom language
- Credential-phishing ("verify/unlock your account"), fake-invoice / billing language
- Links whose visible text lies about their real destination, raw-IP URLs, punycode URLs,
  `@`-obfuscated URLs, URL shorteners
- **Quishing** (QR-code phishing)
- Dangerous attachments and deceptive double extensions (`invoice.pdf.exe`)

**Your host's noise is ignored on purpose:** subject tags your cPanel/MailScanner host
injects — like `{Disarmed}` or `{Definitely Spam?}` — are **stripped and given zero weight**,
because they're frequently wrong. They're shown as a small note, never as a score.

## Risk levels

| Score | Level | Meaning |
|------:|-------|---------|
| 0–19  | Looks legitimate | No meaningful indicators |
| 20–44 | Suspicious | A few weak signals — mild caution |
| 45–69 | High risk | Multiple real indicators |
| 70–100| Very high risk | Strong signs of spoofing / scam |

A fully authenticated + aligned message gets the benefit of the doubt on "soft" signals
(different Reply-To, urgency wording, etc.) so real newsletters and receipts stay green.

## Install (Windows)

No build step — the plugin ships as plain JavaScript.

1. Copy the whole `mailspring-spoof-guard` folder into Mailspring's packages directory:
   ```
   %APPDATA%\Mailspring\packages\
   ```
   (paste `%APPDATA%\Mailspring\packages` into the File Explorer address bar)
2. Restart Mailspring (or **Developer → Reload**).
3. Open any message — a risk badge appears under the sender header. Click it for the full
   reason list and SPF/DKIM/DMARC summary.

macOS path: `~/Library/Application Support/Mailspring/packages/`
Linux path: `~/.config/Mailspring/packages/`

**If you previously installed `mailspring-auth-results`, remove it.** It registers for the
singular `MessageHeader` slot and can block other header plugins. Spoof Guard uses the
shared `MessageHeaderStatus` slot, but removing the old one avoids confusion.

## How it gets the data (and why the badge always shows)

The `Message` object Mailspring hands a plugin has the sender, reply-to, subject, body and
attachments — but **not** the raw headers (Authentication-Results, Received, Return-Path).
So the plugin works in two phases:

1. **Instant** — it analyzes the message object immediately (sender/impersonation, links,
   content, attachments, host-tag stripping) and shows the badge right away.
2. **Enrich** — it then tries `GetMessageRFC2822Task` to fetch the raw `.eml`, parse it
   locally, and add SPF/DKIM/DMARC. If your server can't return the raw source, the badge
   **still shows** (phase 1) and notes that auth couldn't be verified — it never disappears.

Everything runs **locally**; no email content leaves your machine. The temp `.eml` is
deleted right after parsing.

## Troubleshooting

- **No badge at all** → Open **Help → Toggle Developer Tools → Console** and look for
  `[SpoofGuard]` errors. Make sure the folder is directly inside `packages\` (i.e.
  `packages\mailspring-spoof-guard\package.json` exists) and reload.
- **Badge shows but says "Full headers weren't available"** → your mail server/IMAP didn't
  return the raw source for `GetMessageRFC2822Task`; SPF/DKIM/DMARC are skipped, everything
  else still works.

## Settings

Open **Preferences → Spoof Guard**:

- **Enable Spoof Guard** — master on/off for the badge and everything below.
- **Always-trusted senders (allow-list)** — one address (`you@gmail.com`) or whole domain
  (`example.com`) per line. Allow-listed mail is **never flagged** and never auto-moved. Put
  your own other mailboxes and known contacts here. (This is the fix for "I emailed myself
  and it said high risk.")
- **Block-list (always Spam)** — addresses/domains forced to maximum risk (and auto-moved if
  auto-move is on), regardless of content. The inverse of the allow-list. Block wins if a
  sender is on both lists.
- **Your domains** — your signed-in account domains are detected automatically; add extra
  domains you own so "spoofed as you" / look-alike checks cover them too.
- **Online reputation checks** — see below.
- **Auto-move to Spam** — see below.

## Online reputation checks (optional, off by default)

When enabled, the plugin queries public **DNS blocklists** to strengthen detection:

- **Spamhaus ZEN** on the sending IP — is the server a known spam source?
- **Spamhaus DBL** on the sender domain and on domains found in links — known-bad domains?
- **SPF/DMARC record lookup** — does the sender domain publish these at all?

It's all plain DNS — **no API keys**, and **only the IP/domain is sent** to the blocklist,
never your email content. Lookups are cached per session and time-limited so a slow DNS
server can't hang the UI. This is particularly useful when your mail host strips the
`Authentication-Results` header, because it lets the plugin recover reputation signal
independently.

> Note: some public DNS resolvers (e.g. 8.8.8.8) are blocked by Spamhaus' free tier. If
> reputation never reports hits, your resolver may be rejected — the plugin treats a rejected
> query as "no result," so it never produces a false positive from this.

All settings are stored in Mailspring's own config, so they're per-install and survive
updates. Nothing about your domains is baked into the code — the plugin is generic and safe
to share.

## Auto-move risky mail to Spam (optional, off by default)

Mailspring's built-in **Mail Rules** (Preferences → Mail Rules) can move mail automatically,
but they can only match on plain fields (From, Subject, etc.) — **they can't see this
plugin's risk score**. So score-based auto-filing is done by the plugin itself.

Turn on **Preferences → Spoof Guard → "Automatically move risky mail to the Spam folder"**
and pick a threshold:

- It moves **new inbox mail** that scores at/above your chosen level to **Spam**.
- It works two ways: as messages are scanned when you open them, and via a background watch
  on incoming mail while Mailspring is running.
- **Guardrails:** allow-listed senders are never moved; only messages currently in the Inbox
  are touched (never Sent/Spam/Trash); only mail that arrived since launch (it never
  mass-moves your history); and each message is decided once. Anything it moves can be
  rescued from Spam normally.

**Fetch full headers for incoming mail** (sub-option, on by default): lets the background
scan check SPF/DKIM/DMARC on new mail without you opening it, so messages spoofing your own
domain are caught automatically. It's throttled (one fetch at a time) to be gentle on the
server.

**Clean up the current inbox:** auto-move only affects *new* mail. The **Scan inbox now**
button (in settings) runs a one-time sweep over mail already in your Inbox and moves risky
ones to Spam, using the same risk level and allow-list. Anything moved can be rescued.

Recommended: start at **Very high**, watch Spam for a few days, then drop to **High** if you
want it to catch more. For sender/keyword-based filing that doesn't need a risk score, use
Mailspring's native Mail Rules alongside this.

## Develop / test

The analyzer (`lib/analyzer/`) is pure JavaScript with no Mailspring dependency, so it runs
and tests in plain Node:

```
npm test
```

This runs `test/run.js`, a set of labeled sample emails (legit, internal spoof, sextortion,
brand phish, malware attachment, free-mail impersonation, host false-positive) and asserts
the expected risk level and signals.

To tune detection, edit the weights in `lib/analyzer/scoring.js` — all scoring lives there.

## Project layout

```
lib/
  main.js                       register badge + preferences tab + auto-move
  config.js                     settings stored in AppEnv.config (spoofGuard.*)
  spam-mover.js                 optional opt-in auto-move to Spam
  reputation.js                 optional DNS blocklist / SPF-DMARC checks
  components/
    risk-badge.js               the in-message UI (React.createElement, no JSX)
    settings.js                 the Preferences > Spoof Guard tab
  analyzer/
    index.js                    analyze(rawSource, {accountEmail, accountName})
    mime.js                     raw .eml -> headers, text, html, attachments
    auth.js                     SPF/DKIM/DMARC parsing + alignment
    domains.js                  domain/freemail/homoglyph/look-alike helpers
    heuristics-headers.js       spoof / impersonation header signals
    heuristics-content.js       body / link / attachment signals
    scoring.js                  weights -> score, level, summary, recommendation
styles/main.less                badge + detail panel styling
test/run.js                     Node test harness
```

## Roadmap

- Thread-aware BEC detection (reply injected into an existing conversation).
- Per-account settings (different trust lists per mailbox).
- Optional URL-reputation lookups (abuse.ch URLhaus) for malware links.

## Privacy

All analysis runs locally. Email content never leaves your machine. The only optional
network activity is the **online reputation checks** (off by default), which send just the
sending IP and sender/link domains — never message content — to public DNS blocklists.

## Disclaimer

This is an **advisory** tool. It scores risk and can optionally move mail to your Spam
folder, but it is not a guarantee — treat its output as one signal among many, and always
verify important messages independently. Provided "as is" with no warranty (see `LICENSE`).

## License

[MIT](LICENSE)

## Contributing

The detection engine (`lib/analyzer/`) is plain JavaScript with no Mailspring dependency.
Run the test suite with `npm test`. Detection weights live in `lib/analyzer/scoring.js`.
Issues and pull requests welcome.
