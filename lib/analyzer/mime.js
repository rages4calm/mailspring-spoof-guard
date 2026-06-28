// mime.js
// Lightweight, dependency-free RFC822/MIME reader.
//
// Mailspring hands us the raw .eml source (via GetMessageRFC2822Task). We only
// need three things out of it for spoof/phishing analysis:
//   1. The full set of headers (with folded lines unwrapped).
//   2. The decoded human-readable body text (plain + a text version of HTML).
//   3. The raw HTML (so we can compare anchor text vs. real link targets) and
//      the list of attachment filenames.
//
// This is intentionally NOT a full MIME implementation. It handles the cases
// that matter for detection (multipart/alternative, multipart/mixed, base64 and
// quoted-printable transfer encodings) and degrades gracefully on anything else.

'use strict';

// --- transfer-encoding decoders -------------------------------------------

function decodeQuotedPrintable(input) {
  return input
    // soft line breaks
    .replace(/=\r?\n/g, '')
    // =XX hex escapes
    .replace(/=([0-9A-Fa-f]{2})/g, function (_, hex) {
      return String.fromCharCode(parseInt(hex, 16));
    });
}

function decodeBase64(input) {
  try {
    return Buffer.from(input.replace(/\s+/g, ''), 'base64').toString('utf8');
  } catch (e) {
    return input;
  }
}

function decodeBody(body, encoding) {
  var enc = (encoding || '').toLowerCase().trim();
  if (enc === 'base64') return decodeBase64(body);
  if (enc === 'quoted-printable') return decodeQuotedPrintable(body);
  return body;
}

// --- header parsing --------------------------------------------------------

// Splits a header block into a case-preserving map of { Name: [values...] }.
// Header field names are matched case-insensitively elsewhere via getHeader().
function parseHeaderBlock(headerText) {
  var unfolded = headerText.replace(/\r?\n[ \t]+/g, ' ');
  var headers = {};
  unfolded.split(/\r?\n/).forEach(function (line) {
    var idx = line.indexOf(':');
    if (idx === -1) return;
    var name = line.slice(0, idx).trim();
    var value = line.slice(idx + 1).trim();
    if (!name) return;
    if (!headers[name]) headers[name] = [];
    headers[name].push(value);
  });
  return headers;
}

// Case-insensitive header lookup. Returns array of values (possibly empty).
function getHeaderValues(headers, name) {
  var target = name.toLowerCase();
  var out = [];
  Object.keys(headers).forEach(function (k) {
    if (k.toLowerCase() === target) out = out.concat(headers[k]);
  });
  return out;
}

function getParam(headerValue, param) {
  if (!headerValue) return null;
  var re = new RegExp(param + '\\s*=\\s*"?([^";]+)"?', 'i');
  var m = headerValue.match(re);
  return m ? m[1].trim() : null;
}

// --- html helpers ----------------------------------------------------------

function htmlToText(html) {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<\/(p|div|br|tr|li|h[1-6])>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// --- body / part walking ---------------------------------------------------

function splitHeaderAndBody(raw) {
  var sep = raw.indexOf('\r\n\r\n');
  var sepLen = 4;
  if (sep === -1) {
    sep = raw.indexOf('\n\n');
    sepLen = 2;
  }
  if (sep === -1) return { headerText: raw, body: '' };
  return { headerText: raw.slice(0, sep), body: raw.slice(sep + sepLen) };
}

// Recursively walks a MIME entity, collecting text/plain, text/html and
// attachment filenames into `acc`.
function walkEntity(rawEntity, acc, depth) {
  if (depth > 8) return; // guard against pathological nesting
  var parsed = splitHeaderAndBody(rawEntity);
  var headers = parseHeaderBlock(parsed.headerText);
  var contentType = (getHeaderValues(headers, 'Content-Type')[0] || 'text/plain').toLowerCase();
  var encoding = getHeaderValues(headers, 'Content-Transfer-Encoding')[0] || '';
  var disposition = getHeaderValues(headers, 'Content-Disposition')[0] || '';

  // Attachment? record the filename (used for dangerous-extension checks).
  var filename = getParam(disposition, 'filename') || getParam(contentType, 'name');
  if (filename && /attachment/i.test(disposition)) {
    acc.attachments.push(filename);
    return;
  }

  if (contentType.indexOf('multipart/') === 0) {
    var boundary = getParam(contentType, 'boundary');
    if (!boundary) return;
    var marker = '--' + boundary;
    var segments = parsed.body.split(marker);
    // skip the preamble (segment 0) and the trailing closing marker segment
    for (var i = 1; i < segments.length; i++) {
      var seg = segments[i];
      if (/^--/.test(seg)) break; // closing boundary "--boundary--"
      // strip the leading CRLF that follows the boundary line
      seg = seg.replace(/^\r?\n/, '');
      walkEntity(seg, acc, depth + 1);
    }
    return;
  }

  var decoded = decodeBody(parsed.body, encoding);
  if (contentType.indexOf('text/html') === 0) {
    acc.html += decoded;
  } else if (contentType.indexOf('text/plain') === 0) {
    acc.text += decoded;
  } else if (filename) {
    acc.attachments.push(filename);
  }
}

// parseMessage(raw) -> { headers, text, html, attachments }
function parseMessage(raw) {
  raw = String(raw || '');
  var top = splitHeaderAndBody(raw);
  var headers = parseHeaderBlock(top.headerText);

  var acc = { text: '', html: '', attachments: [] };
  walkEntity(raw, acc, 0);

  // If we only got HTML, derive readable text from it.
  if (!acc.text && acc.html) acc.text = htmlToText(acc.html);

  return {
    headers: headers,
    text: acc.text,
    html: acc.html,
    attachments: acc.attachments,
  };
}

module.exports = {
  parseMessage: parseMessage,
  parseHeaderBlock: parseHeaderBlock,
  getHeaderValues: getHeaderValues,
  getParam: getParam,
  htmlToText: htmlToText,
  decodeQuotedPrintable: decodeQuotedPrintable,
  decodeBase64: decodeBase64,
};
