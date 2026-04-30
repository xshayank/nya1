/**
 * DomainFront Relay — Google Apps Script Direct HTTP Relay
 *
 * FLOW:
 *   Client → GAS (Google Apps Script) → Target HTTP endpoint (directly)
 *
 * MODES:
 *   1. Single:  POST { k, m, u, h, b, ct }       → { s, h, b }
 *   2. Batch:   POST { k, q: [{m,u,h,b,ct}, ...] } → { q: [{s,h,b}, ...] }
 *
 * CHANGE THESE:
*/

const AUTH_KEY = "STRONG_SECRET_KEY";

const SKIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1,
  "transfer-encoding": 1, "proxy-connection": 1, "proxy-authorization": 1,
  upgrade: 1,
};

function doPost(e) {
  try {
    var req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) return _json({ e: "unauthorized" });

    if (Array.isArray(req.q)) return _doBatch(req.q);
    return _doSingle(req);

  } catch (err) {
    return _json({ e: String(err) });
  }
}

function _doSingle(req) {
  if (!req.u || typeof req.u !== "string" || !req.u.match(/^https?:\/\//i)) {
    return _json({ e: "bad url" });
  }

  var filteredHeaders = {};
  if (req.h && typeof req.h === "object") {
    for (var k in req.h) {
      if (req.h.hasOwnProperty(k) && !SKIP_HEADERS[k.toLowerCase()]) {
        filteredHeaders[k] = req.h[k];
      }
    }
  }

  var fetchOptions = {
    method: (req.m || "GET").toUpperCase(),
    headers: filteredHeaders,
    muteHttpExceptions: true,
    followRedirects: true
  };

  if (req.b) {
    var blob = Utilities.newBlob(Utilities.base64Decode(req.b));
    if (req.ct) blob.setContentType(req.ct);
    fetchOptions.payload = blob;
  }

  var resp = UrlFetchApp.fetch(req.u, fetchOptions);

  var respHeaders = resp.getHeaders();
  var respHeadersObj = {};
  for (var h in respHeaders) {
    if (respHeaders.hasOwnProperty(h)) {
      respHeadersObj[h] = respHeaders[h];
    }
  }

  return _json({
    s: resp.getResponseCode(),
    h: respHeadersObj,
    b: Utilities.base64Encode(resp.getContent())
  });
}

function _doBatch(items) {
  var fetchArgs = [];
  var errorMap = {};

  for (var i = 0; i < items.length; i++) {
    var item = items[i];

    if (!item.u || typeof item.u !== "string" || !item.u.match(/^https?:\/\//i)) {
      errorMap[i] = "bad url";
      continue;
    }

    var filteredHeaders = {};
    if (item.h && typeof item.h === "object") {
      for (var k in item.h) {
        if (item.h.hasOwnProperty(k) && !SKIP_HEADERS[k.toLowerCase()]) {
          filteredHeaders[k] = item.h[k];
        }
      }
    }

    var fetchOptions = {
      url: item.u,
      method: (item.m || "GET").toUpperCase(),
      headers: filteredHeaders,
      muteHttpExceptions: true,
      followRedirects: true
    };

    if (item.b) {
      var blob = Utilities.newBlob(Utilities.base64Decode(item.b));
      if (item.ct) blob.setContentType(item.ct);
      fetchOptions.payload = blob;
    }

    fetchArgs.push({ _i: i, _o: fetchOptions });
  }

  var responses = [];
  if (fetchArgs.length > 0) {
    responses = UrlFetchApp.fetchAll(fetchArgs.map(function(x) { return x._o; }));
  }

  var results = [];
  var rIdx = 0;

  for (var i = 0; i < items.length; i++) {
    if (errorMap.hasOwnProperty(i)) {
      results.push({ e: errorMap[i] });
    } else {
      var resp = responses[rIdx++];
      var respHeaders = resp.getHeaders();
      var respHeadersObj = {};
      for (var h in respHeaders) {
        if (respHeaders.hasOwnProperty(h)) {
          respHeadersObj[h] = respHeaders[h];
        }
      }
      results.push({
        s: resp.getResponseCode(),
        h: respHeadersObj,
        b: Utilities.base64Encode(resp.getContent())
      });
    }
  }

  return _json({ q: results });
}

function doGet(e) {
  return HtmlService.createHtmlOutput(
    "<!DOCTYPE html><html><head><title>GAS Relay</title></head>" +
      '<body style="font-family:sans-serif;max-width:600px;margin:40px auto">' +
      "<h1>xhttp relay active (Xray/v2ray transport)</h1><p>No Cloudflare. GAS connects directly to the target HTTP endpoint.</p>" +
      "</body></html>"
  );
}

function _json(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

