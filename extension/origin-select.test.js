const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {selectCallerOrigin} = require("./origin-select.js");

const now = 1_000_000;

function chosen(tabUrl, reports) {
  return selectCallerOrigin({tabUrl, reports, now});
}

// An iframe that loads after the top page must not become the caller.
assert.equal(
  chosen("https://example.com/login", [
    {origin: "https://example.com", calling: false, at: now - 10},
    {origin: "https://ads.example", calling: false, at: now - 1},
  ]),
  "https://example.com",
);

// keydown, focus, and pointerdown reports are not the calling frame.
assert.equal(
  chosen("https://example.com/a", [
    {origin: "https://other.example", calling: false, at: now, reason: "keydown"},
  ]),
  "https://example.com",
);

// The frame that called credentials.create or get is the caller, even in an iframe.
assert.equal(
  chosen("https://example.com/login", [
    {origin: "https://ads.example", calling: false, at: now - 1},
    {origin: "https://pay.example", calling: true, at: now - 20},
  ]),
  "https://pay.example",
);

// A later non-calling report does not replace that frame.
assert.equal(
  chosen("https://example.com/login", [
    {origin: "https://pay.example", calling: true, at: now - 20},
    {origin: "https://example.com", calling: false, at: now - 1},
  ]),
  "https://pay.example",
);

// The newest calling frame wins.
assert.equal(
  chosen("https://example.com/a", [
    {origin: "https://old.example", calling: true, at: now - 50},
    {origin: "https://new.example", calling: true, at: now - 5},
  ]),
  "https://new.example",
);

// A calling report older than 30s falls back to the tab top origin.
assert.equal(
  chosen("https://example.com/login", [
    {origin: "https://pay.example", calling: true, at: now - 30000},
  ]),
  "https://example.com",
);

// Chrome origins are not WebAuthn callers.
assert.equal(
  chosen("chrome://newtab/", [{origin: "chrome-extension://abcdefghijklmnop", calling: true, at: now}]),
  null,
);

const root = __dirname;
const background = fs.readFileSync(path.join(root, "background.js"), "utf8");
const originJs = fs.readFileSync(path.join(root, "origin.js"), "utf8");
const hook = fs.readFileSync(path.join(root, "page-hook.js"), "utf8");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));

assert.match(background, /selectCallerOrigin\(/);
assert.match(background, /importScripts\("origin-select\.js"\)/);
assert.doesNotMatch(background, /Date\.now\(\) - frame\.at/);
assert.match(originJs, /calling:\s*true/);
assert.match(originJs, /location\.origin/);
assert.doesNotMatch(originJs, /pointerdown|keydown|addEventListener\("focus"/);
assert.match(hook, /creds\.create/);
assert.match(hook, /fidolizer-caller/);
assert.match(hook, /fidolizer-ack/);
assert.ok(
  manifest.content_scripts.some(
    (script) =>
      script.js.includes("page-hook.js") &&
      script.world === "MAIN" &&
      script.all_frames === true &&
      script.run_at === "document_start",
  ),
);
assert.ok(manifest.permissions.includes("webAuthenticationProxy"));
assert.match(background, /chrome\.webAuthenticationProxy\.attach\(/);
assert.match(background, /onCreateRequest/);
assert.match(background, /onGetRequest/);
assert.match(background, /onIsUvpaaRequest/);
assert.match(background, /isUvpaa:\s*true/);
assert.match(background, /sendNativeMessage\(HOST/);

console.log("origin-select tests passed");
