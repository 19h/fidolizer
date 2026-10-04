importScripts("origin-select.js");

const HOST = "com.fidolizer.webauthn";

const focused = new Map();

chrome.runtime.onMessage.addListener((message, sender) => {
  if (!message || message.type !== "fidolizer-origin" || message.calling !== true) return;
  const origin = usableOrigin(typeof message.origin === "string" ? message.origin : "");
  if (!origin || !sender || !sender.tab) return;
  const now = Date.now();
  const kept = (focused.get(sender.tab.id) || []).filter((report) => now - report.at < 30000);
  kept.push({
    origin,
    frameId: sender.frameId,
    at: now,
    calling: true,
  });
  focused.set(sender.tab.id, kept);
});

async function callerContext() {
  const tabs = await chrome.tabs.query({active: true, lastFocusedWindow: true});
  const tab = tabs && tabs[0];
  if (!tab) throw new Error("caller origin is unknown");
  const origin = selectCallerOrigin({
    tabUrl: tab.url,
    reports: focused.get(tab.id) || [],
    now: Date.now(),
  });
  if (!origin) throw new Error("caller origin is unknown");
  return {origin, top: usableOrigin(originOf(tab.url))};
}

function completeError(kind, requestId, err) {
  const error = {
    name: "NotAllowedError",
    message: err && err.message ? err.message : String(err),
  };
  if (kind === "create") {
    return chrome.webAuthenticationProxy.completeCreateRequest({requestId, error});
  }
  return chrome.webAuthenticationProxy.completeGetRequest({requestId, error});
}

async function handle(kind, request) {
  try {
    const caller = await callerContext();
    const response = await chrome.runtime.sendNativeMessage(HOST, {
      type: kind,
      origin: caller.origin,
      crossOrigin: Boolean(caller.top && caller.top !== caller.origin),
      topOrigin: caller.top,
      request: JSON.parse(request.requestDetailsJson),
    });
    if (!response || response.error) {
      const error = (response && response.error) || {
        name: "NotAllowedError",
        message: "fidolizer returned no credential",
      };
      if (kind === "create") {
        await chrome.webAuthenticationProxy.completeCreateRequest({
          requestId: request.requestId,
          error,
        });
      } else {
        await chrome.webAuthenticationProxy.completeGetRequest({
          requestId: request.requestId,
          error,
        });
      }
      return;
    }
    const responseJson = JSON.stringify(response);
    if (kind === "create") {
      await chrome.webAuthenticationProxy.completeCreateRequest({
        requestId: request.requestId,
        responseJson,
      });
    } else {
      await chrome.webAuthenticationProxy.completeGetRequest({
        requestId: request.requestId,
        responseJson,
      });
    }
  } catch (err) {
    await completeError(kind, request.requestId, err);
  }
}

chrome.webAuthenticationProxy.onCreateRequest.addListener((request) => {
  return handle("create", request);
});

chrome.webAuthenticationProxy.onGetRequest.addListener((request) => {
  return handle("get", request);
});

chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener((request) => {
  chrome.webAuthenticationProxy.completeIsUvpaaRequest({
    requestId: request.requestId,
    isUvpaa: true,
  });
});

function attach() {
  chrome.webAuthenticationProxy.attach().catch((err) => {
    console.error("fidolizer attach failed", err);
  });
}

attach();
chrome.runtime.onStartup.addListener(attach);
chrome.runtime.onInstalled.addListener(attach);
