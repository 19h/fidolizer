// Pure caller-origin choice shared by the service worker and the node test.
// A frame that only loaded, focused, or received a key must not replace the
// tab. The caller is the frame that invoked credentials.create or get.
// Otherwise the active tab's top origin is the caller.

function originOf(url) {
  try {
    const origin = new URL(url).origin;
    if (!origin || origin === "null") return null;
    return origin;
  } catch (err) {
    return null;
  }
}

function usableOrigin(value) {
  if (typeof value !== "string" || value.length === 0 || value === "null") return null;
  if (value.startsWith("chrome")) return null;
  return value;
}

function selectCallerOrigin({tabUrl, reports, now}) {
  const current = typeof now === "number" ? now : 0;
  let best = null;
  for (const report of reports || []) {
    if (!report || report.calling !== true) continue;
    if (typeof report.at !== "number") continue;
    const age = current - report.at;
    if (age < 0 || age >= 30000) continue;
    const origin = usableOrigin(report.origin);
    if (!origin) continue;
    if (!best || report.at >= best.at) best = {origin, at: report.at};
  }
  if (best) return best.origin;
  return usableOrigin(originOf(tabUrl));
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {originOf, usableOrigin, selectCallerOrigin};
}
