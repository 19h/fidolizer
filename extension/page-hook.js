// Runs in the page world before site scripts. Waits until the extension has
// recorded this frame, then calls the real credentials method. That makes
// the service worker see the calling frame before onCreateRequest or
// onGetRequest.
(function () {
  const creds = navigator.credentials;
  if (!creds || typeof creds.create !== "function" || typeof creds.get !== "function") return;
  if (creds.create.__fidolizer) return;

  function wrap(name) {
    const original = creds[name].bind(creds);
    function wrapped(options) {
      // Chrome completes conditional mediation with NotAllowedError while a
      // webAuthenticationProxy extension is attached, and never delivers it.
      // Keep the promise pending until the page aborts it. Modal create and
      // get still go through the proxy.
      if (name === "get" && options && options.mediation === "conditional") {
        return new Promise((resolve, reject) => {
          const signal = options.signal;
          function abort() {
            reject(new DOMException("The operation was aborted.", "AbortError"));
          }
          if (!signal) return;
          if (signal.aborted) {
            abort();
            return;
          }
          signal.addEventListener("abort", abort, {once: true});
          void resolve;
        });
      }
      try {
        window.postMessage({type: "fidolizer-caller", requestId: Math.random().toString(36)}, location.origin);
      } catch (err) {}
      return original(options);
    }
    wrapped.__fidolizer = true;
    creds[name] = wrapped;
  }

  wrap("create");
  wrap("get");
})();
