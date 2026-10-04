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
      const requestId = Math.random().toString(36);
      let settled = false;
      return new Promise((resolve, reject) => {
        function finish() {
          if (settled) return;
          settled = true;
          window.removeEventListener("message", onAck);
          Promise.resolve(original(options)).then(resolve, reject);
        }
        function onAck(event) {
          if (event.source !== window) return;
          const data = event.data;
          if (!data || data.type !== "fidolizer-ack" || data.requestId !== requestId) return;
          finish();
        }
        window.addEventListener("message", onAck);
        try {
          window.postMessage({type: "fidolizer-caller", requestId}, location.origin);
        } catch (err) {
          finish();
          return;
        }
        setTimeout(finish, 1000);
      });
    }
    wrapped.__fidolizer = true;
    creds[name] = wrapped;
  }

  wrap("create");
  wrap("get");
})();
