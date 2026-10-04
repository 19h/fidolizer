// Isolated world. The page hook posts fidolizer-caller from the frame that
// is about to call credentials.create or get. Report that frame, then ack
// so the hook proceeds. Ignore every other message: a child frame's load
// is not the caller.
window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data || data.type !== "fidolizer-caller" || typeof data.requestId !== "string") return;
  const requestId = data.requestId;
  const reply = () => {
    try {
      window.postMessage({type: "fidolizer-ack", requestId}, location.origin);
    } catch (err) {}
  };
  try {
    chrome.runtime.sendMessage({
      type: "fidolizer-origin",
      origin: location.origin,
      calling: true,
    }).then(reply, reply);
  } catch (err) {
    reply();
  }
});
