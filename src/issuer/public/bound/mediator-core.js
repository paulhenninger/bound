// The message handling of the mediator popup, kept free of DOM and network
// code so it can be tested on its own.
//
// Trust comes from the browser, not from parameters: we learn which site is
// asking from MessageEvent.origin, and we deliver tokens with
// postMessage(..., thatOrigin), so they can only reach that site.

/**
 * Listen for the opener's request.
 *   win:        the popup's window (addEventListener, setInterval, clearInterval)
 *   opener:     window.opener (must be non-null)
 *   isAllowed:  origin policy, e.g. isAllowedRpOrigin
 *   onRequest({ rpOrigin, request })   called once, for the first acceptable request
 *   onRefused(message)                 called if the first request comes from a refused origin
 * Returns { respond(msg), stop() }.
 */
export function listenForRequest({ win, opener, isAllowed, onRequest, onRefused, interval = 250 }) {
  let rpOrigin = null;
  let done = false;
  // Announce readiness until the opener answers. This message carries nothing secret.
  const ping = () => opener.postMessage({ type: 'bound:ready' }, '*');
  const timer = win.setInterval(ping, interval);
  ping();

  function onMessage(e) {
    if (done || e.source !== opener || e.data?.type !== 'bound:request') return;
    done = true;
    win.clearInterval(timer);
    if (!isAllowed(e.origin)) { onRefused('Only HTTPS sites can sign in with Bound ID.'); return; }
    rpOrigin = e.origin;   // authenticated by the browser
    const d = e.data;
    onRequest({
      rpOrigin,
      request: {
        nonce: d.nonce, jkt: d.jkt,
        claims: Array.isArray(d.claims) ? d.claims.filter((c) => typeof c === 'string') : [],
        access: d.access && typeof d.access === 'object' ? d.access : undefined,
      },
    });
  }
  win.addEventListener('message', onMessage);

  return {
    /** Deliver the result to the requesting origin only. */
    respond(msg) {
      if (!rpOrigin) throw new Error('no request to respond to');
      opener.postMessage({ type: 'bound:response', ...msg }, rpOrigin);
    },
    stop() { done = true; win.clearInterval(timer); win.removeEventListener('message', onMessage); },
  };
}
