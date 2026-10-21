// Protect consent buttons against (double-)clickjacking: a page that opens
// this popup controls where it appears, and can time it so that a click meant
// for the page lands on "Allow". The buttons only work once the popup has been
// visible and focused for a moment, and are disarmed again whenever it loses
// focus or is hidden.

export function guardButtons(buttons, { win = window, doc = document, delay = 700 } = {}) {
  let timer = null;
  let armed = false;
  const set = (on) => { armed = on; for (const b of buttons) b.disabled = !on; };
  const disarm = () => { win.clearTimeout(timer); timer = null; set(false); };
  const arm = () => {
    disarm();
    if (doc.visibilityState !== 'visible' || !doc.hasFocus()) return;
    timer = win.setTimeout(() => set(true), delay);
  };
  const onVisibility = () => (doc.visibilityState === 'visible' ? arm() : disarm());
  win.addEventListener('focus', arm);
  win.addEventListener('blur', disarm);
  doc.addEventListener('visibilitychange', onVisibility);
  arm();
  return {
    get armed() { return armed; },
    dispose() {
      disarm();
      win.removeEventListener('focus', arm);
      win.removeEventListener('blur', disarm);
      doc.removeEventListener('visibilitychange', onVisibility);
    },
  };
}
