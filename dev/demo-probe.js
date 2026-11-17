'use strict';

// Loaded only by demo-server's explicit --probe-file option. All interaction
// still happens in the visible browser; the probe observes those real frames.
let layoutTimer;
let motionTimer;
const reportLayout = () => {
  clearTimeout(layoutTimer);
  layoutTimer = setTimeout(() => console.info('UI_PROBE_LAYOUT ' + JSON.stringify(window.__uiProbe.layout('body'))), 500);
};
window.addEventListener('load', reportLayout);
window.addEventListener('resize', reportLayout);
document.addEventListener('click', () => {
  clearTimeout(motionTimer);
  window.__uiProbe.slow(5);
  window.__uiProbe.watch('body', { ms: 4000 });
  motionTimer = setTimeout(() => {
    console.info('UI_PROBE_MOTION ' + JSON.stringify(window.__uiProbe.report()));
    window.__uiProbe.slow(1);
    reportLayout();
  }, 4000);
}, true);
