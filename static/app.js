/**
 * Campus Portal — VULNERABLE version JavaScript
 *
 * VULN 1d: DOM-based XSS via innerHTML
 * The welcome banner reads location.hash and writes it to the DOM using
 * innerHTML, which allows injected HTML event handlers to execute.
 *
 * Payload URL: /dashboard#<img src=x onerror=alert('dom-xss')>
 */

document.addEventListener("DOMContentLoaded", function () {
  renderWelcomeBanner();
});
window.addEventListener("hashchange", renderWelcomeBanner);

function renderWelcomeBanner() {
  var banner = document.getElementById("welcome-banner");
  if (!banner) return;

  // VULN 1d: innerHTML used with user-controlled location.hash — DOM XSS
  var name = location.hash ? location.hash.slice(1) : banner.dataset.username;
  if (location.hash) {
    try {
      name = decodeURIComponent(name);
    } catch (error) {
      // Keep malformed percent escapes as text instead of stopping the script.
    }
  }
  banner.innerHTML = "Welcome back, " + name + "!";
}
