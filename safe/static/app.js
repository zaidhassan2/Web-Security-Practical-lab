/**
 * Campus Portal — SAFE version JavaScript
 *
 * FIX 1d: DOM-based XSS prevented by using textContent instead of innerHTML.
 * location.hash is treated as plain text only — no HTML interpretation occurs.
 */

document.addEventListener("DOMContentLoaded", function () {
  renderWelcomeBanner();
});
window.addEventListener("hashchange", renderWelcomeBanner);

function renderWelcomeBanner() {
  var banner = document.getElementById("welcome-banner");
  if (!banner) return;

  // FIX 1d: textContent — browser never parses the value as HTML
  var name = location.hash ? location.hash.slice(1) : banner.dataset.username;
  if (location.hash) {
    try {
      name = decodeURIComponent(name);
    } catch (error) {
      // Keep malformed percent escapes as text instead of stopping the script.
    }
  }
  banner.textContent = "Welcome back, " + name + "!";
}
