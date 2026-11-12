// Runs before first paint (a classic script in <head>): sets the theme so the page never flashes the wrong one.
// 'mc-theme' holds the user's own choice (light or dark); without it the page follows the system. main.js keeps
// data-theme current afterwards.
(function () {
  var theme = null;
  try { theme = localStorage.getItem('mc-theme'); } catch (error) { /* storage is optional */ }
  if (theme !== 'light' && theme !== 'dark') theme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  document.documentElement.dataset.theme = theme;
})();
