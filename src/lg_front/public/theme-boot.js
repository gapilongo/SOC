// Applies the colour theme and table density before the first paint, so nobody sees a
// flash of the other theme. A classic script from 'self' (the CSP allows no inline
// script). The theme follows the system unless the user chose light or dark.
// src/theme/theme.tsx and density.tsx own both settings after start-up; keep the keys
// and values in step with src/lib/prefs.ts.
(function () {
  var root = document.documentElement;
  var theme = 'system';
  var density = 'compact';
  try {
    var stored = window.localStorage.getItem('lg-sotf.theme');
    if (stored === 'light' || stored === 'dark') theme = stored;
    var rows = window.localStorage.getItem('lg-sotf.density');
    if (rows === 'comfortable' || rows === 'dense') density = rows;
  } catch (e) {
    // Storage unavailable: the defaults apply.
  }
  if (theme === 'system') {
    theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  root.setAttribute('data-theme', theme);
  root.setAttribute('data-density', density);
})();
