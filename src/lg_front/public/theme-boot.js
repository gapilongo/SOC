// Applies the colour theme (the stored choice, else the system's) and the table density
// before the first paint, so a light-theme user sees no dark flash. A classic script from 'self' (the CSP allows
// no inline script). src/theme/theme.tsx and density.tsx own both settings after
// start-up; keep the keys and values in step with src/lib/prefs.ts.
(function () {
  var root = document.documentElement;
  var theme = 'dark';
  var density = 'compact';
  try {
    var systemLight = Boolean(window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches);
    // No stored choice follows the system, like "system" itself.
    if (systemLight) theme = 'light';
    var stored = window.localStorage.getItem('lg-sotf.theme');
    if (stored === 'light' || stored === 'dark') theme = stored;
    if (window.localStorage.getItem('lg-sotf.density') === 'comfortable') density = 'comfortable';
  } catch (e) {
    // Storage unavailable: the system theme and the compact density apply.
  }
  root.setAttribute('data-theme', theme);
  root.setAttribute('data-density', density);
})();
