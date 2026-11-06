// Applies the stored colour theme and table density before the first paint, so a
// light-theme user sees no dark flash. A classic script from 'self' (the CSP allows
// no inline script). src/theme/theme.tsx and density.tsx own both settings after
// start-up; keep the keys and values in step with src/lib/prefs.ts.
(function () {
  var root = document.documentElement;
  var theme = 'dark';
  var density = 'compact';
  try {
    var stored = window.localStorage.getItem('lg-sotf.theme');
    if (stored === 'light') theme = 'light';
    else if (stored === 'system' && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) theme = 'light';
    if (window.localStorage.getItem('lg-sotf.density') === 'comfortable') density = 'comfortable';
  } catch (e) {
    // Storage unavailable: the defaults apply.
  }
  root.setAttribute('data-theme', theme);
  root.setAttribute('data-density', density);
})();
