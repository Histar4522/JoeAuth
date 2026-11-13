(function () {
  var STORAGE_KEY = 'joeauth-theme';
  var VALID = { dark: true, light: true, auto: true };
  var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

  function getMode() {
    try {
      var saved = localStorage.getItem(STORAGE_KEY);
      if (saved && VALID[saved]) return saved;
    } catch {}
    return 'auto';
  }

  function resolveTheme(mode) {
    if (mode === 'auto') {
      return media && media.matches ? 'dark' : 'light';
    }
    return mode === 'light' ? 'light' : 'dark';
  }

  function applyTheme(mode) {
    var resolved = resolveTheme(mode);
    document.documentElement.setAttribute('data-bs-theme', resolved);
    document.querySelectorAll('.cf-turnstile').forEach(function (el) {
      el.setAttribute('data-theme', resolved);
    });
    document.querySelectorAll('[data-theme-select]').forEach(function (sel) {
      if (sel.value !== mode) sel.value = mode;
    });
    return resolved;
  }

  function setMode(mode) {
    var next = VALID[mode] ? mode : 'auto';
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {}
    return applyTheme(next);
  }

  applyTheme(getMode());

  if (media) {
    var onMediaChange = function () {
      if (getMode() === 'auto') applyTheme('auto');
    };
    if (media.addEventListener) media.addEventListener('change', onMediaChange);
    else if (media.addListener) media.addListener(onMediaChange);
  }

  document.addEventListener('DOMContentLoaded', function () {
    applyTheme(getMode());
    document.querySelectorAll('[data-theme-select]').forEach(function (sel) {
      sel.value = getMode();
      sel.addEventListener('change', function () {
        setMode(sel.value);
      });
    });
  });

  window.JoeAuthTheme = {
    getMode: getMode,
    getResolved: function () { return resolveTheme(getMode()); },
    setMode: setMode,
  };
})();
