(function () {
    var STORAGE_KEY = 'avs-theme';

    function safeGet() {
        try { return window.localStorage && localStorage.getItem(STORAGE_KEY); }
        catch (e) { return null; }
    }
    function safeSet(value) {
        try { window.localStorage && localStorage.setItem(STORAGE_KEY, value); }
        catch (e) { /* sandboxed iframe — ignore */ }
    }

    function prefersLight() {
        try {
            return window.matchMedia &&
                window.matchMedia('(prefers-color-scheme: light)').matches;
        } catch (e) { return false; }
    }

    function apply(theme) {
        if (!document.body) return;
        if (theme === 'light') document.body.classList.add('light-mode');
        else document.body.classList.remove('light-mode');
        var btn = document.querySelector('[data-theme-toggle]');
        if (btn) {
            btn.setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
            btn.textContent = theme === 'light' ? '🌙 Dark mode' : '☀️ Light mode';
        }
    }

    function currentTheme() {
        var saved = safeGet();
        if (saved === 'light' || saved === 'dark') return saved;
        return prefersLight() ? 'light' : 'dark';
    }

    function toggleTheme() {
        var next = document.body.classList.contains('light-mode') ? 'dark' : 'light';
        apply(next);
        safeSet(next);
    }
    window.toggleTheme = toggleTheme;

    function init() { apply(currentTheme()); }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    try {
        var mql = window.matchMedia('(prefers-color-scheme: light)');
        var listener = function (e) {
            if (safeGet()) return; // user override exists
            apply(e.matches ? 'light' : 'dark');
        };
        if (mql.addEventListener) mql.addEventListener('change', listener);
        else if (mql.addListener) mql.addListener(listener);
    } catch (e) { /* ignore */ }
})();
