/* VoIP Health Check — theme controller.
 * Applies data-theme="light" or data-theme="dark" to <html>, which the
 * stylesheet keys off via :root[data-theme="light"]. Attribute-on-root
 * means we never depend on body existing and never race the parser.
 *
 * The early "blocking" set is done by a tiny inline snippet in base.html
 * (kept there to avoid a flash of wrong theme). This file owns the toggle
 * button wiring and the system-preference listener.
 */
(function () {
    var STORAGE_KEY = 'avs-theme';
    var root = document.documentElement;

    function safeGet() {
        try { return window.localStorage && localStorage.getItem(STORAGE_KEY); }
        catch (e) { return null; }
    }
    function safeSet(value) {
        try { window.localStorage && localStorage.setItem(STORAGE_KEY, value); }
        catch (e) { /* sandboxed iframe / privacy mode — ignore */ }
    }

    function prefersLight() {
        try {
            return !!(window.matchMedia &&
                window.matchMedia('(prefers-color-scheme: light)').matches);
        } catch (e) { return false; }
    }

    function currentTheme() {
        var saved = safeGet();
        if (saved === 'light' || saved === 'dark') return saved;
        var attr = root.getAttribute('data-theme');
        if (attr === 'light' || attr === 'dark') return attr;
        return prefersLight() ? 'light' : 'dark';
    }

    function syncButton(theme) {
        var btn = document.querySelector('[data-theme-toggle]');
        if (!btn) return;
        var isLight = theme === 'light';
        btn.setAttribute('aria-pressed', isLight ? 'true' : 'false');
        btn.textContent = isLight ? '🌙 Dark' : '☀️ Light';
    }

    function apply(theme) {
        root.setAttribute('data-theme', theme);
        syncButton(theme);
    }

    function toggleTheme() {
        var next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
        apply(next);
        safeSet(next);
    }
    window.toggleTheme = toggleTheme;

    function init() {
        apply(currentTheme());
        var btn = document.querySelector('[data-theme-toggle]');
        if (btn && !btn.dataset.bound) {
            btn.addEventListener('click', toggleTheme);
            btn.dataset.bound = '1';
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    try {
        var mql = window.matchMedia('(prefers-color-scheme: light)');
        var listener = function (e) {
            if (safeGet()) return; /* user override exists */
            apply(e.matches ? 'light' : 'dark');
        };
        if (mql.addEventListener) mql.addEventListener('change', listener);
        else if (mql.addListener) mql.addListener(listener);
    } catch (e) { /* ignore */ }
})();
