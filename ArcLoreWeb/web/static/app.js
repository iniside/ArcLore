// ArcLoreWeb browser behaviors. Loaded once from layout.templ on every page.
//
// These listeners are externalized (rather than inline <script>/on* handlers) so
// the page can ship a strict Content-Security-Policy with script-src 'self' and
// no 'unsafe-inline'. Both listeners are delegated on document so they survive
// htmx #main-content swaps without re-binding.

(function () {
	// Copy-to-clipboard for any `.copy-btn`. The value to copy is carried in the
	// button's `data-copy` attribute (e.g. a repository ID or clone command).
	// Preserves the original visual feedback: swap the label to "Copied" for
	// 1200ms, then restore.
	document.addEventListener('click', function (e) {
		var btn = e.target.closest('.copy-btn');
		if (!btn) return;
		navigator.clipboard.writeText(btn.dataset.copy);
		var prev = btn.textContent;
		btn.textContent = 'Copied';
		setTimeout(function () { btn.textContent = prev; }, 1200);
	});

	// Destructive-action confirm guard for any `form[data-confirm]`. Shows the
	// confirm message; cancelling blocks the submit (replaces the prior inline
	// onsubmit="return confirm(...)").
	document.addEventListener('submit', function (e) {
		var form = e.target.closest('form[data-confirm]');
		if (!form) return;
		if (!window.confirm(form.dataset.confirm)) {
			e.preventDefault();
		}
	});
})();
