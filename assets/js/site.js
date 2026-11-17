/* BOZKURT — paylaşılan küçük davranışlar */
(() => {
  const root = document.querySelector('[data-lang-switch]');
  if (!root) return;
  document.addEventListener('click', (event) => {
    if (!root.contains(event.target)) root.removeAttribute('open');
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') root.removeAttribute('open');
  });
})();
