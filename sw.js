/* Jurnal Trading v2.5.0 — cache file aplikasi agar berjalan offline */
const CACHE = "jurnal-trading-2.5.0-mw9evm8l";
const FILES = ["./","apple-touch-icon.png","favicon.svg","icon-192.png","icon-512.png","icon.svg","index.html","manifest.webmanifest","vendor/chart.umd.js","vendor/ed25519-verify.js","vendor/fonts/archivo-latin-ext.woff2","vendor/fonts/archivo-latin.woff2","vendor/fonts/fonts.css","vendor/fonts/inter-latin-ext.woff2","vendor/fonts/inter-latin.woff2","vendor/fonts/jetbrainsmono-latin.woff2"];
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== location.origin) return;
  if (req.mode === 'navigate') {
    e.respondWith(caches.match('./index.html').then(r => r || fetch(req)));
    return;
  }
  e.respondWith(caches.match(req, { ignoreSearch: true }).then(r => r || fetch(req)));
});
