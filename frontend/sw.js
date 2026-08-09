const CACHE_NAME = 'squad-tracker-shell-v2';
const SHELL_FILES = ['/', '/manifest.json', '/icons/icon-192.png', '/icons/icon-512.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

// Network-first: this app is fundamentally live/online (WebSocket-driven),
// so we always prefer a fresh network response and only fall back to the
// cached shell if the network is unreachable (e.g. brief signal loss).
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});

// ---------- WEB PUSH ----------
// Fires even when the app/tab is fully closed, as long as the browser/OS
// keeps this service worker registered (that's the whole point of Web Push).
self.addEventListener('push', (event) => {
  let payload = { title: 'Squad Tracker', body: 'New activity in your room' };
  try {
    if (event.data) payload = event.data.json();
  } catch (e) { /* fall back to default payload above */ }

  event.waitUntil(
    self.registration.showNotification(payload.title || 'Squad Tracker', {
      body: payload.body || '',
      icon: '/icons/icon-192.png',
      badge: '/icons/icon-192.png',
      tag: 'squad-tracker-message',
      renotify: true,
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if ('focus' in client) return client.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow('/');
    })
  );
});
