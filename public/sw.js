/* NOVA MK — Service Worker for Real Smartwatch OS Notification Relay & Caching */
self.addEventListener('install', event => {
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('message', event => {
  const data = event.data;
  if (!data || data.type !== 'NOVA_WATCH_NOTIFY') return;
  const delayMs = Math.max(0, Math.min(15000, Number(data.delayMs) || 0));
  const title = String(data.title || 'NOVA · Ton ami');
  const body = String(data.body || '');

  event.waitUntil(
    new Promise(resolve => setTimeout(resolve, delayMs)).then(() =>
      self.registration.showNotification(title, {
        body,
        vibrate: [250, 120, 250],
        tag: 'nova-watch-' + Date.now(),
        renotify: true,
        requireInteraction: false
      })
    )
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      for (const client of clients) {
        if ('focus' in client) return client.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow('/');
    })
  );
});
