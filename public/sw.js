self.addEventListener('install',event=>self.skipWaiting());
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
// Background push delivery is intentionally not advertised as enabled until
// authenticated subscriptions and VAPID delivery are configured server-side.
self.addEventListener('push',event=>{let data={};try{data=event.data?.json()||{}}catch{};event.waitUntil(self.registration.showNotification('Ping Lah! SG',{body:data.body||'You have a new ping.',icon:'/icon.svg',tag:'ping-lah-new-message'}))});
self.addEventListener('notificationclick',event=>{event.notification.close();event.waitUntil(self.clients.openWindow('/'))});
