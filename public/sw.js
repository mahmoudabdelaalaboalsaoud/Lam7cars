/* Service Worker بسيط: مطلوب تقنيًا عشان متصفحات أندرويد/كروم تسمح بتثبيت
   الموقع كتطبيق. بيخزّن بس الملفات الثابتة (الأيقونات، manifest) مؤقتًا
   لسرعة التحميل، وبيجيب الصفحة نفسها من الإنترنت أولاً دايمًا عشان أي
   تحديث جديد يوصل فورًا، ومايتخزنش بيانات فايربيز/سوبابيز خالص. */
const CACHE_NAME = "kasr100-shell-v1";
const SHELL = ["/manifest.json", "/icons/icon-192.png", "/icons/icon-512.png"];

self.addEventListener("install", (e) => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE_NAME).then((c) => c.addAll(SHELL)).catch(() => {}));
});

self.addEventListener("activate", (e) => {
  self.clients.claim();
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
  );
});

self.addEventListener("fetch", (e) => {
  if (e.request.method !== "GET") return;
  const url = new URL(e.request.url);
  if (url.origin !== location.origin) return; // نسيب طلبات Firebase/Supabase للشبكة العادية دايمًا

  if (e.request.mode === "navigate") {
    // الصفحة نفسها: الشبكة أولاً (تحديث فوري)، والكاش بس لو مفيش إنترنت
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
    return;
  }

  e.respondWith(
    caches.match(e.request).then((cached) => {
      const fetchPromise = fetch(e.request)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((c) => c.put(e.request, copy)).catch(() => {});
          return res;
        })
        .catch(() => cached);
      return cached || fetchPromise;
    })
  );
});
