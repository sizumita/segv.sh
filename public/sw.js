// The push Service Worker (docs/PROTOCOL.md §11.13). It only shows the one fixed notification a push carries and
// opens the app when it is tapped. No fetch handler, no caches, no keys, no requests, no storage: the app's pages and
// scripts always come from the network, and nothing here can read a message.
"use strict";

const FIXED = { title: "segv.sh", body: "new messages", tag: "segv" };

/** The notification of a declarative push message (W3C Push API), or the fixed one for anything else. */
function notificationOf(data) {
  let m = null;
  try {
    m = data ? data.json() : null;
  } catch {
    m = null;
  }
  const n =
    m && m.web_push === 8030 && m.notification && typeof m.notification === "object"
      ? m.notification
      : null;
  const str = (v, d) => (typeof v === "string" && v.length > 0 && v.length <= 256 ? v : d);
  let navigate = "/";
  if (n && typeof n.navigate === "string") {
    try {
      const u = new URL(n.navigate, self.location.origin);
      if (u.origin === self.location.origin) navigate = u.href;
    } catch {
      // keep "/"
    }
  }
  return {
    title: str(n && n.title, FIXED.title),
    body: str(n && n.body, FIXED.body),
    tag: str(n && n.tag, FIXED.tag),
    navigate,
  };
}

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

// Every push shows a notification (userVisibleOnly: iOS revokes a subscription whose pushes show none).
self.addEventListener("push", (event) => {
  const n = notificationOf(event.data);
  event.waitUntil(
    self.registration.showNotification(n.title, {
      body: n.body,
      tag: n.tag,
      data: { navigate: n.navigate },
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const data = event.notification.data;
  const target = data && typeof data.navigate === "string" ? data.navigate : "/";
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      for (const w of windows) {
        if (new URL(w.url).origin === self.location.origin && "focus" in w) return w.focus();
      }
      return self.clients.openWindow(target);
    })(),
  );
});
