import { component$ } from "@qwik.dev/core";
import { DocumentHeadTags, RouterOutlet, useQwikRouter } from "@qwik.dev/router";

// The stylesheet is a plain static file (public/global.css), linked explicitly. Importing CSS
// from src/ would make Qwik inline it as a <style> tag in production (blocked by our CSP, which
// has no 'unsafe-inline' for styles) and would not load it at all under `vp dev` (SSR in workerd).
const STYLESHEET = "/global.css";

export default component$(() => {
  useQwikRouter();

  return (
    <>
      <head>
        <meta charset="utf-8" />
        {/* viewport-fit=cover: the layout pads itself with env(safe-area-inset-*) (global.css). */}
        <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
        <meta name="color-scheme" content="light dark" />
        <meta name="theme-color" media="(prefers-color-scheme: light)" content="#ffffff" />
        <meta name="theme-color" media="(prefers-color-scheme: dark)" content="#000000" />
        <meta name="referrer" content="no-referrer" />
        <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
        <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png" />
        <link rel="manifest" href="/manifest.json" />
        <link rel="stylesheet" href={STYLESHEET} />
        <DocumentHeadTags />
      </head>
      <body>
        <RouterOutlet />
      </body>
    </>
  );
});
