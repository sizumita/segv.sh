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
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="color-scheme" content="light dark" />
        <meta name="referrer" content="no-referrer" />
        <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
        <link rel="stylesheet" href={STYLESHEET} />
        <DocumentHeadTags />
      </head>
      <body>
        <RouterOutlet />
      </body>
    </>
  );
});
