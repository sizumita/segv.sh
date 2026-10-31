/**
 * SSR renderer used by Qwik Router (the only place the Qwik renderer is called; the browser
 * resumes). The CSP nonce is generated per request in src/routes/plugin@csp.ts; Qwik Router
 * passes it in `opts.serverData.nonce`, and the renderer adds it to every script/modulepreload
 * it emits. It is forwarded explicitly here so a future refactor cannot silently drop it.
 */
import { createRenderer } from "@qwik.dev/router";
import Root from "./root";

export default createRenderer((opts) => {
  return {
    jsx: <Root />,
    options: {
      ...opts,
      containerAttributes: {
        lang: "en",
        ...opts.containerAttributes,
      },
      serverData: {
        ...opts.serverData,
        nonce: opts.serverData?.nonce,
      },
    },
  };
});
