import { component$ } from "@qwik.dev/core";
import type { DocumentHead } from "@qwik.dev/router";
import { App } from "~/components/app";

// The whole UI is one client-driven page. Nothing user-specific is rendered or loaded on the
// server (no routeLoader$/server$): the server never sees a secret.
export default component$(() => <App />);

export const head: DocumentHead = {
  title: "segv.sh",
  meta: [
    {
      name: "description",
      content: "end-to-end encrypted messenger on a public, append-only log.",
    },
  ],
};
