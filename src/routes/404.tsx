import { component$ } from "@qwik.dev/core";
import type { DocumentHead } from "@qwik.dev/router";

// Replaces Qwik's built-in 404 page, whose inline <style> our CSP blocks.
export default component$(() => (
  <main class="page">
    <h1>404</h1>
    <p>
      nothing here. <a href="/">back to segv.sh</a>
    </p>
  </main>
));

export const head: DocumentHead = { title: "not found · segv.sh" };
