import { component$ } from "@qwik.dev/core";
import type { DocumentHead } from "@qwik.dev/router";

// Replaces Qwik's built-in error page (inline <style>, blocked by our CSP). Deliberately shows
// no details: error messages never reach the page. The reload button matters in the installed
// app, which has no browser toolbar.
export default component$(() => (
  <main class="page">
    <h1>error</h1>
    <p>
      something went wrong on the server. <a href="/">back to segv.sh</a>
    </p>
    <p>
      <button type="button" onClick$={() => location.reload()}>
        reload
      </button>
    </p>
  </main>
));

export const head: DocumentHead = { title: "error · segv.sh" };
