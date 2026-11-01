// The desktop app's page: the window's attributes and the platform first (the engine starts with it), then @segv/ui
// rendered in the client.
// Qwik's loader, which dispatches the UI's events, is a script of its own in index.html (vite.config.ts).
import "@segv/ui/global.css";
import "./desktop.css";
import { render } from "@qwik.dev/core";
import { configureEngine } from "@segv/engine";
import { App } from "@segv/ui";
import { markWindow, moveByTitleBar } from "./chrome";
import { followOpens, platform } from "./platform";

markWindow();
configureEngine(platform());
followOpens().catch((e: unknown) => console.error("segv: could not follow links", e));
moveByTitleBar();
// Not `void render(…)`: Qwik's optimizer drops a `void` statement whose operand holds a pure JSX node.
render(document.body, <App />).catch((e: unknown) => console.error("segv: could not render", e));
