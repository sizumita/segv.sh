// Entry of the push Service Worker: bundled to /sw.js by the `segv:sw` plugin in vite.config.ts (docs/PROTOCOL.md §11.13).
import { install, type SwScope } from "./sw-core";

install(self as unknown as SwScope);
