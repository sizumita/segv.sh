/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** The deployment's canonical origin that a built app calls, or "" in `tauri dev` (vite.config.ts). */
  readonly SEGV_ORIGIN: string;
}
