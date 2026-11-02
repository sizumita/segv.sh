/**
 * Vite+ config for the whole workspace: `vp lint`, `vp fmt` and `vp check` cover every package, and `vp test` runs
 * each package's test project (its own vite.config.ts). Each app keeps its dev and build config in its own directory
 * (apps/web/vite.config.ts).
 */
import { defineConfig } from "vite-plus";

export default defineConfig({
  // `vp lint` (oxlint). eslint-plugin-qwik runs as an oxlint JS plugin; its
  // qwik/valid-lexical-scope rule needs TS type info that JS plugins don't get -> off.
  lint: {
    plugins: ["oxc", "typescript", "unicorn"],
    jsPlugins: ["eslint-plugin-qwik"],
    categories: { correctness: "warn" },
    rules: {
      "qwik/valid-lexical-scope": "off",
      "qwik/use-method-usage": "error",
      "qwik/no-react-props": "error",
      "qwik/loader-location": "warn",
      "qwik/jsx-key": "warn",
      "qwik/unused-server": "error",
      "qwik/jsx-img": "warn",
      "qwik/jsx-a": "warn",
      "qwik/serializer-signal-usage": "error",
      "qwik/scope-use-task": "error",
    },
  },
  // docs/PROTOCOL.md is the protocol specification, copied verbatim from its author's text on every
  // revision, so it is never reformatted here. The sources of packages/protocol and packages/server have never been
  // formatted: they are formatted in a change of their own, which then removes them from this list. Oxfmt also skips
  // what .gitignore lists. It would read a .prettierignore as well, so patterns go here and nowhere else.
  fmt: {
    ignorePatterns: [
      "**/worker-configuration.d.ts",
      "**/dist/**",
      "apps/web/server/**",
      "apps/desktop/src-tauri/gen/**",
      "docs/PROTOCOL.md",
      "packages/protocol/src/**",
      "packages/server/src/**",
    ],
  },
  test: {
    projects: ["packages/*"],
  },
});
