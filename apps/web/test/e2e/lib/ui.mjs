// What a user does in @segv/ui, for any page that shows it: the web app in Chromium, or the desktop app's web view.
// Each function takes a device `d`, { name, page }, and finds the UI by its roles and labels.
import { readFile } from "node:fs/promises";
import { check, T, watch } from "./harness.mjs";

/**
 * A browser context of its own (a device) at `base`, with a virtual authenticator that supports PRF and approves
 * every request.
 */
export async function device(browser, base, name) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  await ctx.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) =>
      console.error(`CSP violation: ${e.violatedDirective} blocked=${e.blockedURI}`),
    );
  });
  const page = await ctx.newPage();
  watch(name, page);
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
    },
  });
  await page.goto(`${base}/`, { waitUntil: "load" });
  return { name, ctx, page };
}

export async function signedOut(d) {
  await d.page.getByRole("button", { name: "use recovery code" }).waitFor({ timeout: T });
}

export async function ready(d) {
  await d.page.locator("aside.left").waitFor({ timeout: T });
}

/** Creates an account with a passkey; `atCode` runs on the recovery code's screen. Returns the recovery code. */
export async function register(d, handle, { remember = false, atCode } = {}) {
  await d.page.getByRole("button", { name: "create account" }).waitFor({ timeout: T });
  if (remember) await d.page.getByLabel("remember this device").check();
  await d.page.getByLabel("handle", { exact: true }).fill(handle);
  await d.page.getByRole("button", { name: "create account" }).click();
  await d.page.getByText("save your recovery code").waitFor({ timeout: T });
  const code = (await d.page.locator(".code").innerText()).replace(/\s+/g, "-");
  check(/^([0-9A-Z]{4}-){7}[0-9A-Z]{4}$/.test(code), `unexpected recovery code format: ${code}`);
  await atCode?.();
  await d.page.getByLabel("i saved it").check();
  await d.page.getByRole("button", { name: "continue" }).click();
  await ready(d);
  return code;
}

/** Unlocks with a recovery code; `atForm` runs once the code is in its field. */
export async function unlockWithCode(d, code, { atForm } = {}) {
  await signedOut(d);
  await d.page.getByRole("button", { name: "use recovery code" }).click();
  await d.page.getByLabel("recovery code").fill(code.toLowerCase());
  await atForm?.();
  await d.page.getByRole("button", { name: "unlock" }).click();
  await ready(d);
}

export async function signInWithPasskey(d) {
  await signedOut(d);
  await d.page.getByRole("button", { name: "sign in with passkey" }).click();
  await ready(d);
}

/** Opens the settings dialog (add passkey, notifications, sign out) and returns it. */
export async function settings(d) {
  await d.page.getByRole("button", { name: "settings", exact: true }).click({ timeout: T });
  const dialog = d.page.getByRole("dialog", { name: "settings" });
  await dialog.waitFor({ timeout: T });
  return dialog;
}

export async function closeSettings(d) {
  const dialog = d.page.getByRole("dialog", { name: "settings" });
  await dialog.getByRole("button", { name: "close", exact: true }).click();
  await dialog.waitFor({ state: "hidden", timeout: T });
}

/** Opens the conversation's first image full size, and returns the viewer. */
export async function openImage(d) {
  await d.page.locator(".thread").getByRole("button", { name: "open image" }).first().click();
  const viewer = d.page.getByRole("dialog", { name: "image" });
  await viewer.waitFor({ timeout: T });
  return viewer;
}

export async function closeImage(d) {
  const viewer = d.page.getByRole("dialog", { name: "image" });
  await viewer.getByRole("button", { name: "close", exact: true }).click();
  await viewer.waitFor({ state: "hidden", timeout: T });
}

/**
 * Starts a conversation with `handles` ("bob" or "bob, carol") from the "new conversation" dialog, as the main handle:
 * each handle typed into its "people" box and added with Enter, then the group name if given (groups only: the dialog
 * has no name for a 1:1). `atForm` runs before "start" is pressed.
 */
export async function newConversation(d, handles, name, { atForm } = {}) {
  const list = handles.split(/[\s,]+/).filter(Boolean);
  if (name && list.length < 2)
    throw new Error(`newConversation: the dialog names only groups, not a 1:1 with ${handles}`);
  await d.page
    .locator(".newconv")
    .getByRole("button", { name: "new conversation", exact: true })
    .click({ timeout: T });
  const dialog = d.page.getByRole("dialog", { name: "new conversation" });
  await dialog.waitFor({ timeout: T });
  const people = dialog.getByRole("combobox", { name: "people" });
  for (const h of list) {
    await people.fill(h);
    await people.press("Enter");
    await dialog.getByRole("button", { name: `remove @${h}`, exact: true }).waitFor({ timeout: T });
  }
  if (name) await dialog.getByLabel("group name (optional)").fill(name);
  await atForm?.();
  await dialog.getByRole("button", { name: "start", exact: true }).click();
  await dialog.waitFor({ state: "hidden", timeout: T });
  const title = name ?? list.map((h) => `@${h}`).join(", ");
  await d.page.locator(".convhead .title", { hasText: title }).waitFor({ timeout: T });
  await d.page.getByLabel("message", { exact: true }).waitFor({ timeout: T });
}

/** Switches the left pane to a list (chats, requests, archives); the switcher shows once there is more than chats. */
async function showList(d, list, wait = false) {
  const lists = d.page.locator("nav.lists");
  if (!wait && !(await lists.isVisible())) return;
  await lists.getByRole("button", { name: list }).click({ timeout: T });
}

function listItem(d, convName) {
  return d.page.locator(".conv", { has: d.page.locator(".name", { hasText: convName }) }).first();
}

export async function open(d, convName) {
  await showList(d, "chats");
  const item = listItem(d, convName);
  await item.waitFor({ timeout: T });
  await item.click();
  await d.page.locator(".convhead .title", { hasText: convName }).waitFor({ timeout: T });
}

/** Opens a request, whose preview shows `text` without accepting it. `accept` then accepts it. */
export async function openRequest(d, convName, text) {
  await showList(d, "requests", true);
  await listItem(d, convName).click({ timeout: T });
  await d.page.locator(".convhead .title", { hasText: convName }).waitFor({ timeout: T });
  await seen(d, text);
  await d.page.waitForTimeout(1000); // reading it must not accept it
  check(await requestBar(d).isVisible(), `${d.name}: the request was accepted by opening it`);
  check(
    !(await d.page.getByLabel("message", { exact: true }).isVisible()),
    `${d.name}: a request shows a composer`,
  );
}

const requestBar = (d) => d.page.getByRole("region", { name: "request" });

export async function accept(d) {
  await requestBar(d).getByRole("button", { name: "accept", exact: true }).click();
  await d.page.getByLabel("message", { exact: true }).waitFor({ timeout: T });
}

export async function inList(d, list, convName) {
  await showList(d, list, true);
  await listItem(d, convName).waitFor({ timeout: T });
}

export async function send(d, text) {
  await d.page.getByLabel("message", { exact: true }).fill(text);
  await d.page.getByLabel("message", { exact: true }).press("Enter");
  await seen(d, text);
  await d.page.waitForFunction(() => !document.body.innerText.includes("sending…"), null, {
    timeout: T,
  });
}

/** Sends a 1600 × 900 PNG that shows `label`. */
export async function sendImage(d, label) {
  const bytes = await d.page.evaluate(async (label) => {
    const c = document.createElement("canvas");
    c.width = 1600;
    c.height = 900;
    const g = c.getContext("2d");
    g.fillStyle = "#123";
    g.fillRect(0, 0, 1600, 900);
    g.fillStyle = "#fc3";
    g.font = "120px monospace";
    g.fillText(label, 80, 480);
    const b = await new Promise((r) => c.toBlob(r, "image/png"));
    return Array.from(new Uint8Array(await b.arrayBuffer()));
  }, label);
  await d.page
    .getByLabel("attach image")
    .setInputFiles({ name: "pic.png", mimeType: "image/png", buffer: Buffer.from(bytes) });
  await d.page.getByRole("button", { name: "send", exact: true }).click();
  await d.page.locator('.thread img[src^="blob:"]').first().waitFor({ timeout: T });
}

/**
 * Sends a text file named `name` that holds `text`, as a file: "+", then "file" in its menu, then the file picker.
 * `atMenu` runs while the menu is open.
 */
export async function sendFile(d, name, text, { atMenu } = {}) {
  await d.page.getByRole("button", { name: "attach", exact: true }).click();
  const item = d.page.locator(".attach .menu").getByRole("button", { name: /^file\b/ });
  await item.waitFor({ timeout: T });
  await atMenu?.();
  const [chooser] = await Promise.all([
    d.page.waitForEvent("filechooser", { timeout: T }),
    item.click(),
  ]);
  check(chooser.isMultiple(), `${d.name}: the file picker takes several files`);
  await chooser.setFiles({ name, mimeType: "text/plain", buffer: Buffer.from(text, "utf8") });
  check(!(await d.page.locator(".attach .menu").isVisible()), `${d.name}: the menu stays open`);
  await d.page.getByRole("button", { name: "send", exact: true }).click();
  await d.page
    .locator(".thread")
    .getByRole("button", { name: `save ${name}` })
    .first()
    .waitFor({ timeout: T });
}

/** Saves the conversation's file `name` (a download) and returns what it holds, as UTF-8. */
export async function saveFile(d, name) {
  const save = d.page
    .locator(".thread")
    .getByRole("button", { name: `save ${name}` })
    .first();
  await save.waitFor({ timeout: T });
  const [download] = await Promise.all([
    d.page.waitForEvent("download", { timeout: T }),
    save.click(),
  ]);
  check(
    download.suggestedFilename() === name,
    `${d.name}: saved as ${download.suggestedFilename()}`,
  );
  return readFile(await download.path(), "utf8");
}

/** Waits until the conversation shows an image of `sendImage` decoded at its full width. */
export async function seenImage(d) {
  const img = d.page.locator('.thread img[src^="blob:"]').first();
  await img.waitFor({ timeout: T });
  await d.page.waitForFunction(
    () => {
      const i = document.querySelector('.thread img[src^="blob:"]');
      return i && i.complete && i.naturalWidth > 0;
    },
    null,
    { timeout: T },
  );
  const w = await img.evaluate((i) => i.naturalWidth);
  check(w === 1600, `${d.name}: decoded image width ${w}`);
}

export async function seen(d, text, timeout = T) {
  await d.page.locator(".thread").getByText(text, { exact: false }).first().waitFor({ timeout });
}

export async function notSeen(d, text, waitMs = 4000) {
  await d.page.waitForTimeout(waitMs);
  const n = await d.page.locator(".thread").getByText(text, { exact: false }).count();
  check(n === 0, `${d.name} should not see "${text}"`);
}

export async function openMembers(d) {
  const panel = d.page.locator("aside.members");
  if (!(await panel.isVisible()))
    await d.page.locator(".convhead").getByRole("button", { name: "members" }).click();
  await panel.waitFor({ timeout: T });
  return panel;
}

export async function closeMembers(d) {
  const panel = d.page.locator("aside.members");
  await panel.getByRole("button", { name: "close", exact: true }).click();
  await panel.waitFor({ state: "hidden", timeout: T });
}
