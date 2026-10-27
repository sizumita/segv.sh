// Placeholder for the protocol v2 client engine (docs/PROTOCOL-v2.md §11; docs/STAGE1-PLAN.md M6).
//
// The v1 engine was removed when v2 replaced v1 in place. Until the v2 engine lands, the app loads this
// stand-in: it implements the Engine contract, starts in the "fatal" phase with an explanation, and refuses
// every operation, so the UI renders and nothing pretends to work. `?mock` in dev still gives the in-memory
// mock engine (src/client/mock-engine.ts) for UI work.
import type { Engine, EngineState } from "./types";

const NOT_READY =
  "this build is between protocol versions: messaging returns with the protocol v2 engine";

const STATE: EngineState = {
  phase: "fatal",
  progress: "",
  error: NOT_READY,
  me: null,
  conversations: [],
  head: { seq: 0, h: "" },
  connected: false,
  syncing: false,
  warnings: [],
  prfSupported: null,
};

const refuse = async (): Promise<never> => {
  throw new Error(NOT_READY);
};

class PlaceholderEngine implements Engine {
  getState(): EngineState {
    return STATE;
  }
  subscribe(fn: (s: EngineState) => void): () => void {
    fn(STATE);
    return () => {};
  }
  register = refuse;
  login = refuse;
  loginWithRecovery = refuse;
  addPasskey = refuse;
  async logout(): Promise<void> {}
  createConversation = refuse;
  sendText = refuse;
  sendImage = refuse;
  addMembers = refuse;
  removeMember = refuse;
  leave = refuse;
  loadImage = refuse;
  markRead(): void {}
  clearError(): void {}
}

let engine: Engine | undefined;

export function getEngine(): Engine {
  engine ??= new PlaceholderEngine();
  return engine;
}
