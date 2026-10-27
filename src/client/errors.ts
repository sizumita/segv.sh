// Error types shared by the engine modules.

/** An error whose message is meant for the user (shown as-is in `state.error`). */
export class UserError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UserError";
  }
}

/** The session ended (sign-out, or another account signed in) while an operation was running. */
export class SessionEnded extends UserError {
  constructor() {
    super("signed out");
    this.name = "SessionEnded";
  }
}

export function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
