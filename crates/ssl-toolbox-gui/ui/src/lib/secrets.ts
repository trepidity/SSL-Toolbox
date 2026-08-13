/**
 * Passphrase handling rules for the webview side.
 *
 * A passphrase typed here lives in a JS heap that neither Rust nor the OS can
 * scrub on demand — there is no `zeroize` for a JS string. The Rust side takes
 * care of its half (`Secret` zeroizes on drop and is never serialized back), so
 * what is left to us is: keep the exposure short and narrow.
 *
 * Rules, enforced by using the helpers here rather than raw state:
 *
 * 1. A passphrase lives in exactly one component's local state, never in a
 *    context, store, `localStorage`, or URL.
 * 2. It is cleared as soon as the operation submits — success or failure.
 * 3. It is never written into a `JobRecord`, a log line, or an error message.
 * 4. It is never round-tripped: the backend cannot send one back.
 */

import { useCallback, useState } from "react";

export interface SecretField {
  /** Current value — bind to an `<input type="password">`. */
  value: string;
  /** Update handler for the input. */
  set: (next: string) => void;
  /** Wipe the value. Call after submit, in a `finally`. */
  clear: () => void;
}

/**
 * A passphrase input bound to component-local state only.
 *
 * Prefer this over a bare `useState` so the clearing discipline is visible at
 * the call site and easy to audit.
 */
export function useSecret(): SecretField {
  const [value, setValue] = useState("");
  const clear = useCallback(() => setValue(""), []);
  return { value, set: setValue, clear };
}

/**
 * Clear several passphrase fields at once.
 *
 * Call in a `finally` so a thrown error cannot leave a passphrase sitting in a
 * mounted component.
 */
export function clearSecrets(...fields: SecretField[]): void {
  for (const field of fields) field.clear();
}
