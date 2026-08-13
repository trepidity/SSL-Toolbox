import { useCallback, useState } from "react";
import { runOp } from "./api";
import type { OpOutcome, OpRequest } from "./types";

interface OpState {
  busy: boolean;
  error: string | null;
  outcome: OpOutcome | null;
  /** Run an operation, replacing any previous result. */
  run: (request: OpRequest) => Promise<OpOutcome | null>;
  reset: () => void;
}

/**
 * Drive a single operation with busy/error/result state.
 *
 * Errors are captured rather than thrown: a failed verification or a wrong
 * passphrase is an ordinary outcome in this tool, not an exception the user
 * should meet as a blank screen.
 */
export function useOp(): OpState {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<OpOutcome | null>(null);

  const run = useCallback(async (request: OpRequest) => {
    setBusy(true);
    setError(null);
    try {
      const result = await runOp(request);
      setOutcome(result);
      return result;
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      setOutcome(null);
      return null;
    } finally {
      setBusy(false);
    }
  }, []);

  const reset = useCallback(() => {
    setError(null);
    setOutcome(null);
  }, []);

  return { busy, error, outcome, run, reset };
}
