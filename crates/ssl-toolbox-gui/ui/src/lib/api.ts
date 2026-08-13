import { invoke } from "@tauri-apps/api/core";
import type {
  ActionInfo,
  OpOutcome,
  OpRequest,
  SessionState,
  ValidationAuditEntry,
  WorkspaceSnapshot,
} from "./types";

/**
 * Errors arrive from Rust as plain strings (see `CmdResult` in `src/lib.rs`).
 * Normalize anything else so a caller never has to render `[object Object]`.
 */
function normalizeError(error: unknown): Error {
  if (typeof error === "string") return new Error(error);
  if (error instanceof Error) return error;
  return new Error("An unexpected error occurred");
}

/** Run one toolbox operation. The single route to functionality, as in the CLI. */
export async function runOp(request: OpRequest): Promise<OpOutcome> {
  try {
    return await invoke<OpOutcome>("run_op", { request });
  } catch (error) {
    throw normalizeError(error);
  }
}

export async function listActions(): Promise<ActionInfo[]> {
  return invoke<ActionInfo[]>("list_actions");
}

export async function loadSession(): Promise<SessionState> {
  return invoke<SessionState>("load_session");
}

export async function scanWorkspace(root?: string): Promise<WorkspaceSnapshot> {
  try {
    return await invoke<WorkspaceSnapshot>("scan_workspace", { root: root ?? null });
  } catch (error) {
    throw normalizeError(error);
  }
}

export async function defaultExportDir(host: string, port: number): Promise<string> {
  return invoke<string>("default_export_dir", { host, port });
}

export async function validationHistory(): Promise<ValidationAuditEntry[]> {
  return invoke<ValidationAuditEntry[]>("validation_history");
}
