/**
 * Stable protocol error codes and the ApiError shape (spec §8.1).
 * Codes are stable machine identifiers; messages are for operators only and
 * never appear inside signed/audit material.
 */

export type ApiErrorBody = { error: { code: string; retryable: boolean; action_id: string | null } };

export class LexError extends Error {
  readonly code: string;
  readonly status: number;
  readonly retryable: boolean;
  readonly actionId: string | null;

  constructor(code: string, status: number, retryable = false, actionId: string | null = null, message?: string) {
    super(message ?? code);
    this.code = code;
    this.status = status;
    this.retryable = retryable;
    this.actionId = actionId;
  }

  body(): ApiErrorBody {
    return { error: { code: this.code, retryable: this.retryable, action_id: this.actionId } };
  }
}

/** Status mapping per spec §8.1. Codes not listed here are programming errors. */
const STATUS: Record<string, number> = {
  INVALID_JSON: 400, DUPLICATE_KEY: 400,
  AUTH_REQUIRED: 401,
  FORBIDDEN: 403, SELF_REVIEW: 403, HUMAN_REQUIRED: 403, AUTH_REVOKED: 403,
  NOT_FOUND: 404,
  STATE_CONFLICT: 409, REVISION_CONFLICT: 409, HASH_MISMATCH: 409,
  IDEMPOTENCY_CONFLICT: 409, DRIFT: 409, SCOPE_DENY: 409, HARD_DENY: 409,
  EXPIRED: 410, PAYLOAD_GONE: 410,
  BODY_TOO_LARGE: 413,
  CONTENT_TYPE: 415,
  SCHEMA_INVALID: 422, CONFIRM_REQUIRED: 422, POLICY_INVALID: 422,
  VIEW_REQUIRED: 422, UNSUPPORTED_VERSION: 422, ROTATION_INVALID: 422,
  CAPACITY: 429, RATE_LIMIT: 429,
  DEPENDENCY_UNAVAILABLE: 503, AUDIT_UNAVAILABLE: 503, CLOCK_UNSAFE: 503,
  UNSUPPORTED_ADAPTER: 503, ADAPTER_PROTOCOL: 503,
  // Offline / harness-only codes (no HTTP mapping needed but keep stable):
  YAML_FEATURE_FORBIDDEN: 400, YAML_INVALID: 400,
  ANCHOR_REQUIRED: 422,
};

const RETRYABLE = new Set([
  "DEPENDENCY_UNAVAILABLE", "AUDIT_UNAVAILABLE", "CLOCK_UNSAFE",
  "CAPACITY", "RATE_LIMIT", "UNSUPPORTED_ADAPTER", "ADAPTER_PROTOCOL",
]);

export function err(code: string, actionId: string | null = null, message?: string): LexError {
  const status = STATUS[code] ?? 500;
  return new LexError(code, status, RETRYABLE.has(code), actionId, message);
}

export function toErrorBody(e: unknown): { status: number; body: ApiErrorBody } {
  if (e instanceof LexError) return { status: e.status, body: e.body() };
  return { status: 500, body: { error: { code: "INTERNAL", retryable: false, action_id: null } } };
}
