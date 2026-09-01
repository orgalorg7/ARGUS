export type ScopeBlockReason =
  | "INVALID_URL"
  | "UNEXPECTED_SCHEME"
  | "CREDENTIALS_IN_URL"
  | "SCOPE_NOT_CONFIGURED"
  | "HOST_NOT_AUTHORIZED"
  | "PORT_NOT_AUTHORIZED"
  | "PATH_EXCLUDED"
  | "RESOLUTION_FAILED"
  | "ADDRESS_BLOCKED"
  | "DNS_REBINDING_DETECTED"
  | "REDIRECT_LIMIT_EXCEEDED"
  | "UNSAFE_METHOD";

export class ScopeViolationError extends Error {
  readonly code = "SCOPE_VIOLATION";

  constructor(
    readonly reason: ScopeBlockReason,
    message: string,
    readonly url?: string,
  ) {
    super(message);
    this.name = "ScopeViolationError";
  }
}
