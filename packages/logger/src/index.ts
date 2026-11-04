export interface LogContext {
  requestId?: string;
  workspaceId?: string;
  scanId?: string;
  jobId?: string;
  workerId?: string;
  scanner?: string;
  [key: string]: unknown;
}

const secretKey =
  /(authorization|cookie|password|passwd|secret|token|api[-_]?key|session|credential)/i;
const safePolicyKey = /^(access-control-allow-credentials|allowCredentials|credentialConfigured)$/i;
const bearer = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/giu;
const jwt = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/gu;

function redactLogValue(value: unknown, key = ""): unknown {
  if (secretKey.test(key) && !safePolicyKey.test(key)) return "[REDACTED]";
  if (Array.isArray(value)) return value.map((entry) => redactLogValue(entry));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([nestedKey, nested]) => [
        nestedKey,
        redactLogValue(nested, nestedKey),
      ]),
    );
  }
  return typeof value === "string"
    ? value.replace(bearer, "$1 [REDACTED]").replace(jwt, "[REDACTED_JWT]")
    : value;
}

function emit(
  level: "debug" | "info" | "warn" | "error",
  message: string,
  context: LogContext,
): void {
  const record = JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    message,
    ...(redactLogValue(context) as LogContext),
  });
  if (level === "error") process.stderr.write(`${record}\n`);
  else process.stdout.write(`${record}\n`);
}

export const logger = {
  debug: (message: string, context: LogContext = {}) => emit("debug", message, context),
  info: (message: string, context: LogContext = {}) => emit("info", message, context),
  warn: (message: string, context: LogContext = {}) => emit("warn", message, context),
  error: (message: string, context: LogContext = {}) => emit("error", message, context),
};
