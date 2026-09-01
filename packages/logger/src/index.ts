export interface LogContext {
  requestId?: string;
  workspaceId?: string;
  scanId?: string;
  jobId?: string;
  workerId?: string;
  scanner?: string;
  [key: string]: unknown;
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
    ...context,
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
