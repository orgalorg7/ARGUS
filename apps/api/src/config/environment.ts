export interface Environment {
  nodeEnv: "development" | "test" | "production";
  apiPort: number;
  databaseUrl: string;
  redisUrl: string;
  jwtSecret: string;
  jwtExpiresIn: string;
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Required environment variable ${name} is missing.`);
  return value;
}

export function loadEnvironment(): Environment {
  const nodeEnv = process.env["NODE_ENV"] ?? "development";
  if (nodeEnv !== "development" && nodeEnv !== "test" && nodeEnv !== "production") {
    throw new Error("NODE_ENV must be development, test, or production.");
  }
  const jwtSecret = required("JWT_SECRET");
  if (jwtSecret.length < 32) throw new Error("JWT_SECRET must contain at least 32 characters.");
  const apiPort = Number(process.env["API_PORT"] ?? "3001");
  if (!Number.isInteger(apiPort) || apiPort < 1 || apiPort > 65_535)
    throw new Error("API_PORT is invalid.");
  return {
    nodeEnv,
    apiPort,
    databaseUrl: required("DATABASE_URL"),
    redisUrl: required("REDIS_URL"),
    jwtSecret,
    jwtExpiresIn: process.env["JWT_EXPIRES_IN"] ?? "15m",
  };
}
