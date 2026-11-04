import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { redactText, redactUnknown } from "@aasp/security-core";
import type { CredentialMaterial } from "./types.js";

export interface EncryptedSecret {
  algorithm: "aes-256-gcm";
  ciphertext: string;
  iv: string;
  authTag: string;
  fingerprint: string;
}

function keyFromBase64(encodedKey: string): Buffer {
  const key = Buffer.from(encodedKey, "base64");
  if (key.length !== 32)
    throw new Error("Identity secret encryption key must be 32 bytes in base64.");
  return key;
}

export function encryptCredential(
  material: CredentialMaterial,
  encodedKey: string,
): EncryptedSecret {
  const plaintext = Buffer.from(JSON.stringify(material), "utf8");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", keyFromBase64(encodedKey), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    algorithm: "aes-256-gcm",
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    fingerprint: createHash("sha256").update(plaintext).digest("hex"),
  };
}

export function decryptCredential(secret: EncryptedSecret, encodedKey: string): CredentialMaterial {
  if (secret.algorithm !== "aes-256-gcm")
    throw new Error("Unsupported credential encryption algorithm.");
  const decipher = createDecipheriv(
    "aes-256-gcm",
    keyFromBase64(encodedKey),
    Buffer.from(secret.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(secret.authTag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(secret.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
  return JSON.parse(plaintext) as CredentialMaterial;
}

export function safeAuthenticationError(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error);
  return redactText(String(redactUnknown(raw))).slice(0, 500);
}
