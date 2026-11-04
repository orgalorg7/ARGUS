import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { GovernanceError } from "./context.js";

function encryptionKey(): Buffer {
  const value = process.env["EVIDENCE_ENCRYPTION_KEY"] ?? "";
  const key = Buffer.from(value, "base64");
  if (key.length !== 32 || key.toString("base64") !== value)
    throw new GovernanceError(503, "EVIDENCE_VAULT_NOT_CONFIGURED");
  return key;
}

export function sealDocument(content: Buffer, context: string): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  cipher.setAAD(Buffer.from(context));
  const ciphertext = Buffer.concat([cipher.update(content), cipher.final()]);
  return Buffer.concat([Buffer.from([1]), iv, cipher.getAuthTag(), ciphertext]);
}

export function openDocument(sealed: Uint8Array, context: string, hash: string): Buffer {
  const bytes = Buffer.from(sealed);
  if (bytes.length < 30 || bytes[0] !== 1)
    throw new GovernanceError(409, "DOCUMENT_INTEGRITY_FAILURE");
  try {
    const decipher = createDecipheriv("aes-256-gcm", encryptionKey(), bytes.subarray(1, 13));
    decipher.setAAD(Buffer.from(context));
    decipher.setAuthTag(bytes.subarray(13, 29));
    const content = Buffer.concat([decipher.update(bytes.subarray(29)), decipher.final()]);
    if (createHash("sha256").update(content).digest("hex") !== hash)
      throw new Error("Hash mismatch");
    return content;
  } catch (error) {
    if (error instanceof GovernanceError) throw error;
    throw new GovernanceError(409, "DOCUMENT_INTEGRITY_FAILURE");
  }
}
