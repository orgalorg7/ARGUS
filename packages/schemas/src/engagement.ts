import { z } from "zod";

const label = z.string().trim().min(2).max(160);
export const reasonSchema = z.string().trim().min(10).max(2000);
export const createClientSchema = z.object({ name: label, legalName: label }).strict();
export const createEngagementSchema = z
  .object({
    clientId: z.string().min(1).max(128),
    name: label,
    objective: z.string().trim().min(10).max(4000),
    environment: z.enum(["PRODUCTION", "STAGING", "DEVELOPMENT", "LAB"]),
  })
  .strict();
export const engagementPolicySchema = z
  .object({
    expectedVersion: z.number().int().positive(),
    reason: reasonSchema,
    targetIds: z
      .array(z.string().min(1).max(128))
      .min(1)
      .max(100)
      .refine((ids) => new Set(ids).size === ids.length, "Duplicate targets are not allowed."),
    windowStartsAt: z.string().datetime({ offset: true }),
    windowEndsAt: z.string().datetime({ offset: true }),
    maxRequests: z.number().int().min(1).max(100000),
    requestsPerSecond: z.number().min(0.1).max(20),
    maxConcurrency: z.number().int().min(1).max(10),
    maxRisk: z.enum(["PASSIVE", "SAFE", "LOW_IMPACT"]),
    allowedCategories: z
      .array(z.enum(["DISCOVERY", "HTTP_CONFIGURATION", "AUTHORIZATION"]))
      .min(1)
      .max(3),
    allowedProtocols: z
      .array(z.enum(["http:", "https:"]))
      .min(1)
      .max(2),
    restrictions: z.string().trim().min(10).max(4000),
  })
  .strict()
  .refine(
    (p) => new Date(p.windowEndsAt) > new Date(p.windowStartsAt),
    "Testing window must end after it starts.",
  );
export const transitionEngagementSchema = z
  .object({
    expectedVersion: z.number().int().positive(),
    reason: reasonSchema,
    to: z.enum([
      "DRAFT",
      "SCOPING",
      "AWAITING_AUTHORIZATION",
      "AUTHORIZED",
      "SCHEDULED",
      "ACTIVE",
      "TESTING",
      "INTERNAL_REVIEW",
      "CLIENT_REVIEW",
      "REMEDIATION",
      "RETEST",
      "COMPLETED",
      "ARCHIVED",
    ]),
  })
  .strict();
export const authorizationGrantSchema = z
  .object({
    expectedVersion: z.number().int().positive(),
    reason: reasonSchema,
    documentId: z.string().min(1).max(128),
    authorizedBy: label,
    validFrom: z.string().datetime({ offset: true }),
    validUntil: z.string().datetime({ offset: true }),
  })
  .strict()
  .refine(
    (p) => new Date(p.validUntil) > new Date(p.validFrom),
    "Authorization must end after it starts.",
  );
export const authorizationDocumentSchema = z
  .object({
    filename: z
      .string()
      .trim()
      .min(1)
      .max(180)
      .regex(/^[\p{L}\p{N}_. ()-]+$/u),
    contentType: z.enum(["application/pdf", "text/plain"]),
    contentBase64: z
      .string()
      .min(4)
      .max(1400000)
      .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/),
  })
  .strict();
