-- Replace technical ownership verification with a permissioned, persisted
-- assessment-scope boundary. Existing verified targets become scope-ready;
-- pending targets remain drafts until their scope is saved.

DROP TABLE IF EXISTS "TargetVerification";

ALTER TYPE "TargetStatus" RENAME TO "TargetStatus_old";
CREATE TYPE "TargetStatus" AS ENUM (
  'DRAFT',
  'READY',
  'SCANNING',
  'COMPLETED',
  'FAILED',
  'CANCELLED',
  'DISABLED'
);
ALTER TABLE "Target" ALTER COLUMN "status" DROP DEFAULT;
ALTER TABLE "Target"
  ALTER COLUMN "status" TYPE "TargetStatus"
  USING (
    CASE "status"::text
      WHEN 'VERIFIED' THEN 'READY'
      WHEN 'PENDING_VERIFICATION' THEN 'DRAFT'
      WHEN 'REJECTED' THEN 'DISABLED'
      ELSE 'DISABLED'
    END
  )::"TargetStatus";
ALTER TABLE "Target" ALTER COLUMN "status" SET DEFAULT 'DRAFT';
DROP TYPE "TargetStatus_old";

ALTER TABLE "Target"
  ADD COLUMN "includeSubdomains" BOOLEAN NOT NULL DEFAULT false,
  DROP COLUMN "authorizationExpiresAt",
  DROP COLUMN "verifiedAt";

DROP TYPE IF EXISTS "VerificationStatus";
DROP TYPE IF EXISTS "VerificationMethod";

-- Existing targets already have an explicit HOST rule. Make their origin port
-- explicit as well so the migrated scope satisfies the same invariant as new
-- targets without widening it.
INSERT INTO "ScopeRule" ("id", "workspaceId", "targetId", "type", "value", "enabled", "createdAt")
SELECT
  'migrated-port-' || md5(target."id"),
  target."workspaceId",
  target."id",
  'PORT'::"ScopeRuleType",
  COALESCE(
    target."normalizedPort"::text,
    CASE WHEN target."origin" LIKE 'https://%' THEN '443' ELSE '80' END
  ),
  true,
  CURRENT_TIMESTAMP
FROM "Target" AS target
WHERE NOT EXISTS (
  SELECT 1
  FROM "ScopeRule" AS rule
  WHERE rule."targetId" = target."id"
    AND rule."type" = 'PORT'::"ScopeRuleType"
    AND rule."enabled" = true
);

-- WAITING_FOR_TARGET_VERIFICATION is no longer part of scan execution. Any
-- legacy scan that never progressed is returned to CREATED for an operator to
-- start under the configured-scope rule.
DELETE FROM "ScanStage" WHERE "name"::text = 'WAITING_FOR_TARGET_VERIFICATION';
ALTER TYPE "ScanState" RENAME TO "ScanState_old";
CREATE TYPE "ScanState" AS ENUM (
  'CREATED',
  'AUTHORIZED',
  'QUEUED',
  'VALIDATING_SCOPE',
  'DISCOVERY',
  'CRAWLING',
  'API_DISCOVERY',
  'FINGERPRINTING',
  'PASSIVE_ANALYSIS',
  'SAFE_ACTIVE_ANALYSIS',
  'NORMALIZING',
  'CORRELATING',
  'AI_ANALYSIS',
  'AI_ANALYSIS_WAITING_FOR_PROVIDER',
  'GENERATING_SCAN_REPORT',
  'GENERATING_VULNERABILITY_REPORTS',
  'COMPLETED',
  'COMPLETED_WITH_WARNINGS',
  'FAILED',
  'CANCELLED'
);
ALTER TABLE "Scan" ALTER COLUMN "state" DROP DEFAULT;
ALTER TABLE "Scan"
  ALTER COLUMN "state" TYPE "ScanState"
  USING (
    CASE
      WHEN "state"::text = 'WAITING_FOR_TARGET_VERIFICATION' THEN 'CREATED'
      ELSE "state"::text
    END
  )::"ScanState";
ALTER TABLE "ScanStage"
  ALTER COLUMN "name" TYPE "ScanState"
  USING "name"::text::"ScanState";
ALTER TABLE "Scan" ALTER COLUMN "state" SET DEFAULT 'CREATED';
DROP TYPE "ScanState_old";

-- Preserve resumability for jobs that were already queued or executing when
-- this migration was applied. Workers require the target reservation state.
UPDATE "Target" AS target
SET "status" = 'SCANNING'::"TargetStatus"
WHERE target."status" <> 'DISABLED'::"TargetStatus"
  AND EXISTS (
    SELECT 1
    FROM "Scan" AS scan
    WHERE scan."targetId" = target."id"
      AND scan."state" IN (
        'QUEUED'::"ScanState",
        'VALIDATING_SCOPE'::"ScanState",
        'DISCOVERY'::"ScanState",
        'CRAWLING'::"ScanState",
        'API_DISCOVERY'::"ScanState",
        'FINGERPRINTING'::"ScanState",
        'PASSIVE_ANALYSIS'::"ScanState",
        'SAFE_ACTIVE_ANALYSIS'::"ScanState",
        'NORMALIZING'::"ScanState",
        'CORRELATING'::"ScanState",
        'AI_ANALYSIS'::"ScanState",
        'AI_ANALYSIS_WAITING_FOR_PROVIDER'::"ScanState",
        'GENERATING_SCAN_REPORT'::"ScanState",
        'GENERATING_VULNERABILITY_REPORTS'::"ScanState"
      )
  );

-- Target lifecycle reflects the latest scan without relying on every queue
-- failure/cancellation handler to remember a second write.
CREATE OR REPLACE FUNCTION "sync_target_status_from_scan"()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW."state" IS DISTINCT FROM OLD."state" THEN
    IF NEW."state" = 'QUEUED'::"ScanState" THEN
      UPDATE "Target" SET "status" = 'SCANNING'::"TargetStatus" WHERE "id" = NEW."targetId";
    ELSIF NEW."state" IN ('COMPLETED'::"ScanState", 'COMPLETED_WITH_WARNINGS'::"ScanState") THEN
      UPDATE "Target" SET "status" = 'COMPLETED'::"TargetStatus" WHERE "id" = NEW."targetId";
    ELSIF NEW."state" = 'FAILED'::"ScanState" THEN
      UPDATE "Target" SET "status" = 'FAILED'::"TargetStatus" WHERE "id" = NEW."targetId";
    ELSIF NEW."state" = 'CANCELLED'::"ScanState" THEN
      UPDATE "Target" SET "status" = 'CANCELLED'::"TargetStatus" WHERE "id" = NEW."targetId";
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "Scan_sync_target_status"
AFTER UPDATE OF "state" ON "Scan"
FOR EACH ROW
EXECUTE FUNCTION "sync_target_status_from_scan"();
