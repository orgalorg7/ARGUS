BEGIN;
ALTER TABLE "Report" ADD COLUMN "jsonSha256" TEXT;

-- Reject inconsistent legacy links before enabling guards; never silently discard evidence.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM "FindingEvidence" l JOIN "Finding" f ON f.id = l."findingId" JOIN "Evidence" e ON e.id = l."evidenceId" WHERE f."workspaceId" <> e."workspaceId" OR f."scanId" <> e."scanId")
  OR EXISTS (SELECT 1 FROM "FindingOccurrence" l JOIN "Finding" f ON f.id = l."findingId" JOIN "ScannerObservation" o ON o.id = l."observationId" WHERE f."workspaceId" <> o."workspaceId" OR f."scanId" <> o."scanId")
  OR EXISTS (SELECT 1 FROM "ResourceIdentityRelationship" l JOIN "AuthorizedResource" r ON r.id = l."resourceId" JOIN "AssessmentIdentity" i ON i.id = l."identityId" WHERE r."workspaceId" <> i."workspaceId" OR r."targetId" <> i."targetId")
  THEN RAISE EXCEPTION 'Legacy security links require a reviewed tenant repair before upgrade'; END IF;
END; $$;

CREATE OR REPLACE FUNCTION reject_tenant_reassignment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD."workspaceId" <> NEW."workspaceId"
    OR to_jsonb(OLD)->'scanId' IS DISTINCT FROM to_jsonb(NEW)->'scanId'
    OR to_jsonb(OLD)->'targetId' IS DISTINCT FROM to_jsonb(NEW)->'targetId'
  THEN RAISE EXCEPTION 'Tenant and assessment reassignment is prohibited' USING ERRCODE = '23514'; END IF;
  RETURN NEW;
END; $$;
COMMIT;
