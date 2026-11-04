BEGIN;

ALTER TABLE "Engagement" ADD CONSTRAINT "Engagement_valid_counters" CHECK (version >= 1 AND "policyRevision" >= 0 AND "requestsMade" >= 0);
ALTER TABLE "Target" ADD CONSTRAINT "Target_scope_revision_positive" CHECK ("scopeRevision" >= 1);
ALTER TABLE "EngagementPolicy" ADD CONSTRAINT "ROE_valid_limits" CHECK (
  revision > 0 AND "windowStartsAt" < "windowEndsAt" AND "maxRequests" BETWEEN 1 AND 100000
  AND "requestsPerSecond" BETWEEN 0.1 AND 20 AND "maxConcurrency" BETWEEN 1 AND 10
  AND cardinality("allowedCategories") BETWEEN 1 AND 3
  AND cardinality("allowedProtocols") BETWEEN 1 AND 2 AND "allowedProtocols" <@ ARRAY['http:', 'https:']::TEXT[]
);
ALTER TABLE "AuthorizationGrant" ADD CONSTRAINT "Grant_valid_window" CHECK ("validFrom" < "validUntil");
ALTER TABLE "AuthorizationDocument" ADD CONSTRAINT "Document_valid_integrity_metadata" CHECK (
  "byteLength" BETWEEN 1 AND 1048576 AND sha256 ~ '^[a-f0-9]{64}$' AND octet_length("encryptedContent") > 29
);
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_confidence_range" CHECK (confidence BETWEEN 0 AND 1);
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_grant_requires_engagement_actor" CHECK (
  "authorizationGrantId" IS NULL OR ("engagementId" IS NOT NULL AND "executionActorId" IS NOT NULL)
);

-- Actor references cannot disappear while custody or authorization records remain.
ALTER TABLE "EngagementPolicy" ADD FOREIGN KEY ("createdById") REFERENCES "User"(id) ON DELETE RESTRICT;
ALTER TABLE "AuthorizationDocument" ADD FOREIGN KEY ("uploadedById") REFERENCES "User"(id) ON DELETE RESTRICT;
ALTER TABLE "AuthorizationGrant" ADD FOREIGN KEY ("approvedById") REFERENCES "User"(id) ON DELETE RESTRICT;
ALTER TABLE "AuthorizationRevocation" ADD FOREIGN KEY ("actorId") REFERENCES "User"(id) ON DELETE RESTRICT;
ALTER TABLE "EngagementTransition" ADD FOREIGN KEY ("actorId") REFERENCES "User"(id) ON DELETE RESTRICT;
ALTER TABLE "EngagementTransition" ADD FOREIGN KEY ("grantId") REFERENCES "AuthorizationGrant"(id) ON DELETE RESTRICT;
ALTER TABLE "ExecutionDecision" ADD FOREIGN KEY ("actorId") REFERENCES "User"(id) ON DELETE RESTRICT;
ALTER TABLE "ExecutionDecision" ADD FOREIGN KEY ("workspaceId", "scanId") REFERENCES "Scan"("workspaceId", id) ON DELETE RESTRICT;
ALTER TABLE "ExecutionDecision" ADD FOREIGN KEY ("workspaceId", "engagementId", "grantId") REFERENCES "AuthorizationGrant"("workspaceId", "engagementId", id) ON DELETE RESTRICT;
ALTER TABLE "Scan" ADD FOREIGN KEY ("executionActorId") REFERENCES "User"(id) ON DELETE RESTRICT;

-- Legacy join tables lack tenant columns. Validate both parents on insert/update.
CREATE FUNCTION enforce_security_link_tenant() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE left_workspace TEXT; right_workspace TEXT; left_scan TEXT; right_scan TEXT;
BEGIN
  IF TG_TABLE_NAME = 'FindingEvidence' THEN
    SELECT "workspaceId", "scanId" INTO left_workspace, left_scan FROM "Finding" WHERE id = NEW."findingId";
    SELECT "workspaceId", "scanId" INTO right_workspace, right_scan FROM "Evidence" WHERE id = NEW."evidenceId";
  ELSIF TG_TABLE_NAME = 'FindingOccurrence' THEN
    SELECT "workspaceId", "scanId" INTO left_workspace, left_scan FROM "Finding" WHERE id = NEW."findingId";
    SELECT "workspaceId", "scanId" INTO right_workspace, right_scan FROM "ScannerObservation" WHERE id = NEW."observationId";
  ELSE
    SELECT "workspaceId", "targetId" INTO left_workspace, left_scan FROM "AuthorizedResource" WHERE id = NEW."resourceId";
    SELECT "workspaceId", "targetId" INTO right_workspace, right_scan FROM "AssessmentIdentity" WHERE id = NEW."identityId";
  END IF;
  IF left_workspace IS NULL OR right_workspace IS NULL OR left_workspace <> right_workspace OR left_scan <> right_scan THEN
    RAISE EXCEPTION 'Security link crosses tenant or assessment boundary' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER "FindingEvidence_tenant" BEFORE INSERT OR UPDATE ON "FindingEvidence" FOR EACH ROW EXECUTE FUNCTION enforce_security_link_tenant();
CREATE TRIGGER "FindingOccurrence_tenant" BEFORE INSERT OR UPDATE ON "FindingOccurrence" FOR EACH ROW EXECUTE FUNCTION enforce_security_link_tenant();
CREATE TRIGGER "ResourceIdentityRelationship_tenant" BEFORE INSERT OR UPDATE ON "ResourceIdentityRelationship" FOR EACH ROW EXECUTE FUNCTION enforce_security_link_tenant();

CREATE FUNCTION reject_security_record_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION '% records are append-only', TG_TABLE_NAME USING ERRCODE = '23514'; END; $$;
DO $$ DECLARE tab TEXT; BEGIN
  FOREACH tab IN ARRAY ARRAY['Evidence','AuditEvent','AuthorizationDocument','AuthorizationGrant','AuthorizationRevocation','EngagementPolicy','EngagementTarget','EngagementTransition','ExecutionDecision'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_security_record_mutation()', tab || '_append_only', tab);
  END LOOP;
END; $$;

-- Check transition records at commit, after the application writes the event in the same transaction.
CREATE FUNCTION require_engagement_transition_record() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.state <> NEW.state THEN
    IF NEW.version <> OLD.version + 1 OR NOT EXISTS (
      SELECT 1 FROM "EngagementTransition" t WHERE t."workspaceId" = NEW."workspaceId" AND t."engagementId" = NEW.id
      AND t.version = NEW.version AND t."fromState" = OLD.state AND t."toState" = NEW.state
      AND length(trim(t.reason)) >= 10 AND length(t."authorizationBasis") > 0
    ) THEN RAISE EXCEPTION 'Engagement transition requires versioned authorization and audit context' USING ERRCODE = '23514'; END IF;
  END IF;
  RETURN NULL;
END; $$;
CREATE CONSTRAINT TRIGGER "Engagement_transition_record" AFTER UPDATE ON "Engagement" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_engagement_transition_record();

COMMIT;
