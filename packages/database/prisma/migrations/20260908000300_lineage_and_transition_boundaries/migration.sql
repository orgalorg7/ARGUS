BEGIN;
ALTER TABLE "EngagementTransition" DROP CONSTRAINT "EngagementTransition_grantId_fkey";
ALTER TABLE "EngagementTransition" ADD CONSTRAINT "EngagementTransition_workspaceId_engagementId_grantId_fkey" FOREIGN KEY ("workspaceId", "engagementId", "grantId") REFERENCES "AuthorizationGrant"("workspaceId", "engagementId", id) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "Finding" DROP CONSTRAINT "Finding_previousFindingId_fkey";
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_workspaceId_previousFindingId_fkey" FOREIGN KEY ("workspaceId", "previousFindingId") REFERENCES "Finding"("workspaceId", id) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "ScanComparison" DROP CONSTRAINT "ScanComparison_previousScanId_fkey";
ALTER TABLE "ScanComparison" ADD CONSTRAINT "ScanComparison_workspaceId_previousScanId_fkey" FOREIGN KEY ("workspaceId", "previousScanId") REFERENCES "Scan"("workspaceId", id) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "AuthorizationTestResult" DROP CONSTRAINT "AuthorizationTestResult_testCaseId_fkey";
ALTER TABLE "AuthorizationTestResult" ADD CONSTRAINT "AuthorizationTestResult_workspaceId_testCaseId_fkey" FOREIGN KEY ("workspaceId", "testCaseId") REFERENCES "AuthorizationTestCase"("workspaceId", id) ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE FUNCTION enforce_engagement_state_edge() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE allowed TEXT[];
BEGIN
  IF OLD.state = NEW.state THEN RETURN NEW; END IF;
  allowed := CASE OLD.state
    WHEN 'DRAFT' THEN ARRAY['SCOPING','ARCHIVED']
    WHEN 'SCOPING' THEN ARRAY['AWAITING_AUTHORIZATION','ARCHIVED']
    WHEN 'AWAITING_AUTHORIZATION' THEN ARRAY['SCOPING','AUTHORIZED','ARCHIVED']
    WHEN 'AUTHORIZED' THEN ARRAY['SCOPING','SCHEDULED']
    WHEN 'SCHEDULED' THEN ARRAY['SCOPING','ACTIVE']
    WHEN 'ACTIVE' THEN ARRAY['TESTING','SCOPING']
    WHEN 'TESTING' THEN ARRAY['INTERNAL_REVIEW','SCOPING']
    WHEN 'INTERNAL_REVIEW' THEN ARRAY['TESTING','CLIENT_REVIEW','SCOPING']
    WHEN 'CLIENT_REVIEW' THEN ARRAY['INTERNAL_REVIEW','REMEDIATION']
    WHEN 'REMEDIATION' THEN ARRAY['RETEST','COMPLETED','SCOPING']
    WHEN 'RETEST' THEN ARRAY['INTERNAL_REVIEW','REMEDIATION','COMPLETED','SCOPING']
    WHEN 'COMPLETED' THEN ARRAY['ARCHIVED']
    ELSE ARRAY[]::TEXT[] END;
  IF NOT NEW.state::TEXT = ANY(allowed) THEN RAISE EXCEPTION 'Illegal engagement state transition' USING ERRCODE = '23514'; END IF;
  RETURN NEW;
END; $$;
CREATE TRIGGER "Engagement_state_edge" BEFORE UPDATE ON "Engagement" FOR EACH ROW EXECUTE FUNCTION enforce_engagement_state_edge();

-- A linked parent cannot be moved to another tenant after validating its children.
CREATE FUNCTION reject_tenant_reassignment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD."workspaceId" <> NEW."workspaceId" THEN RAISE EXCEPTION 'Tenant reassignment is prohibited' USING ERRCODE = '23514'; END IF;
  RETURN NEW;
END; $$;
DO $$ DECLARE tab TEXT; BEGIN
  FOREACH tab IN ARRAY ARRAY['Client','Engagement','Target','Scan','ScannerObservation','Finding','AssessmentIdentity','AuthorizedResource','AuthorizationTestCase','DiscoveredEndpoint'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION reject_tenant_reassignment()', tab || '_immutable_tenant', tab);
  END LOOP;
END; $$;
COMMIT;
