CREATE TYPE "FindingTrendStatus" AS ENUM (
  'NEW',
  'RECURRING',
  'RESOLVED',
  'REGRESSED',
  'CHANGED',
  'UNVERIFIED'
);

CREATE TYPE "RemediationPriority" AS ENUM (
  'FIX_NOW',
  'FIX_NEXT',
  'PLANNED',
  'HARDENING'
);

ALTER TYPE "ReportType" ADD VALUE IF NOT EXISTS 'EXECUTIVE' BEFORE 'COMPLETE_SCAN';
ALTER TYPE "ReportType" ADD VALUE IF NOT EXISTS 'EXECUTIVE_PDF_READY' BEFORE 'COMPLETE_SCAN';

ALTER TABLE "Finding"
  ADD COLUMN "trendStatus" "FindingTrendStatus" NOT NULL DEFAULT 'NEW',
  ADD COLUMN "remediationPriority" "RemediationPriority" NOT NULL DEFAULT 'HARDENING',
  ADD COLUMN "recurrenceCount" INTEGER NOT NULL DEFAULT 1,
  ADD COLUMN "previousFindingId" TEXT;

ALTER TABLE "Finding"
  ADD CONSTRAINT "Finding_previousFindingId_fkey"
  FOREIGN KEY ("previousFindingId") REFERENCES "Finding"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

CREATE INDEX "Finding_workspaceId_scanId_trendStatus_idx"
  ON "Finding"("workspaceId", "scanId", "trendStatus");
CREATE INDEX "Finding_previousFindingId_idx" ON "Finding"("previousFindingId");

CREATE TABLE "ScanComparison" (
  "id" TEXT NOT NULL,
  "workspaceId" TEXT NOT NULL,
  "scanId" TEXT NOT NULL,
  "previousScanId" TEXT,
  "coverageSufficient" BOOLEAN NOT NULL,
  "coverageRatio" DOUBLE PRECISION NOT NULL,
  "summary" JSONB NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "ScanComparison_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ScanComparison_scanId_key" ON "ScanComparison"("scanId");
CREATE INDEX "ScanComparison_workspaceId_createdAt_idx"
  ON "ScanComparison"("workspaceId", "createdAt");
CREATE INDEX "ScanComparison_previousScanId_idx" ON "ScanComparison"("previousScanId");

ALTER TABLE "ScanComparison"
  ADD CONSTRAINT "ScanComparison_workspaceId_fkey"
  FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "ScanComparison"
  ADD CONSTRAINT "ScanComparison_scanId_fkey"
  FOREIGN KEY ("scanId") REFERENCES "Scan"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "ScanComparison"
  ADD CONSTRAINT "ScanComparison_previousScanId_fkey"
  FOREIGN KEY ("previousScanId") REFERENCES "Scan"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

CREATE TABLE "FindingComparison" (
  "id" TEXT NOT NULL,
  "scanComparisonId" TEXT NOT NULL,
  "currentFindingId" TEXT,
  "previousFindingId" TEXT,
  "correlationKey" TEXT NOT NULL,
  "trendStatus" "FindingTrendStatus" NOT NULL,
  "severityBefore" "Severity",
  "severityAfter" "Severity",
  "reason" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "FindingComparison_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "FindingComparison_scanComparisonId_correlationKey_key"
  ON "FindingComparison"("scanComparisonId", "correlationKey");
CREATE INDEX "FindingComparison_currentFindingId_idx"
  ON "FindingComparison"("currentFindingId");
CREATE INDEX "FindingComparison_previousFindingId_idx"
  ON "FindingComparison"("previousFindingId");

ALTER TABLE "FindingComparison"
  ADD CONSTRAINT "FindingComparison_scanComparisonId_fkey"
  FOREIGN KEY ("scanComparisonId") REFERENCES "ScanComparison"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "FindingComparison"
  ADD CONSTRAINT "FindingComparison_currentFindingId_fkey"
  FOREIGN KEY ("currentFindingId") REFERENCES "Finding"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "FindingComparison"
  ADD CONSTRAINT "FindingComparison_previousFindingId_fkey"
  FOREIGN KEY ("previousFindingId") REFERENCES "Finding"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;
