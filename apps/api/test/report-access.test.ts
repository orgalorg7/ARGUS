import { BadRequestException, NotFoundException } from "@nestjs/common";
import { describe, expect, it } from "vitest";
import { resolveStoredReportPath } from "../src/scans/scans.service.js";

describe("report storage boundary", () => {
  const root = "/srv/aasp/reports";

  it("resolves generated formats only inside the report root", () => {
    expect(
      resolveStoredReportPath(
        root,
        "/srv/aasp/reports/scan-1/scan-report.html",
        "json",
        "COMPLETE_SCAN",
      ),
    ).toBe("/srv/aasp/reports/scan-1/scan-report.json");
    expect(
      resolveStoredReportPath(
        root,
        "/srv/aasp/reports/scan-1/scan-report.html",
        "pdf-ready",
        "COMPLETE_SCAN",
      ),
    ).toBe("/srv/aasp/reports/scan-1/scan-report.pdf-ready.html");
  });

  it("rejects a persisted path that escapes the configured report store", () => {
    expect(() => resolveStoredReportPath(root, "/etc/passwd", "html", "COMPLETE_SCAN")).toThrow(
      NotFoundException,
    );
    expect(() =>
      resolveStoredReportPath(root, "/srv/aasp/reports/../secrets.txt", "html", "COMPLETE_SCAN"),
    ).toThrow(NotFoundException);
  });

  it("does not invent a PDF-ready standalone vulnerability file", () => {
    expect(() =>
      resolveStoredReportPath(
        root,
        "/srv/aasp/reports/scan-1/findings/FIND-0001.html",
        "pdf-ready",
        "VULNERABILITY",
      ),
    ).toThrow(BadRequestException);
  });
});
