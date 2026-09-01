import { describe, expect, it, vi } from "vitest";
import type { AuditService } from "../../apps/api/src/audit/audit.service.js";
import type { AuthenticatedUser } from "../../apps/api/src/auth/auth.types.js";
import type { PrismaService } from "../../apps/api/src/database/prisma.service.js";
import { ModelProvidersService } from "../../apps/api/src/model-providers/model-providers.service.js";
import type { QueuePublisherService } from "../../apps/api/src/queue/queue-publisher.service.js";
import { ScansService } from "../../apps/api/src/scans/scans.service.js";

describe("Day 4 tenant and provider boundaries", () => {
  it("does not query findings when the scan is outside the requested workspace", async () => {
    const findingQuery = vi.fn();
    const prisma = {
      scan: { findFirst: vi.fn().mockResolvedValue(null) },
      finding: { findMany: findingQuery },
    } as unknown as PrismaService;
    const service = new ScansService(prisma, {} as AuditService, {} as QueuePublisherService);
    await expect(service.findings("workspace-a", "scan-from-workspace-b")).rejects.toThrowError(
      /does not exist in this workspace/,
    );
    expect(findingQuery).not.toHaveBeenCalled();
  });

  it("requires system-administrator authority to configure a provider", async () => {
    const service = new ModelProvidersService({} as PrismaService, {} as AuditService);
    const actor: AuthenticatedUser = {
      id: "workspace-owner",
      email: "owner@example.test",
      isSystemAdmin: false,
    };
    await expect(
      service.configure("workspace-a", actor, {
        name: "private-qwen",
        baseUrl: "http://qwen:8000",
        modelName: "Qwen/Qwen3.8-27B",
      }),
    ).rejects.toThrowError(/requires a system administrator/);
  });
});
