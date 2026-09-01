import { ForbiddenException, type ExecutionContext } from "@nestjs/common";
import type { Reflector } from "@nestjs/core";
import { describe, expect, it, vi } from "vitest";
import type { PrismaService } from "../src/database/prisma.service.js";
import { WorkspaceRbacGuard } from "../src/rbac/workspace-rbac.guard.js";

function context(workspaceId: string, userId: string): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({
        params: { workspaceId },
        user: { id: userId, email: "analyst@example.test", isSystemAdmin: false },
      }),
    }),
    getHandler: () => function handler() {},
    getClass: () => class Controller {},
  } as unknown as ExecutionContext;
}

function guardWith(roleName: "OWNER" | "ADMIN" | "ANALYST" | "VIEWER" | null) {
  const findFirst = vi.fn().mockResolvedValue(roleName ? { name: roleName } : null);
  const prisma = { role: { findFirst } } as unknown as PrismaService;
  const reflector = {
    getAllAndOverride: vi.fn().mockReturnValue(["OWNER", "ADMIN", "ANALYST"]),
  } as unknown as Reflector;
  return { guard: new WorkspaceRbacGuard(reflector, prisma), findFirst };
}

describe("workspace RBAC and tenant boundary", () => {
  it("rejects a user who has no membership in the requested workspace", async () => {
    const { guard, findFirst } = guardWith(null);
    await expect(guard.canActivate(context("workspace-b", "user-a"))).rejects.toThrowError(
      ForbiddenException,
    );
    expect(findFirst).toHaveBeenCalledWith({
      where: { members: { some: { workspaceId: "workspace-b", userId: "user-a" } } },
    });
  });

  it("prevents a VIEWER from entering a scan-start role boundary", async () => {
    const { guard } = guardWith("VIEWER");
    await expect(guard.canActivate(context("workspace-a", "viewer-a"))).rejects.toThrowError(
      ForbiddenException,
    );
  });

  it("allows an ANALYST who belongs to the requested workspace", async () => {
    const { guard } = guardWith("ANALYST");
    await expect(guard.canActivate(context("workspace-a", "analyst-a"))).resolves.toBe(true);
  });
});
