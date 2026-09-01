import { PrismaClient, WorkspaceRole } from "@prisma/client";
import argon2 from "argon2";

const prisma = new PrismaClient();

const descriptions: Record<WorkspaceRole, string> = {
  OWNER: "Full workspace control, including membership and destructive administration.",
  ADMIN: "Workspace administration, target approval workflow, and assessment control.",
  ANALYST: "Target registration, verification, assessment execution, and finding review.",
  VIEWER: "Read-only access to authorized workspace assessment data.",
};

async function seed(): Promise<void> {
  for (const role of Object.values(WorkspaceRole)) {
    await prisma.role.upsert({
      where: { name: role },
      create: { name: role, description: descriptions[role] },
      update: { description: descriptions[role] },
    });
  }

  const email = process.env["ADMIN_EMAIL"]?.trim().toLowerCase();
  const password = process.env["ADMIN_PASSWORD"];
  if (!email || !password) {
    process.stdout.write(
      "Roles seeded. ADMIN_EMAIL/ADMIN_PASSWORD absent; no admin user created.\n",
    );
    return;
  }
  if (password.length < 16) {
    throw new Error("ADMIN_PASSWORD must contain at least 16 characters.");
  }

  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
  await prisma.user.upsert({
    where: { email },
    create: {
      email,
      passwordHash,
      displayName: "System Administrator",
      isSystemAdmin: true,
    },
    update: { passwordHash, isSystemAdmin: true, isActive: true },
  });
  process.stdout.write(`System administrator seeded for ${email}.\n`);
}

seed()
  .catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
