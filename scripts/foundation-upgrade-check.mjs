import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { PrismaClient } from "../packages/database/dist/index.js";

const input = process.env.AASP_TEST_DATABASE_URL;
if (!input || !new URL(input).pathname.endsWith("_test"))
  throw new Error("Use an isolated AASP_TEST_DATABASE_URL ending in _test.");
const url = new URL(input);
const schema = `upgrade_${randomUUID().replaceAll("-", "")}`;
url.searchParams.set("schema", schema);
const scratch = await mkdtemp(resolve(tmpdir(), "pentest-upgrade-"));
const db = new PrismaClient({ datasourceUrl: url.toString() });
const root = resolve(import.meta.dirname, "..");

function migrate(schemaPath) {
  const run = spawnSync("pnpm", ["exec", "prisma", "migrate", "deploy", "--schema", schemaPath], {
    cwd: root,
    env: { ...process.env, DATABASE_URL: url.toString() },
    encoding: "utf8",
  });
  if (run.status !== 0) throw new Error(`Upgrade migration failed: ${run.stderr}\n${run.stdout}`);
}

try {
  // Migrate the real previous migration chain, insert legacy state, then apply the new chain.
  await mkdir(resolve(scratch, "migrations"));
  await writeFile(
    resolve(scratch, "schema.prisma"),
    await readFile(resolve(root, "packages/database/prisma/schema.prisma")),
  );
  const migrations = resolve(root, "packages/database/prisma/migrations");
  for (const name of await readdir(migrations))
    if (name < "20260908000100")
      await cp(resolve(migrations, name), resolve(scratch, "migrations", name), {
        recursive: true,
      });
  migrate(resolve(scratch, "schema.prisma"));
  await db.$executeRaw`INSERT INTO "User" (id,email,"passwordHash","displayName","updatedAt") VALUES ('legacy-user','legacy@synthetic.test','unused','Legacy owner',now())`;
  await db.$executeRaw`INSERT INTO "Role" (id,name,description) VALUES ('legacy-role','OWNER','Legacy owner')`;
  await db.$executeRaw`INSERT INTO "Workspace" (id,name,slug,"updatedAt") VALUES ('legacy-workspace','Legacy workspace','legacy',now())`;
  await db.$executeRaw`INSERT INTO "WorkspaceMember" (id,"workspaceId","userId","roleId") VALUES ('legacy-member','legacy-workspace','legacy-user','legacy-role')`;
  await db.$executeRaw`INSERT INTO "Target" (id,"workspaceId",name,origin,"normalizedHostname","createdById","updatedAt") VALUES ('legacy-target','legacy-workspace','Legacy target','https://example.test','example.test','legacy-user',now())`;
  await db.$executeRaw`INSERT INTO "Scan" (id,"workspaceId","targetId",name,"createdById","updatedAt") VALUES ('legacy-scan','legacy-workspace','legacy-target','Legacy scan','legacy-user',now())`;
  migrate(resolve(root, "packages/database/prisma/schema.prisma"));
  const workspace = await db.workspace.findUniqueOrThrow({
    where: { id: "legacy-workspace" },
    include: { organization: { include: { members: true } } },
  });
  assert.equal(workspace.organization.id, "org_legacy-workspace");
  assert.equal(workspace.organization.members[0].userId, "legacy-user");
  assert.equal(
    (await db.scan.findUniqueOrThrow({ where: { id: "legacy-scan" } })).authorizationGrantId,
    null,
  );
  assert.equal(await db.authorizationGrant.count(), 0);
  process.stdout.write(
    "Upgrade passed: legacy workspace, membership and scan preserved; no authorization invented.\n",
  );
} finally {
  // The schema name is generated here; it never comes from user-supplied SQL text.
  await db.$executeRawUnsafe(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
  await db.$disconnect();
  await rm(scratch, { recursive: true, force: true });
}
