import { mkdtemp, rm, writeFile, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { readVerifiedReport } from "../src/scans/report-store.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});
async function artifact() {
  const root = await mkdtemp(join(tmpdir(), "pentest-report-"));
  roots.push(root);
  const path = join(root, "report.html");
  const text = "<html>Authorized report</html>";
  await writeFile(path, text);
  return { root, path, text, hash: createHash("sha256").update(text).digest("hex") };
}
describe("report download custody", () => {
  it("returns only verified bytes and rejects a modified report", async () => {
    const file = await artifact();
    expect((await readVerifiedReport(file.root, file.path, file.hash)).toString()).toBe(file.text);
    await writeFile(file.path, "altered risk statement");
    await expect(readVerifiedReport(file.root, file.path, file.hash)).rejects.toThrow(
      "integrity verification failed",
    );
  });
  it("rejects a symlink escaping the report store even if the digest matches", async () => {
    const own = await artifact();
    const other = await artifact();
    const path = join(own.root, "escaped.html");
    await symlink(other.path, path);
    await expect(readVerifiedReport(own.root, path, other.hash)).rejects.toThrow(
      "outside the report store",
    );
  });
  it("requires a recorded digest for legacy or untracked formats", async () => {
    const file = await artifact();
    await expect(readVerifiedReport(file.root, file.path, null)).rejects.toThrow("Regenerate");
  });
});
