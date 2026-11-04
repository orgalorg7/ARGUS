import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import { isAbsolute, relative } from "node:path";
import { createHash } from "node:crypto";
import { ConflictException, NotFoundException } from "@nestjs/common";

/** Read bounded, verified bytes before returning any part of a sensitive report. */
export async function readVerifiedReport(
  root: string,
  path: string,
  sha256: string | null,
): Promise<Buffer> {
  if (!sha256 || !/^[a-f0-9]{64}$/.test(sha256))
    throw new ConflictException("Report integrity metadata is unavailable. Regenerate the report.");
  const [store, file] = await Promise.all([realpath(root), realpath(path)]).catch(() => {
    throw new NotFoundException("Report file is unavailable.");
  });
  const offset = relative(store, file);
  if (offset.startsWith("..") || isAbsolute(offset))
    throw new NotFoundException("Report file is outside the report store.");
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const chunks: Buffer[] = [];
    const limit = 64 * 1024 * 1024;
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > limit)
      throw new ConflictException("Report exceeds the 64 MiB download limit.");
    let size = 0;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      const bytes = Buffer.from(chunk as Uint8Array);
      size += bytes.length;
      if (size > limit) throw new ConflictException("Report exceeds the 64 MiB download limit.");
      chunks.push(bytes);
    }
    const content = Buffer.concat(chunks);
    if (createHash("sha256").update(content).digest("hex") !== sha256)
      throw new ConflictException("Report integrity verification failed.");
    return content;
  } finally {
    await handle.close();
  }
}
