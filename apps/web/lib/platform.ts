import { cookies } from "next/headers";
import { redirect } from "next/navigation";

const apiBaseUrl = process.env["API_BASE_URL"] ?? "http://localhost:3001";

export async function platformGet<T>(path: string): Promise<T> {
  const token = (await cookies()).get("aasp_access")?.value;
  if (!token) redirect("/login");
  const response = await fetch(`${apiBaseUrl}/api/${path}`, {
    headers: { authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (response.status === 401) redirect("/login");
  if (!response.ok) throw new Error(`Platform request failed with status ${response.status}.`);
  return response.json() as Promise<T>;
}

export function workspaceHref(path: string, workspaceId: string): string {
  return `${path}?workspaceId=${encodeURIComponent(workspaceId)}`;
}
