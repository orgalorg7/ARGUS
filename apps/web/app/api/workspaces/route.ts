import { cookies } from "next/headers";
import { NextResponse } from "next/server";

const apiBaseUrl = process.env["API_BASE_URL"] ?? "http://localhost:3001";

export async function POST(request: Request) {
  const token = (await cookies()).get("aasp_access")?.value;
  if (!token) return NextResponse.json({ message: "Authentication required." }, { status: 401 });
  const response = await fetch(`${apiBaseUrl}/api/workspaces`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: await request.text(),
    cache: "no-store",
  });
  return new NextResponse(await response.text(), {
    status: response.status,
    headers: { "content-type": response.headers.get("content-type") ?? "application/json" },
  });
}
