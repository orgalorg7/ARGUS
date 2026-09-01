import { cookies } from "next/headers";
import { NextResponse } from "next/server";

const apiBaseUrl = process.env["API_BASE_URL"] ?? "http://localhost:3001";

async function proxy(request: Request, context: { params: Promise<{ path: string[] }> }) {
  const token = (await cookies()).get("aasp_access")?.value;
  if (!token) return NextResponse.json({ message: "Authentication required." }, { status: 401 });
  const { path } = await context.params;
  if (path[0] !== "workspaces") {
    return NextResponse.json({ message: "Unsupported platform route." }, { status: 404 });
  }
  const source = new URL(request.url);
  const target = `${apiBaseUrl}/api/${path.map(encodeURIComponent).join("/")}${source.search}`;
  const body =
    request.method === "GET" || request.method === "HEAD" ? undefined : await request.text();
  const response = await fetch(target, {
    method: request.method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(request.headers.get("content-type")
        ? { "content-type": request.headers.get("content-type") as string }
        : {}),
    },
    ...(body !== undefined ? { body } : {}),
    cache: "no-store",
  });
  return new NextResponse(response.body, {
    status: response.status,
    headers: {
      "content-type": response.headers.get("content-type") ?? "application/json",
      ...(response.headers.get("content-disposition")
        ? { "content-disposition": response.headers.get("content-disposition") as string }
        : {}),
      "x-content-type-options": "nosniff",
    },
  });
}

export const GET = proxy;
export const POST = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
