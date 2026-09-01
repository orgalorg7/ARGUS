import { NextResponse } from "next/server";

const apiBaseUrl = process.env["API_BASE_URL"] ?? "http://localhost:3001";

export async function POST(request: Request) {
  const response = await fetch(`${apiBaseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: await request.text(),
    cache: "no-store",
  });
  const payload = (await response.json()) as { accessToken?: string; message?: string };
  if (!response.ok || !payload.accessToken) {
    return NextResponse.json(
      { message: payload.message ?? "Sign-in failed." },
      { status: response.status },
    );
  }
  const result = NextResponse.json({ authenticated: true });
  result.cookies.set("aasp_access", payload.accessToken, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env["NODE_ENV"] === "production",
    path: "/",
    maxAge: 15 * 60,
  });
  return result;
}

export function DELETE() {
  const response = NextResponse.json({ authenticated: false });
  response.cookies.delete("aasp_access");
  return response;
}
