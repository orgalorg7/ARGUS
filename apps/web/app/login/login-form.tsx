"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";

export function LoginForm() {
  const router = useRouter();
  const [error, setError] = useState<string>();
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(undefined);
    const form = new FormData(event.currentTarget);
    const response = await fetch("/api/session", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: form.get("email"), password: form.get("password") }),
    });
    if (!response.ok) {
      const payload = (await response.json().catch(() => ({ message: "Sign-in failed." }))) as {
        message?: string;
      };
      setError(payload.message ?? "Sign-in failed.");
      setSubmitting(false);
      return;
    }
    router.replace("/workspaces");
    router.refresh();
  }

  return (
    <form onSubmit={(event) => void submit(event)}>
      <div className="field">
        <label htmlFor="email">Email address</label>
        <input id="email" name="email" type="email" autoComplete="username" required />
      </div>
      <div className="field">
        <label htmlFor="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
        />
      </div>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      <button className="button submit" disabled={submitting} type="submit">
        {submitting ? "Signing in" : "Sign in securely"}
      </button>
    </form>
  );
}
