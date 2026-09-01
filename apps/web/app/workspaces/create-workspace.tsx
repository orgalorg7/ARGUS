"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";

export function CreateWorkspace() {
  const router = useRouter();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(undefined);
    const form = new FormData(event.currentTarget);
    const response = await fetch("/api/workspaces", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: form.get("name") }),
    });
    if (!response.ok) {
      setError("Workspace creation failed.");
      setSubmitting(false);
      return;
    }
    event.currentTarget.reset();
    setSubmitting(false);
    router.refresh();
  }

  return (
    <div>
      <form className="create-form" onSubmit={(event) => void submit(event)}>
        <input
          name="name"
          aria-label="Workspace name"
          minLength={2}
          maxLength={120}
          placeholder="Workspace name"
          required
        />
        <button className="button" type="submit" disabled={submitting}>
          {submitting ? "Creating" : "Create workspace"}
        </button>
      </form>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
