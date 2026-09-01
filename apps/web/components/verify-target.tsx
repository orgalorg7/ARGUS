"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export function VerifyTarget({
  workspaceId,
  targetId,
  manual,
}: {
  workspaceId: string;
  targetId: string;
  manual: boolean;
}) {
  const router = useRouter();
  const [error, setError] = useState("");
  return (
    <form
      className="inline-form"
      onSubmit={(event) =>
        void (async () => {
          event.preventDefault();
          const data = new FormData(event.currentTarget);
          const response = await fetch(
            `/api/platform/workspaces/${workspaceId}/targets/${targetId}/verify`,
            {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(manual ? {} : { token: data.get("token") }),
            },
          );
          const body = (await response.json()) as { message?: string };
          if (!response.ok) setError(body.message ?? "Verification failed.");
          else router.refresh();
        })()
      }
    >
      {!manual && <input name="token" placeholder="Verification token" required />}
      <button className="button secondary" type="submit">
        Verify authorization
      </button>
      {error && <span className="error">{error}</span>}
    </form>
  );
}
