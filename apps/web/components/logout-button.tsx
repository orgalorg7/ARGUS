"use client";

import { useRouter } from "next/navigation";

export function LogoutButton() {
  const router = useRouter();
  return (
    <button
      className="text-button"
      onClick={() =>
        void (async () => {
          await fetch("/api/session", { method: "DELETE" });
          router.push("/login");
          router.refresh();
        })()
      }
    >
      Sign out
    </button>
  );
}
