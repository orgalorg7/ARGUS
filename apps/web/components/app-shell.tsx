import Link from "next/link";
import { workspaceHref } from "../lib/platform";
import { LogoutButton } from "./logout-button";

export function AppShell({
  workspaceId,
  children,
}: Readonly<{ workspaceId: string; children: React.ReactNode }>) {
  const links = [
    ["Scans", "/scans"],
    ["Targets", "/targets"],
    ["Audit", "/audit"],
    ["Settings", "/settings"],
  ] as const;
  return (
    <>
      <header className="topbar">
        <div className="shell topbar-inner">
          <Link className="brand" href={workspaceHref("/scans", workspaceId)}>
            AASP / Assessment console
          </Link>
          <nav>
            {links.map(([label, href]) => (
              <Link key={href} href={workspaceHref(href, workspaceId)}>
                {label}
              </Link>
            ))}
          </nav>
          <LogoutButton />
        </div>
      </header>
      <main className="shell page">{children}</main>
    </>
  );
}
