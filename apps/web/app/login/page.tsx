import { LoginForm } from "./login-form";

export default function LoginPage() {
  return (
    <main className="auth-shell">
      <section className="auth-panel" aria-labelledby="login-title">
        <p className="eyebrow">Authorized access only</p>
        <h1 id="login-title">Assessment console</h1>
        <p className="lede">Sign in to manage verified targets and evidence-backed assessments.</p>
        <LoginForm />
      </section>
    </main>
  );
}
