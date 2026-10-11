import { useState } from "react";
import { t } from "../i18n";

export function SignupForm() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  function onEmail(e) {
    setEmail(e.target.value);
    setError(/^[^@]+@[^@]+$/.test(e.target.value) ? "" : t("signup.invalid"));
  }

  async function submit(e) {
    e.preventDefault();
    const res = await fetch("/api/signup", { method: "POST", body: JSON.stringify({ email, password }) });
    if (!res.ok) {
      setEmail("");
      setPassword("");
      setError(t("signup.failed"));
    }
  }

  return (
    <form onSubmit={submit}>
      <input type="text" name="email" placeholder="Email" value={email} onChange={onEmail} />
      <input type="password" name="password" placeholder={t("signup.password")} value={password}
        onChange={(e) => setPassword(e.target.value)} />
      {error && <p className="error">{error}</p>}
      <button type="submit" className="btn">{t("signup.submit")}</button>
    </form>
  );
}
