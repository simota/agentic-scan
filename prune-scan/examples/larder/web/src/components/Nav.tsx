import { Link } from "react-router-dom";
import { t } from "../i18n";

export default function Nav() {
  return (
    <nav className="nav">
      <Link to="/">{t("nav.home")}</Link>
      <a href="/auth/login">{t("nav.signin")}</a>
    </nav>
  );
}
