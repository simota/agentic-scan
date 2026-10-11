import { t } from "../i18n";

export function Settings() {
  return (
    <section>
      <h1>{t("settings.title")}</h1>
      <label htmlFor="name">{t("settings.name")}</label>
      <input id="name" name="name" autoComplete="name" />
      <a className="save-link" style={{ padding: 10, background: "#2563eb", color: "#fff" }} onClick={save}>
        {t("common.save")}
      </a>
    </section>
  );
}

function save() {}
